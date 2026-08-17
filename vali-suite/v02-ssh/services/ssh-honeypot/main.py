"""
VALI SSH Honeypot v2
Medium-interaction SSH that logs authentication attempts and commands.
"""

import asyncio
import os
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path

import asyncssh
import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("vali-ssh")

LOGGER_URL = os.getenv("LOGGER_URL", "http://logger:8001")
LOGGER_API_KEY = os.getenv("LOGGER_API_KEY", "vali-logger-secret-key-change-me-v2")
HOST_KEY_DIR = Path("/app/keys")
DATA_DIR = Path("/app/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Fake filesystem responses
FAKE_FS = {
    "/": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\n",
    "/home": "admin  deploy  ubuntu\n",
    "/home/admin": "documents  downloads  .ssh  .bashrc  notes.txt\n",
    "/etc": "passwd  shadow  hosts  hostname  ssh  nginx  systemd\n",
    "/var": "log  tmp  cache  lib\n",
    "/var/log": "auth.log  syslog  nginx  journal\n",
}

FAKE_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash\n",
    "/etc/hostname": "nexusops-prod-01\n",
    "/home/admin/notes.txt": "TODO: rotate staging DB credentials\nTODO: update backup retention policy\n",
}


async def log_to_vali(session_id: str, event_type: str, source_ip: str, details: dict = None, user_agent: str = None):
    payload = {
        "session_id": session_id,
        "event_type": event_type,
        "source_ip": source_ip,
        "user_agent": user_agent or "ssh-client",
        "service": "ssh",
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{LOGGER_URL}/ingest",
                json=payload,
                headers={"X-API-Key": LOGGER_API_KEY},
            )
    except Exception as e:
        logger.warning(f"Failed to log event: {e}")


class ValiSSHSession(asyncssh.SSHServerSession):
    def __init__(self, conn, username, source_ip):
        self._conn = conn
        self.username = username
        self.source_ip = source_ip
        self.session_id = str(uuid.uuid4())
        self.cwd = "/home/admin"
        self._input = ""
        self._chan = None

    def connection_made(self, chan):
        self._chan = chan

    def shell_requested(self):
        return True

    def exec_requested(self, command):
        return True

    def session_started(self):
        asyncio.create_task(self._start())

    async def _start(self):
        await log_to_vali(
            self.session_id, "ssh_login", self.source_ip,
            details={"username": self.username, "success": True},
        )
        banner = (
            f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\n"
            f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {self.source_ip}\n"
        )
        self._chan.write(banner)
        self._prompt()

    def _prompt(self):
        user = self.username if self.username != "root" else "root"
        host = "nexusops-prod-01"
        path = self.cwd if self.cwd != f"/home/{user}" else "~"
        self._chan.write(f"{user}@{host}:{path}$ ")

    def data_received(self, data, datatype):
        self._input += data
        while "\n" in self._input or "\r" in self._input:
            line, self._input = self._input.split("\n", 1) if "\n" in self._input else self._input.split("\r", 1)
            line = line.strip("\r")
            asyncio.create_task(self._handle_command(line))

    async def _handle_command(self, cmd: str):
        if not cmd:
            self._prompt()
            return

        await log_to_vali(
            self.session_id, "ssh_command", self.source_ip,
            details={"command": cmd, "cwd": self.cwd, "username": self.username},
        )

        parts = cmd.split()
        base = parts[0] if parts else ""

        if base in ("exit", "logout", "quit"):
            self._chan.write("logout\n")
            self._chan.exit(0)
            return

        if base == "whoami":
            self._chan.write(f"{self.username}\n")
        elif base == "id":
            self._chan.write(f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})\n")
        elif base == "pwd":
            self._chan.write(f"{self.cwd}\n")
        elif base == "uname":
            self._chan.write("Linux nexusops-prod-01 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux\n")
        elif base in ("ls", "dir"):
            target = parts[1] if len(parts) > 1 else self.cwd
            if not target.startswith("/"):
                target = os.path.normpath(os.path.join(self.cwd, target))
            content = FAKE_FS.get(target, "")
            if content:
                self._chan.write(content)
            else:
                self._chan.write(f"ls: cannot access '{target}': No such file or directory\n")
        elif base == "cd":
            target = parts[1] if len(parts) > 1 else f"/home/{self.username}"
            if not target.startswith("/"):
                target = os.path.normpath(os.path.join(self.cwd, target))
            if target in FAKE_FS or target in ("/home/admin", "/root", "/tmp", "/var", "/etc"):
                self.cwd = target
            else:
                self._chan.write(f"bash: cd: {target}: No such file or directory\n")
        elif base == "cat":
            target = parts[1] if len(parts) > 1 else ""
            if not target.startswith("/"):
                target = os.path.normpath(os.path.join(self.cwd, target))
            content = FAKE_FILES.get(target)
            if content:
                self._chan.write(content)
            else:
                self._chan.write(f"cat: {target}: No such file or directory\n")
        elif base == "help":
            self._chan.write("Available: ls, cd, pwd, cat, whoami, id, uname, exit\n")
        else:
            self._chan.write(f"bash: {base}: command not found\n")

        self._prompt()

    def eof_received(self):
        return False

    def connection_lost(self, exc):
        logger.info(f"SSH session closed: {self.session_id} from {self.source_ip}")


class ValiSSHServer(asyncssh.SSHServer):
    def __init__(self):
        self.source_ip = "unknown"

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername")
        self.source_ip = peer[0] if peer else "unknown"
        logger.info(f"SSH connection from {self.source_ip}")

    def begin_auth(self, username):
        return True  # Always require auth (then accept anything)

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        # Accept everything — log it
        logger.info(f"Auth attempt: user={username} from={self.source_ip}")
        # Fire-and-forget log (sync context, schedule)
        asyncio.create_task(log_to_vali(
            str(uuid.uuid4()), "ssh_login", self.source_ip,
            details={"username": username, "password_length": len(password), "success": True, "note": "pre-session"},
        ))
        return True

    def session_requested(self):
        return ValiSSHSession(None, "admin", self.source_ip)


async def start_server():
    host_keys = []
    for name in ("ssh_host_rsa_key", "ssh_host_ed25519_key"):
        path = HOST_KEY_DIR / name
        if path.exists():
            host_keys.append(str(path))

    if not host_keys:
        # Generate on the fly if missing
        key = asyncssh.generate_private_key("ssh-rsa")
        host_keys = [key]

    logger.info("Starting VALI SSH Honeypot on port 2222...")
    await asyncssh.create_server(
        ValiSSHServer,
        "",
        2222,
        server_host_keys=host_keys,
        login_timeout=30,
    )
    logger.info("SSH Honeypot ready")


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_server())
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        loop.close()
