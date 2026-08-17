"""
VALI SSH Honeypot v4 — Richer medium-interaction
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
log = logging.getLogger("vali-ssh")

LOGGER_URL = os.getenv("LOGGER_URL", "http://logger:8001")
LOGGER_API_KEY = os.getenv("LOGGER_API_KEY", "vali-logger-secret-key-change-me-v4")
HOST_KEY_DIR = Path("/app/keys")

FAKE_FS = {
    "/": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\n",
    "/home": "admin  deploy  ubuntu\n",
    "/home/admin": ".bashrc  .ssh  documents  downloads  notes.txt  secrets.env\n",
    "/home/admin/.ssh": "authorized_keys  id_rsa  id_rsa.pub  known_hosts\n",
    "/etc": "passwd  shadow  hosts  hostname  ssh  nginx  systemd  nginx\n",
    "/var": "log  tmp  cache  lib\n",
    "/var/log": "auth.log  syslog  nginx  journal\n",
    "/opt": "nexusops  backups\n",
    "/opt/nexusops": "config.yaml  bin  data\n",
}

FAKE_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\ndeploy:x:1001:1001:Deploy:/home/deploy:/bin/bash\n",
    "/etc/hostname": "nexusops-prod-01\n",
    "/home/admin/notes.txt": "TODO: rotate staging DB credentials before Friday\nTODO: review backup retention\nTODO: disable legacy VPN accounts\n",
    "/home/admin/secrets.env": "DB_HOST=db.internal\nDB_USER=app\nDB_PASS=ChangeMe_In_Vault\nAWS_ACCESS_KEY_ID=AKIA_FAKE_KEY_FOR_DECOY\n",
    "/opt/nexusops/config.yaml": "env: production\nregion: us-east-1\napi_endpoint: https://api.nexusops.internal\n",
}


async def log_event(session_id, etype, source_ip, details=None):
    payload = {
        "session_id": session_id,
        "event_type": etype,
        "source_ip": source_ip,
        "user_agent": "ssh-client",
        "service": "ssh",
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            await c.post(f"{LOGGER_URL}/ingest", json=payload,
                         headers={"X-API-Key": LOGGER_API_KEY})
    except Exception as e:
        log.warning(f"log failed: {e}")


class ValiSession(asyncssh.SSHServerSession):
    def __init__(self, username, source_ip):
        self.username = username
        self.source_ip = source_ip
        self.session_id = str(uuid.uuid4())
        self.cwd = f"/home/{username}" if username != "root" else "/root"
        self._input = ""
        self._chan = None

    def connection_made(self, chan):
        self._chan = chan

    def shell_requested(self):
        return True

    def session_started(self):
        asyncio.create_task(self._boot())

    async def _boot(self):
        await log_event(self.session_id, "ssh_login", self.source_ip,
                        {"username": self.username, "success": True})
        self._chan.write(
            f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\n"
            f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {self.source_ip}\n"
        )
        self._prompt()

    def _prompt(self):
        user = self.username
        host = "nexusops-prod-01"
        path = "~" if self.cwd in (f"/home/{user}", "/root") else self.cwd
        self._chan.write(f"{user}@{host}:{path}$ ")

    def data_received(self, data, datatype):
        self._input += data
        while "\n" in self._input or "\r" in self._input:
            if "\n" in self._input:
                line, self._input = self._input.split("\n", 1)
            else:
                line, self._input = self._input.split("\r", 1)
            line = line.strip("\r")
            asyncio.create_task(self._cmd(line))

    async def _cmd(self, cmd: str):
        if not cmd:
            self._prompt()
            return
        await log_event(self.session_id, "ssh_command", self.source_ip,
                        {"command": cmd, "cwd": self.cwd, "username": self.username})

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
            args = parts[1:] if len(parts) > 1 else []
            if "-a" in args:
                self._chan.write("Linux nexusops-prod-01 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux\n")
            else:
                self._chan.write("Linux\n")
        elif base in ("ls", "dir"):
            target = parts[1] if len(parts) > 1 else self.cwd
            if not target.startswith("/"):
                target = os.path.normpath(os.path.join(self.cwd, target))
            content = FAKE_FS.get(target)
            if content is not None:
                self._chan.write(content)
            else:
                self._chan.write(f"ls: cannot access '{target}': No such file or directory\n")
        elif base == "cd":
            target = parts[1] if len(parts) > 1 else f"/home/{self.username}"
            if not target.startswith("/"):
                target = os.path.normpath(os.path.join(self.cwd, target))
            if target in FAKE_FS or target.startswith("/home") or target in ("/tmp", "/var", "/etc", "/opt", "/root"):
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
        elif base == "env" or base == "printenv":
            self._chan.write("USER=" + self.username + "\nHOME=/home/" + self.username + "\nSHELL=/bin/bash\n")
        elif base == "help":
            self._chan.write("Common commands: ls cd pwd cat whoami id uname env exit\n")
        else:
            self._chan.write(f"bash: {base}: command not found\n")
        self._prompt()

    def eof_received(self):
        return False

    def connection_lost(self, exc):
        log.info(f"session closed {self.session_id} from {self.source_ip}")


class ValiServer(asyncssh.SSHServer):
    def __init__(self):
        self.source_ip = "unknown"
        self.username = "admin"

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername")
        self.source_ip = peer[0] if peer else "unknown"
        log.info(f"connection from {self.source_ip}")

    def begin_auth(self, username):
        self.username = username
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        log.info(f"auth user={username} from={self.source_ip}")
        asyncio.create_task(log_event(
            str(uuid.uuid4()), "ssh_login", self.source_ip,
            {"username": username, "password_length": len(password), "success": True, "phase": "auth"},
        ))
        return True

    def session_requested(self):
        return ValiSession(self.username, self.source_ip)


async def main():
    keys = []
    for name in ("ssh_host_rsa_key", "ssh_host_ed25519_key"):
        p = HOST_KEY_DIR / name
        if p.exists():
            keys.append(str(p))
    if not keys:
        keys = [asyncssh.generate_private_key("ssh-rsa")]
    log.info("VALI SSH Honeypot v4 listening on 2222")
    await asyncssh.create_server(ValiServer, "", 2222, server_host_keys=keys, login_timeout=30)
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
