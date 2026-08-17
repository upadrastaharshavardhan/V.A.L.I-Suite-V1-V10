"""
VALI Logger Service v2
Central telemetry + session intelligence.
"""

import os
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="VALI Logger v2", version="2.0.0")

LOG_DIR = Path("/app/logs")
SESSION_DIR = Path("/app/sessions")
LOG_DIR.mkdir(parents=True, exist_ok=True)
SESSION_DIR.mkdir(parents=True, exist_ok=True)

API_KEY = os.getenv("LOGGER_API_KEY", "vali-logger-secret-key-change-me-v2")

# Simple tool fingerprints
TOOL_PATTERNS = [
    (r"sqlmap", "sqlmap"),
    (r"nikto", "nikto"),
    (r"nmap|masscan", "scanner"),
    (r"python-requests|curl/|wget/", "script"),
    (r"gobuster|dirbuster|ffuf|feroxbuster", "dirbuster"),
    (r"burp|zap|owasp", "proxy"),
    (r"metasploit|meterpreter", "metasploit"),
    (r"hydra|medusa|ncrack", "bruteforce"),
    (r"mozilla|chrome|safari|edge|firefox", "browser"),
]


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


class InteractionEvent(BaseModel):
    session_id: str
    event_type: str = Field(..., description="request|unlock|login_attempt|ssh_login|ssh_command|action|terminate")
    source_ip: str
    user_agent: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    status_code: Optional[int] = None
    service: Optional[str] = "web"  # web | ssh
    details: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_tools(user_agent: Optional[str], path: Optional[str] = None) -> List[str]:
    signals = []
    blob = f"{user_agent or ''} {path or ''}".lower()
    for pattern, name in TOOL_PATTERNS:
        if re.search(pattern, blob, re.I):
            signals.append(name)
    return list(dict.fromkeys(signals))  # unique, preserve order


def append_event(event: dict):
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file = LOG_DIR / f"events-{day}.jsonl"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def update_session(session_id: str, event: dict):
    session_file = SESSION_DIR / f"{session_id}.json"
    if session_file.exists():
        with open(session_file, "r", encoding="utf-8") as f:
            session = json.load(f)
    else:
        session = {
            "session_id": session_id,
            "source_ip": event.get("source_ip"),
            "service": event.get("service", "web"),
            "first_seen": event.get("timestamp"),
            "last_seen": event.get("timestamp"),
            "events": [],
            "paths": [],
            "unlocks": [],
            "user_agents": [],
            "tools": [],
            "commands": [],
            "depth": 0,
            "login_attempts": 0,
        }

    session["last_seen"] = event.get("timestamp")
    session["events"].append(event)

    if event.get("path") and event["path"] not in session["paths"]:
        session["paths"].append(event["path"])

    if event.get("event_type") == "unlock" and event.get("details"):
        name = event["details"].get("unlocked")
        if name and name not in session["unlocks"]:
            session["unlocks"].append(name)
            session["depth"] = len(session["unlocks"])

    if event.get("event_type") == "login_attempt":
        session["login_attempts"] = session.get("login_attempts", 0) + 1

    if event.get("event_type") == "ssh_command" and event.get("details"):
        cmd = event["details"].get("command")
        if cmd:
            session["commands"].append(cmd)

    ua = event.get("user_agent")
    if ua and ua not in session["user_agents"]:
        session["user_agents"].append(ua)

    # Tool signals
    new_tools = detect_tools(ua, event.get("path"))
    for t in new_tools:
        if t not in session["tools"]:
            session["tools"].append(t)

    # Bound size
    session["events"] = session["events"][-300:]
    session["commands"] = session["commands"][-100:]

    with open(session_file, "w", encoding="utf-8") as f:
        json.dump(session, f, indent=2, ensure_ascii=False)


@app.post("/ingest")
async def ingest_event(event: InteractionEvent, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    payload = event.model_dump()
    if not payload.get("timestamp"):
        payload["timestamp"] = utc_now()
    # Enrich
    payload["tools_detected"] = detect_tools(payload.get("user_agent"), payload.get("path"))
    append_event(payload)
    update_session(event.session_id, payload)
    return {"status": "ok", "session_id": event.session_id}


@app.get("/sessions")
async def list_sessions(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    sessions = []
    for f in SESSION_DIR.glob("*.json"):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                sessions.append({
                    "session_id": data.get("session_id"),
                    "source_ip": data.get("source_ip"),
                    "service": data.get("service", "web"),
                    "first_seen": data.get("first_seen"),
                    "last_seen": data.get("last_seen"),
                    "event_count": len(data.get("events", [])),
                    "depth": data.get("depth", 0),
                    "unlocks": data.get("unlocks", []),
                    "tools": data.get("tools", []),
                    "login_attempts": data.get("login_attempts", 0),
                    "paths_count": len(data.get("paths", [])),
                })
        except Exception:
            continue
    sessions.sort(key=lambda x: x.get("last_seen") or "", reverse=True)
    return {"sessions": sessions}


@app.get("/sessions/{session_id}")
async def get_session(session_id: str, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    session_file = SESSION_DIR / f"{session_id}.json"
    if not session_file.exists():
        raise HTTPException(status_code=404, detail="Session not found")
    with open(session_file, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/stats")
async def stats(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    sessions = list(SESSION_DIR.glob("*.json"))
    total_events = 0
    max_depth = 0
    tools = set()
    for f in sessions:
        try:
            with open(f) as fh:
                d = json.load(fh)
                total_events += len(d.get("events", []))
                max_depth = max(max_depth, d.get("depth", 0))
                tools.update(d.get("tools", []))
        except Exception:
            pass
    return {
        "sessions": len(sessions),
        "total_events": total_events,
        "max_depth": max_depth,
        "unique_tools": sorted(tools),
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vali-logger", "version": "2.0.0"}


@app.get("/")
async def root():
    return {"service": "VALI Logger v2", "version": "2.0.0"}
