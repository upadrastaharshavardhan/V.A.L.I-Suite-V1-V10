"""
VALI Logger + Intelligence Engine v4
Scoring • Profiling • Correlation • Canaries • Export
"""

import os
import json
import re
import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

import yaml
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

app = FastAPI(title="VALI Logger v4", version="4.0.0")

LOG_DIR = Path("/app/logs")
SESSION_DIR = Path("/app/sessions")
CANARY_DIR = Path("/app/canaries")
CONFIG_PATH = Path("/app/config/vali.yaml")
for d in (LOG_DIR, SESSION_DIR, CANARY_DIR):
    d.mkdir(parents=True, exist_ok=True)

API_KEY = os.getenv("LOGGER_API_KEY", "vali-logger-secret-key-change-me-v4")

TOOL_PATTERNS = [
    (r"sqlmap", "sqlmap"),
    (r"nikto", "nikto"),
    (r"nmap|masscan|zmap", "scanner"),
    (r"python-requests|curl/|wget/|httpie", "script"),
    (r"gobuster|dirbuster|ffuf|feroxbuster|dirmap", "dirbuster"),
    (r"burp|owasp.?zap|zap", "proxy"),
    (r"metasploit|meterpreter", "metasploit"),
    (r"hydra|medusa|ncrack|patator", "bruteforce"),
    (r"mozilla|chrome|safari|edg/|firefox", "browser"),
]


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                return yaml.safe_load(f) or {}
        except Exception:
            pass
    return {}


CFG = load_config()
WEIGHTS = CFG.get("scoring", {}).get("weights", {})
CAPS = CFG.get("scoring", {}).get("caps", {})
PROFILE_CFG = CFG.get("profiling", {})


def verify(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")


class InteractionEvent(BaseModel):
    session_id: str
    event_type: str
    source_ip: str
    user_agent: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    status_code: Optional[int] = None
    service: Optional[str] = "web"
    details: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def detect_tools(ua: Optional[str], path: Optional[str] = None) -> List[str]:
    blob = f"{ua or ''} {path or ''}".lower()
    found = []
    for pat, name in TOOL_PATTERNS:
        if re.search(pat, blob, re.I):
            found.append(name)
    return list(dict.fromkeys(found))


def compute_risk(session: dict) -> int:
    score = 0.0
    score += min(session.get("depth", 0) * WEIGHTS.get("depth", 16), 40)
    score += min(session.get("login_attempts", 0) * WEIGHTS.get("login_attempts", 7), 22)
    score += min(len(session.get("tools", [])) * WEIGHTS.get("unique_tools", 11), 28)
    score += min(len(session.get("events", [])) * WEIGHTS.get("event_count", 0.35), CAPS.get("event_count", 22))
    score += min(len(session.get("commands", [])) * WEIGHTS.get("ssh_commands", 1.4), CAPS.get("ssh_commands", 18))
    score += session.get("canary_hits", 0) * WEIGHTS.get("canary_hit", 22)

    # Targeted path bonus
    interesting = sum(1 for p in session.get("paths", []) if any(x in p for x in ["/vault", "/secrets", "/backup", "/config", "/api/"]))
    score += min(interesting * WEIGHTS.get("targeted_paths", 10), 20)

    # Automation rate
    events = session.get("events", [])
    if len(events) >= 6:
        try:
            t0 = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(events[-1]["timestamp"].replace("Z", "+00:00"))
            dur = max((t1 - t0).total_seconds(), 0.5)
            if len(events) / dur > PROFILE_CFG.get("automated_rate_threshold", 1.2):
                score += WEIGHTS.get("fast_automation", 14)
        except Exception:
            pass

    return int(min(max(score, 0), 100))


def profile_attacker(session: dict) -> str:
    tools = set(session.get("tools", []))
    scanner_tools = set(PROFILE_CFG.get("scanner_tools", ["scanner", "dirbuster", "nikto"]))
    depth = session.get("depth", 0)
    events = session.get("events", [])
    duration = 0
    if len(events) >= 2:
        try:
            t0 = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(events[-1]["timestamp"].replace("Z", "+00:00"))
            duration = (t1 - t0).total_seconds()
        except Exception:
            pass

    rate = len(events) / max(duration, 0.5) if events else 0

    if tools & scanner_tools and depth <= 1:
        return "scanner"
    if rate > PROFILE_CFG.get("automated_rate_threshold", 1.2) and "browser" not in tools:
        return "automated"
    if depth >= PROFILE_CFG.get("targeted_min_depth", 3) or session.get("canary_hits", 0) > 0:
        return "targeted"
    if duration >= PROFILE_CFG.get("interactive_min_duration", 45) or "browser" in tools:
        return "interactive"
    return "unknown"


def append_event(event: dict):
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(LOG_DIR / f"events-{day}.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def update_session(session_id: str, event: dict):
    path = SESSION_DIR / f"{session_id}.json"
    if path.exists():
        with open(path, encoding="utf-8") as f:
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
            "canary_hits": 0,
            "canaries_triggered": [],
            "risk_score": 0,
            "profile": "unknown",
            "related_sessions": [],
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

    if event.get("event_type") == "canary":
        session["canary_hits"] = session.get("canary_hits", 0) + 1
        cid = (event.get("details") or {}).get("canary_id")
        if cid and cid not in session.get("canaries_triggered", []):
            session.setdefault("canaries_triggered", []).append(cid)

    ua = event.get("user_agent")
    if ua and ua not in session["user_agents"]:
        session["user_agents"].append(ua)

    for t in detect_tools(ua, event.get("path")):
        if t not in session["tools"]:
            session["tools"].append(t)

    session["events"] = session["events"][-500:]
    session["commands"] = session["commands"][-200:]
    session["risk_score"] = compute_risk(session)
    session["profile"] = profile_attacker(session)

    # Simple IP correlation
    ip = session.get("source_ip")
    related = []
    if ip:
        for f in SESSION_DIR.glob("*.json"):
            if f.stem == session_id:
                continue
            try:
                with open(f, encoding="utf-8") as fh:
                    other = json.load(fh)
                if other.get("source_ip") == ip and other.get("session_id") != session_id:
                    related.append({
                        "session_id": other.get("session_id"),
                        "service": other.get("service"),
                        "risk_score": other.get("risk_score", 0),
                    })
            except Exception:
                pass
    session["related_sessions"] = related[:10]

    with open(path, "w", encoding="utf-8") as f:
        json.dump(session, f, indent=2, ensure_ascii=False)


@app.post("/ingest")
async def ingest(event: InteractionEvent, x_api_key: Optional[str] = Header(None)):
    verify(x_api_key)
    payload = event.model_dump()
    if not payload.get("timestamp"):
        payload["timestamp"] = utc_now()
    payload["tools_detected"] = detect_tools(payload.get("user_agent"), payload.get("path"))
    append_event(payload)
    update_session(event.session_id, payload)
    return {"status": "ok", "session_id": event.session_id}


@app.post("/canary")
async def canary_hit(session_id: str, canary_id: str, source_ip: str,
                     details: Optional[Dict[str, Any]] = None,
                     x_api_key: Optional[str] = Header(None)):
    verify(x_api_key)
    event = {
        "session_id": session_id,
        "event_type": "canary",
        "source_ip": source_ip,
        "service": "web",
        "details": {"canary_id": canary_id, **(details or {})},
        "timestamp": utc_now(),
    }
    append_event(event)
    update_session(session_id, event)
    with open(CANARY_DIR / f"{canary_id}-{session_id[:8]}.json", "w") as f:
        json.dump(event, f, indent=2)
    return {"status": "alert_recorded", "canary_id": canary_id}


@app.get("/sessions")
async def list_sessions(x_api_key: Optional[str] = Header(None)):
    verify(x_api_key)
    out = []
    for f in SESSION_DIR.glob("*.json"):
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
                out.append({
                    "session_id": d.get("session_id"),
                    "source_ip": d.get("source_ip"),
                    "service": d.get("service", "web"),
                    "first_seen": d.get("first_seen"),
                    "last_seen": d.get("last_seen"),
                    "event_count": len(d.get("events", [])),
                    "depth": d.get("depth", 0),
                    "risk_score": d.get("risk_score", 0),
                    "profile": d.get("profile", "unknown"),
                    "tools": d.get("tools", []),
                    "canary_hits": d.get("canary_hits", 0),
                    "related_count": len(d.get("related_sessions", [])),
                })
        except Exception:
            continue
    out.sort(key=lambda x: (x.get("risk_score", 0), x.get("last_seen") or ""), reverse=True)
    return {"sessions": out}


@app.get("/sessions/{session_id}")
async def get_session(session_id: str, x_api_key: Optional[str] = Header(None)):
    verify(x_api_key)
    p = SESSION_DIR / f"{session_id}.json"
    if not p.exists():
        raise HTTPException(404, "Not found")
    with open(p, encoding="utf-8") as f:
        return json.load(f)


@app.get("/stats")
async def stats(x_api_key: Optional[str] = Header(None)):
    verify(x_api_key)
    sessions = list(SESSION_DIR.glob("*.json"))
    total_events = high = canary_total = 0
    profiles = {}
    tools = set()
    for f in sessions:
        try:
            with open(f) as fh:
                d = json.load(fh)
                total_events += len(d.get("events", []))
                if d.get("risk_score", 0) >= 50:
                    high += 1
                canary_total += d.get("canary_hits", 0)
                tools.update(d.get("tools", []))
                p = d.get("profile", "unknown")
                profiles[p] = profiles.get(p, 0) + 1
        except Exception:
            pass
    return {
        "sessions": len(sessions),
        "total_events": total_events,
        "high_risk": high,
        "canary_hits": canary_total,
        "profiles": profiles,
        "unique_tools": sorted(tools),
    }


@app.get("/export/sessions.json")
async def export_json(x_api_key: Optional[str] = Header(None)):
    verify(x_api_key)
    data = []
    for f in SESSION_DIR.glob("*.json"):
        try:
            with open(f, encoding="utf-8") as fh:
                data.append(json.load(fh))
        except Exception:
            pass
    return data


@app.get("/export/sessions.csv")
async def export_csv(x_api_key: Optional[str] = Header(None)):
    verify(x_api_key)
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["session_id", "source_ip", "service", "risk_score", "profile", "depth",
                "events", "login_attempts", "canary_hits", "tools", "first_seen", "last_seen"])
    for f in SESSION_DIR.glob("*.json"):
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
                w.writerow([
                    d.get("session_id"), d.get("source_ip"), d.get("service"),
                    d.get("risk_score", 0), d.get("profile"), d.get("depth", 0),
                    len(d.get("events", [])), d.get("login_attempts", 0),
                    d.get("canary_hits", 0), "|".join(d.get("tools", [])),
                    d.get("first_seen"), d.get("last_seen"),
                ])
        except Exception:
            pass
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=vali-sessions.csv"})


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vali-logger", "version": "4.0.0"}


@app.get("/status")
async def status(x_api_key: Optional[str] = Header(None)):
    verify(x_api_key)
    return {
        "version": "4.0.0",
        "sessions": len(list(SESSION_DIR.glob("*.json"))),
        "canary_files": len(list(CANARY_DIR.glob("*.json"))),
        "log_files": len(list(LOG_DIR.glob("*.jsonl"))),
    }
