"""
VALI Logger Service
Central telemetry collector for all deceptive interactions.
"""

import os
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(
    title="VALI Logger",
    description="Telemetry collector for VALI deception environments",
    version="1.0.0",
)

LOG_DIR = Path("/app/logs")
SESSION_DIR = Path("/app/sessions")
LOG_DIR.mkdir(parents=True, exist_ok=True)
SESSION_DIR.mkdir(parents=True, exist_ok=True)

API_KEY = os.getenv("LOGGER_API_KEY", "vali-logger-secret-key-change-me")


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


class InteractionEvent(BaseModel):
    session_id: str
    event_type: str = Field(..., description="request | unlock | login_attempt | action | terminate")
    source_ip: str
    user_agent: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    status_code: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None


class SessionSummary(BaseModel):
    session_id: str
    source_ip: str
    first_seen: str
    last_seen: str
    event_count: int
    paths: List[str]
    unlocks: List[str]
    user_agents: List[str]
    duration_seconds: float
    depth: int


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_event(event: dict):
    """Append a single event to the daily log file."""
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file = LOG_DIR / f"events-{day}.jsonl"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def update_session(session_id: str, event: dict):
    """Maintain a rolling session file for quick intelligence."""
    session_file = SESSION_DIR / f"{session_id}.json"
    if session_file.exists():
        with open(session_file, "r", encoding="utf-8") as f:
            session = json.load(f)
    else:
        session = {
            "session_id": session_id,
            "source_ip": event.get("source_ip"),
            "first_seen": event.get("timestamp"),
            "last_seen": event.get("timestamp"),
            "events": [],
            "paths": [],
            "unlocks": [],
            "user_agents": set(),
            "depth": 0,
        }

    session["last_seen"] = event.get("timestamp")
    session["events"].append(event)

    if event.get("path"):
        if event["path"] not in session["paths"]:
            session["paths"].append(event["path"])

    if event.get("event_type") == "unlock" and event.get("details"):
        unlock_name = event["details"].get("unlocked")
        if unlock_name and unlock_name not in session["unlocks"]:
            session["unlocks"].append(unlock_name)
            session["depth"] = len(session["unlocks"])

    ua = event.get("user_agent")
    if ua:
        # sets are not JSON serializable, convert later
        if "user_agents" not in session or not isinstance(session["user_agents"], list):
            session["user_agents"] = []
        if ua not in session["user_agents"]:
            session["user_agents"].append(ua)

    # Keep only last 200 events per session to bound size
    session["events"] = session["events"][-200:]

    with open(session_file, "w", encoding="utf-8") as f:
        json.dump(session, f, indent=2, ensure_ascii=False, default=list)


@app.post("/ingest")
async def ingest_event(
    event: InteractionEvent,
    x_api_key: Optional[str] = Header(None),
):
    verify_api_key(x_api_key)

    payload = event.model_dump()
    if not payload.get("timestamp"):
        payload["timestamp"] = utc_now()

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
                    "first_seen": data.get("first_seen"),
                    "last_seen": data.get("last_seen"),
                    "event_count": len(data.get("events", [])),
                    "depth": data.get("depth", 0),
                    "unlocks": data.get("unlocks", []),
                    "paths_count": len(data.get("paths", [])),
                })
        except Exception:
            continue

    # Sort by last_seen descending
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


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vali-logger", "version": "1.0.0"}


@app.get("/")
async def root():
    return {
        "service": "VALI Logger",
        "version": "1.0.0",
        "endpoints": ["/ingest", "/sessions", "/sessions/{id}", "/health"],
    }
