"""
VALI Web Decoy Service
Realistic progressive deceptive environment.
"""

import os
import uuid
import time
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

import httpx
from fastapi import FastAPI, Request, Form, Response, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI(title="Internal Admin Portal", docs_url=None, redoc_url=None)

# Secret for session signing
SECRET = os.getenv("WEB_DECOY_SECRET", "change-me-to-a-long-random-string")
app.add_middleware(SessionMiddleware, secret_key=SECRET)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

LOGGER_URL = os.getenv("LOGGER_URL", "http://logger:8001")
LOGGER_API_KEY = os.getenv("LOGGER_API_KEY", "vali-logger-secret-key-change-me")

# Progressive unlock thresholds (actions required)
UNLOCK_RULES = {
    "api_docs": {"min_actions": 3, "paths": ["/login", "/dashboard", "/users"]},
    "staging": {"min_actions": 6, "required_unlock": "api_docs"},
    "config_panel": {"min_actions": 9, "required_unlock": "staging"},
    "backup_files": {"min_actions": 12, "required_unlock": "config_panel"},
}


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_or_create_session_id(request: Request) -> str:
    sid = request.session.get("vali_sid")
    if not sid:
        sid = str(uuid.uuid4())
        request.session["vali_sid"] = sid
        request.session["actions"] = 0
        request.session["unlocks"] = []
        request.session["paths_seen"] = []
        request.session["start_time"] = time.time()
    return sid


async def log_event(
    session_id: str,
    event_type: str,
    request: Request,
    path: str = None,
    status_code: int = None,
    details: Dict[str, Any] = None,
):
    """Send interaction to VALI Logger (fire-and-forget style)."""
    payload = {
        "session_id": session_id,
        "event_type": event_type,
        "source_ip": get_client_ip(request),
        "user_agent": request.headers.get("user-agent"),
        "method": request.method,
        "path": path or str(request.url.path),
        "query": str(request.url.query) if request.url.query else None,
        "status_code": status_code,
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(
                f"{LOGGER_URL}/ingest",
                json=payload,
                headers={"X-API-Key": LOGGER_API_KEY},
            )
    except Exception:
        # Never let logging break the decoy experience
        pass


def increment_action(request: Request, path: str):
    request.session["actions"] = request.session.get("actions", 0) + 1
    paths = request.session.get("paths_seen", [])
    if path not in paths:
        paths.append(path)
        request.session["paths_seen"] = paths


def check_unlocks(request: Request) -> List[str]:
    """Evaluate progressive unlock rules and return newly unlocked features."""
    actions = request.session.get("actions", 0)
    current_unlocks = set(request.session.get("unlocks", []))
    newly = []

    for name, rule in UNLOCK_RULES.items():
        if name in current_unlocks:
            continue
        if actions < rule.get("min_actions", 999):
            continue
        req = rule.get("required_unlock")
        if req and req not in current_unlocks:
            continue
        # Unlock it
        current_unlocks.add(name)
        newly.append(name)

    if newly:
        request.session["unlocks"] = list(current_unlocks)
    return newly


async def process_request(request: Request, path: str, status_code: int = 200, details: dict = None):
    sid = get_or_create_session_id(request)
    increment_action(request, path)
    newly = check_unlocks(request)

    await log_event(sid, "request", request, path=path, status_code=status_code, details=details)

    for unlock in newly:
        await log_event(
            sid,
            "unlock",
            request,
            path=path,
            details={"unlocked": unlock, "total_actions": request.session.get("actions")},
        )
    return sid


# ---------------------------------------------------------------------------
# Routes - Designed to look like a real (slightly messy) internal portal
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    await process_request(request, "/")
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "unlocks": request.session.get("unlocks", []),
            "actions": request.session.get("actions", 0),
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    await process_request(request, "/login")
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None, "unlocks": request.session.get("unlocks", [])},
    )


@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    sid = await process_request(
        request,
        "/login",
        details={"username_attempt": username, "password_length": len(password)},
    )
    await log_event(
        sid,
        "login_attempt",
        request,
        path="/login",
        details={"username": username, "success": False},
    )

    # Always fail, but look realistic. Different messages to encourage more tries.
    messages = [
        "Invalid credentials. Please try again.",
        "Account locked due to multiple failed attempts. Contact IT.",
        "Authentication service temporarily unavailable.",
        "Password expired. Please reset via the self-service portal.",
    ]
    # Pseudo-random based on username
    idx = hash(username) % len(messages)
    error = messages[idx]

    # Small artificial delay to raise cost slightly
    time.sleep(0.4 + (hash(password) % 10) / 20)

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": error,
            "unlocks": request.session.get("unlocks", []),
        },
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    await process_request(request, "/dashboard")
    unlocks = request.session.get("unlocks", [])
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "unlocks": unlocks,
            "actions": request.session.get("actions", 0),
        },
    )


@app.get("/users", response_class=HTMLResponse)
async def users(request: Request):
    await process_request(request, "/users")
    return templates.TemplateResponse(
        "users.html",
        {"request": request, "unlocks": request.session.get("unlocks", [])},
    )


@app.get("/api/docs", response_class=HTMLResponse)
async def api_docs(request: Request):
    unlocks = request.session.get("unlocks", [])
    if "api_docs" not in unlocks:
        # Still log the probe
        await process_request(request, "/api/docs", status_code=403)
        return templates.TemplateResponse(
            "forbidden.html",
            {"request": request, "message": "API documentation is restricted."},
            status_code=403,
        )
    await process_request(request, "/api/docs")
    return templates.TemplateResponse(
        "api_docs.html",
        {"request": request, "unlocks": unlocks},
    )


@app.get("/staging", response_class=HTMLResponse)
async def staging(request: Request):
    unlocks = request.session.get("unlocks", [])
    if "staging" not in unlocks:
        await process_request(request, "/staging", status_code=403)
        return templates.TemplateResponse(
            "forbidden.html",
            {"request": request, "message": "Staging environment access denied."},
            status_code=403,
        )
    await process_request(request, "/staging")
    return templates.TemplateResponse(
        "staging.html",
        {"request": request, "unlocks": unlocks},
    )


@app.get("/config", response_class=HTMLResponse)
async def config_panel(request: Request):
    unlocks = request.session.get("unlocks", [])
    if "config_panel" not in unlocks:
        await process_request(request, "/config", status_code=403)
        return templates.TemplateResponse(
            "forbidden.html",
            {"request": request, "message": "Configuration panel requires elevated privileges."},
            status_code=403,
        )
    await process_request(request, "/config")
    return templates.TemplateResponse(
        "config.html",
        {"request": request, "unlocks": unlocks},
    )


@app.get("/backups", response_class=HTMLResponse)
async def backups(request: Request):
    unlocks = request.session.get("unlocks", [])
    if "backup_files" not in unlocks:
        await process_request(request, "/backups", status_code=403)
        return templates.TemplateResponse(
            "forbidden.html",
            {"request": request, "message": "Backup repository is not accessible."},
            status_code=403,
        )
    await process_request(request, "/backups")
    return templates.TemplateResponse(
        "backups.html",
        {"request": request, "unlocks": unlocks},
    )


# Fake API endpoints that look juicy
@app.get("/api/v1/users")
async def api_users(request: Request):
    await process_request(request, "/api/v1/users", details={"api_call": True})
    return JSONResponse(
        {
            "status": "error",
            "message": "Authentication required",
            "code": "AUTH_REQUIRED",
        },
        status_code=401,
    )


@app.get("/api/v1/config")
async def api_config(request: Request):
    await process_request(request, "/api/v1/config", details={"api_call": True})
    return JSONResponse(
        {
            "status": "error",
            "message": "Insufficient permissions",
            "code": "FORBIDDEN",
        },
        status_code=403,
    )


@app.get("/api/v1/health")
async def api_health(request: Request):
    await process_request(request, "/api/v1/health", details={"api_call": True})
    return {"status": "ok", "version": "2.4.1-internal", "env": "production"}


# Catch-all for probing
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def catch_all(request: Request, full_path: str):
    path = "/" + full_path
    await process_request(request, path, status_code=404)
    return templates.TemplateResponse(
        "404.html",
        {"request": request, "path": path},
        status_code=404,
    )
