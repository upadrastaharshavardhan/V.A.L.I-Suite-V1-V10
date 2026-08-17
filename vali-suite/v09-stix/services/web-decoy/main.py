"""
VALI Web Decoy v9 — Progressive + Canaries + Optional LLM feel
"""

import os
import uuid
import time
import random
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

import httpx
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI(title="NexusOps Control Plane", docs_url=None, redoc_url=None)
SECRET = os.getenv("WEB_DECOY_SECRET", "change-me-to-a-very-long-random-string-v9")
app.add_middleware(SessionMiddleware, secret_key=SECRET)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

LOGGER_URL = os.getenv("LOGGER_URL", "http://logger:8001")
LOGGER_API_KEY = os.getenv("LOGGER_API_KEY", "vali-logger-secret-key-change-me-v9")
ENABLE_DELAY = os.getenv("ENABLE_ADAPTIVE_DELAY", "true").lower() == "true"
MIN_DELAY = int(os.getenv("MIN_DELAY_MS", "120")) / 1000.0
MAX_DELAY = int(os.getenv("MAX_DELAY_MS", "800")) / 1000.0
ENABLE_LLM = os.getenv("ENABLE_LLM", "false").lower() == "true"

CONFIG_PATH = Path("/app/config/vali.yaml")

def load_unlocks():
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                cfg = yaml.safe_load(f) or {}
            return cfg.get("progressive", {}).get("unlocks", {})
        except Exception:
            pass
    return {
        "api_docs": {"min_actions": 3},
        "staging": {"min_actions": 6, "requires": "api_docs"},
        "config_panel": {"min_actions": 10, "requires": "staging"},
        "backup_files": {"min_actions": 14, "requires": "config_panel"},
        "secrets_vault": {"min_actions": 17, "requires": "backup_files"},
    }

UNLOCK_RULES = load_unlocks()


def get_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_sid(request: Request) -> str:
    sid = request.session.get("vali_sid")
    if not sid:
        sid = str(uuid.uuid4())
        request.session["vali_sid"] = sid
        request.session["actions"] = 0
        request.session["unlocks"] = []
        request.session["paths_seen"] = []
    return sid


async def log_event(sid, etype, request, path=None, status=None, details=None):
    payload = {
        "session_id": sid,
        "event_type": etype,
        "source_ip": get_ip(request),
        "user_agent": request.headers.get("user-agent"),
        "method": request.method,
        "path": path or str(request.url.path),
        "query": str(request.url.query) if request.url.query else None,
        "status_code": status,
        "service": "web",
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=2.5) as c:
            await c.post(f"{LOGGER_URL}/ingest", json=payload, headers={"X-API-Key": LOGGER_API_KEY})
    except Exception:
        pass


async def fire_canary(sid, canary_id, request, extra=None):
    try:
        async with httpx.AsyncClient(timeout=2.5) as c:
            await c.post(f"{LOGGER_URL}/canary",
                         params={"session_id": sid, "canary_id": canary_id, "source_ip": get_ip(request)},
                         json=extra or {}, headers={"X-API-Key": LOGGER_API_KEY})
    except Exception:
        pass


def delay():
    if ENABLE_DELAY:
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))


def bump(request, path):
    request.session["actions"] = request.session.get("actions", 0) + 1
    paths = request.session.get("paths_seen", [])
    if path not in paths:
        paths.append(path)
        request.session["paths_seen"] = paths


def check_unlocks(request) -> List[str]:
    actions = request.session.get("actions", 0)
    current = set(request.session.get("unlocks", []))
    newly = []
    for name, rule in UNLOCK_RULES.items():
        if name in current:
            continue
        if actions < rule.get("min_actions", 999):
            continue
        req = rule.get("requires")
        if req and req not in current:
            continue
        current.add(name)
        newly.append(name)
    if newly:
        request.session["unlocks"] = list(current)
    return newly


async def process(request, path, status=200, details=None):
    sid = get_sid(request)
    bump(request, path)
    newly = check_unlocks(request)
    delay()
    await log_event(sid, "request", request, path=path, status=status, details=details)
    for u in newly:
        await log_event(sid, "unlock", request, path=path,
                        details={"unlocked": u, "total_actions": request.session.get("actions")})
    return sid


# Routes

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    await process(request, "/")
    return templates.TemplateResponse("index.html", {
        "request": request, "unlocks": request.session.get("unlocks", []),
        "actions": request.session.get("actions", 0),
    })


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    await process(request, "/login")
    return templates.TemplateResponse("login.html", {
        "request": request, "error": None, "unlocks": request.session.get("unlocks", []),
    })


@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    sid = await process(request, "/login", details={"username_attempt": username[:80], "password_length": len(password)})
    await log_event(sid, "login_attempt", request, path="/login", details={"username": username[:80], "success": False})
    time.sleep(0.2 + random.random() * 0.45)
    msgs = ["Invalid credentials.", "Account locked. Contact IT.", "MFA challenge required.",
            "Password expired.", "Authentication service unavailable."]
    err = msgs[hash(username + password) % len(msgs)]
    return templates.TemplateResponse("login.html", {
        "request": request, "error": err, "unlocks": request.session.get("unlocks", []),
    })


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    await process(request, "/dashboard")
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "unlocks": request.session.get("unlocks", []),
        "actions": request.session.get("actions", 0),
    })


@app.get("/users", response_class=HTMLResponse)
async def users(request: Request):
    await process(request, "/users")
    return templates.TemplateResponse("users.html", {
        "request": request, "unlocks": request.session.get("unlocks", []),
    })


@app.get("/api/docs", response_class=HTMLResponse)
async def api_docs(request: Request):
    unlocks = request.session.get("unlocks", [])
    if "api_docs" not in unlocks:
        await process(request, "/api/docs", status=403)
        return templates.TemplateResponse("forbidden.html", {
            "request": request, "message": "API documentation restricted.",
        }, status_code=403)
    await process(request, "/api/docs")
    return templates.TemplateResponse("api_docs.html", {"request": request, "unlocks": unlocks})


@app.get("/staging", response_class=HTMLResponse)
async def staging(request: Request):
    unlocks = request.session.get("unlocks", [])
    if "staging" not in unlocks:
        await process(request, "/staging", status=403)
        return templates.TemplateResponse("forbidden.html", {
            "request": request, "message": "Staging access denied.",
        }, status_code=403)
    await process(request, "/staging")
    return templates.TemplateResponse("staging.html", {"request": request, "unlocks": unlocks})


@app.get("/config", response_class=HTMLResponse)
async def config(request: Request):
    unlocks = request.session.get("unlocks", [])
    if "config_panel" not in unlocks:
        await process(request, "/config", status=403)
        return templates.TemplateResponse("forbidden.html", {
            "request": request, "message": "Elevated privileges required.",
        }, status_code=403)
    await process(request, "/config")
    return templates.TemplateResponse("config.html", {"request": request, "unlocks": unlocks})


@app.get("/backups", response_class=HTMLResponse)
async def backups(request: Request):
    unlocks = request.session.get("unlocks", [])
    if "backup_files" not in unlocks:
        await process(request, "/backups", status=403)
        return templates.TemplateResponse("forbidden.html", {
            "request": request, "message": "Backup repository inaccessible.",
        }, status_code=403)
    await process(request, "/backups")
    return templates.TemplateResponse("backups.html", {"request": request, "unlocks": unlocks})


@app.get("/vault", response_class=HTMLResponse)
async def vault(request: Request):
    unlocks = request.session.get("unlocks", [])
    if "secrets_vault" not in unlocks:
        await process(request, "/vault", status=403)
        return templates.TemplateResponse("forbidden.html", {
            "request": request, "message": "Secrets vault requires maximum clearance.",
        }, status_code=403)
    sid = await process(request, "/vault")
    await fire_canary(sid, "canary-vault", request)
    return templates.TemplateResponse("vault.html", {"request": request, "unlocks": unlocks})


@app.get("/api/v1/secrets")
async def api_secrets(request: Request):
    sid = await process(request, "/api/v1/secrets", details={"api_call": True})
    await fire_canary(sid, "canary-aws-key", request, {"endpoint": "/api/v1/secrets"})
    return JSONResponse({"status": "error", "message": "Forbidden"}, status_code=403)


@app.get("/backups/download/{name}")
async def backup_download(request: Request, name: str):
    sid = await process(request, f"/backups/download/{name}", details={"file": name})
    await fire_canary(sid, "canary-backup-download", request, {"file": name})
    return JSONResponse({"status": "error", "message": "Authorization required"}, status_code=401)


@app.get("/api/v1/users")
async def api_users(request: Request):
    await process(request, "/api/v1/users", details={"api_call": True})
    return JSONResponse({"status": "error", "message": "Authentication required"}, status_code=401)


@app.get("/api/v1/config")
async def api_config(request: Request):
    await process(request, "/api/v1/config", details={"api_call": True})
    return JSONResponse({"status": "error", "message": "Insufficient permissions"}, status_code=403)


@app.get("/api/v1/health")
async def api_health(request: Request):
    await process(request, "/api/v1/health", details={"api_call": True})
    return {"status": "ok", "version": "9.0.0-internal", "env": "production"}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def catch_all(request: Request, full_path: str):
    path = "/" + full_path
    await process(request, path, status=404)
    return templates.TemplateResponse("404.html", {"request": request, "path": path}, status_code=404)
