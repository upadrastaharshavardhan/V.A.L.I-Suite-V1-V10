"""
VALI Intelligence Dashboard v4
Risk • Profiles • Correlation • Timelines • Canaries
"""

import json
from pathlib import Path
from datetime import datetime

import streamlit as st
import pandas as pd

st.set_page_config(page_title="VALI Intelligence", page_icon="◈", layout="wide")

SESSION_DIR = Path("/app/sessions")
LOG_DIR = Path("/app/logs")
CANARY_DIR = Path("/app/canaries")


def load_sessions():
    sessions = []
    if not SESSION_DIR.exists():
        return sessions
    for f in SESSION_DIR.glob("*.json"):
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
                first, last = data.get("first_seen"), data.get("last_seen")
                duration = 0.0
                if first and last:
                    try:
                        t1 = datetime.fromisoformat(first.replace("Z", "+00:00"))
                        t2 = datetime.fromisoformat(last.replace("Z", "+00:00"))
                        duration = (t2 - t1).total_seconds()
                    except Exception:
                        pass
                sessions.append({
                    "session_id": (data.get("session_id") or "")[:13] + "…",
                    "full_id": data.get("session_id"),
                    "source_ip": data.get("source_ip"),
                    "service": data.get("service", "web"),
                    "first_seen": first,
                    "last_seen": last,
                    "duration_s": round(duration, 1),
                    "events": len(data.get("events", [])),
                    "depth": data.get("depth", 0),
                    "risk_score": data.get("risk_score", 0),
                    "profile": data.get("profile", "unknown"),
                    "unlocks": data.get("unlocks", []),
                    "tools": data.get("tools", []),
                    "login_attempts": data.get("login_attempts", 0),
                    "canary_hits": data.get("canary_hits", 0),
                    "canaries_triggered": data.get("canaries_triggered", []),
                    "related_sessions": data.get("related_sessions", []),
                    "paths": data.get("paths", []),
                    "commands": data.get("commands", []),
                    "user_agents": data.get("user_agents", []),
                    "raw": data,
                })
        except Exception:
            continue
    sessions.sort(key=lambda x: (x.get("risk_score", 0), x.get("last_seen") or ""), reverse=True)
    return sessions


def load_canaries():
    hits = []
    if CANARY_DIR.exists():
        for f in sorted(CANARY_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                with open(f, encoding="utf-8") as fh:
                    hits.append(json.load(fh))
            except Exception:
                pass
    return hits


st.title("◈ VALI Intelligence Dashboard")
st.caption("Version 4.0 • Advanced deception fabric")

sessions = load_sessions()
canaries = load_canaries()

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Sessions", len(sessions))
c2.metric("High Risk (≥50)", sum(1 for s in sessions if s["risk_score"] >= 50))
c3.metric("Max Risk", max((s["risk_score"] for s in sessions), default=0))
c4.metric("Canary Hits", sum(s["canary_hits"] for s in sessions) or len(canaries))
c5.metric("Targeted", sum(1 for s in sessions if s["profile"] == "targeted"))
c6.metric("SSH", sum(1 for s in sessions if s["service"] == "ssh"))

st.divider()

if not sessions:
    st.info("No sessions yet. Interact with web decoy (:8080) or SSH (:2222).")
else:
    st.subheader("Sessions ranked by Risk")
    df = pd.DataFrame([{
        "Risk": s["risk_score"],
        "Profile": s["profile"],
        "Session": s["session_id"],
        "IP": s["source_ip"],
        "Svc": s["service"].upper(),
        "Depth": s["depth"],
        "Events": s["events"],
        "Canaries": s["canary_hits"],
        "Related": len(s["related_sessions"]),
        "Tools": ", ".join(s["tools"][:3]) or "—",
    } for s in sessions])
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.subheader("Session Detail")
    opts = {f"[{s['risk_score']}|{s['profile']}] {s['session_id']} | {s['source_ip']}": s for s in sessions}
    choice = st.selectbox("Select session", list(opts.keys()))
    if choice:
        sel = opts[choice]
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Risk Score", sel["risk_score"])
            st.write("**Profile:**", sel["profile"])
            st.write("**IP:**", sel["source_ip"])
            st.write("**Service:**", sel["service"])
            st.write("**Duration:**", f"{sel['duration_s']}s")
        with col2:
            st.write("**Depth:**", sel["depth"])
            st.write("**Events:**", sel["events"])
            st.write("**Logins:**", sel["login_attempts"])
            st.write("**Canary hits:**", sel["canary_hits"])
        with col3:
            st.write("**Unlocks**")
            for u in sel["unlocks"] or ["—"]:
                st.success(u) if u != "—" else st.write(u)
            st.write("**Tools**")
            for t in sel["tools"] or ["—"]:
                st.warning(t) if t != "—" else st.write(t)

        if sel["canaries_triggered"]:
            st.error("Canaries: " + ", ".join(sel["canaries_triggered"]))

        if sel["related_sessions"]:
            st.info("Related sessions (same IP): " + ", ".join(
                f"{r.get('service')}({r.get('risk_score')})" for r in sel["related_sessions"][:5]
            ))

        if sel["paths"]:
            st.markdown("**Path Sequence**")
            st.code(" → ".join(sel["paths"][:35]))

        if sel["commands"]:
            st.markdown("**SSH Commands**")
            st.code("\n".join(sel["commands"][-30:]))

        # Simple timeline
        events = sel["raw"].get("events", [])[-40:]
        if events:
            st.markdown("**Recent Timeline**")
            tdf = pd.DataFrame([{
                "Time": (e.get("timestamp") or "")[:19],
                "Type": e.get("event_type"),
                "Path/Cmd": e.get("path") or (e.get("details") or {}).get("command", ""),
            } for e in events])
            st.dataframe(tdf, use_container_width=True, hide_index=True)

st.divider()
if canaries:
    st.subheader("Canary Alerts")
    cdf = pd.DataFrame([{
        "Time": (c.get("timestamp") or "")[:19],
        "Canary": (c.get("details") or {}).get("canary_id", "—"),
        "IP": c.get("source_ip"),
        "Session": (c.get("session_id") or "")[:12],
    } for c in canaries[:25]])
    st.dataframe(cdf, use_container_width=True, hide_index=True)

st.divider()
st.caption("VALI v4 — Attackers spend. Defenders learn. Export: Logger /export/sessions.json")
