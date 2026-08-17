"""
VALI Intelligence Dashboard v2
"""

import json
from pathlib import Path
from datetime import datetime

import streamlit as st
import pandas as pd

st.set_page_config(page_title="VALI Intelligence", page_icon="◈", layout="wide")

SESSION_DIR = Path("/app/sessions")
LOG_DIR = Path("/app/logs")


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
                    "unlocks": data.get("unlocks", []),
                    "tools": data.get("tools", []),
                    "login_attempts": data.get("login_attempts", 0),
                    "paths": data.get("paths", []),
                    "commands": data.get("commands", []),
                    "user_agents": data.get("user_agents", []),
                    "raw": data,
                })
        except Exception:
            continue
    sessions.sort(key=lambda x: x.get("last_seen") or "", reverse=True)
    return sessions


def load_recent_events(limit=80):
    events = []
    if not LOG_DIR.exists():
        return events
    for f in sorted(LOG_DIR.glob("events-*.jsonl"), reverse=True):
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass
        if len(events) >= limit:
            break
    return events[:limit]


# UI
st.title("◈ VALI Intelligence Dashboard")
st.caption("Version 2.0 • Deception-driven adversarial intelligence")

sessions = load_sessions()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Sessions", len(sessions))
c2.metric("Total Events", sum(s["events"] for s in sessions))
c3.metric("Max Depth", max((s["depth"] for s in sessions), default=0))
c4.metric("SSH Sessions", sum(1 for s in sessions if s["service"] == "ssh"))
c5.metric("Deep (≥2)", sum(1 for s in sessions if s["depth"] >= 2))

st.divider()

if not sessions:
    st.info("No sessions yet. Interact with the web decoy (port 8080) or SSH (port 2222) to generate intelligence.")
else:
    st.subheader("Attacker Sessions")
    df = pd.DataFrame([{
        "Session": s["session_id"],
        "IP": s["source_ip"],
        "Service": s["service"].upper(),
        "First Seen": (s["first_seen"] or "")[:19],
        "Duration (s)": s["duration_s"],
        "Events": s["events"],
        "Depth": s["depth"],
        "Tools": ", ".join(s["tools"]) or "—",
        "Logins": s["login_attempts"],
    } for s in sessions])
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.subheader("Session Detail")
    opts = {f"{s['session_id']} | {s['source_ip']} | {s['service']} | depth={s['depth']}": s for s in sessions}
    choice = st.selectbox("Select session", list(opts.keys()))
    if choice:
        sel = opts[choice]
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**IP:** `{sel['source_ip']}`")
            st.markdown(f"**Service:** {sel['service']}")
            st.markdown(f"**Duration:** {sel['duration_s']}s")
            st.markdown(f"**Events:** {sel['events']}")
            st.markdown(f"**Depth:** {sel['depth']}")
            st.markdown(f"**Login attempts:** {sel['login_attempts']}")
        with col2:
            st.markdown("**Unlocks**")
            if sel["unlocks"]:
                for u in sel["unlocks"]:
                    st.success(u)
            else:
                st.write("None")
            st.markdown("**Tools Detected**")
            if sel["tools"]:
                for t in sel["tools"]:
                    st.warning(t)
            else:
                st.write("None")

        if sel["paths"]:
            st.markdown("**Path Sequence**")
            st.code(" → ".join(sel["paths"][:25]))

        if sel["commands"]:
            st.markdown("**SSH Commands**")
            st.code("\n".join(sel["commands"][-20:]))

        st.markdown("**User-Agents**")
        for ua in sel["user_agents"][:4]:
            st.code(ua)

st.divider()
st.subheader("Recent Events")
events = load_recent_events(60)
if events:
    edf = pd.DataFrame([{
        "Time": (e.get("timestamp") or "")[:19],
        "Session": (e.get("session_id") or "")[:12],
        "IP": e.get("source_ip"),
        "Svc": e.get("service", "web"),
        "Type": e.get("event_type"),
        "Path / Cmd": e.get("path") or (e.get("details") or {}).get("command", ""),
    } for e in events])
    st.dataframe(edf, use_container_width=True, hide_index=True)
else:
    st.write("No events recorded yet.")

st.divider()
st.caption("VALI v2 — Attackers spend. Defenders learn. All data stays local.")
