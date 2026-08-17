"""
VALI Intelligence Dashboard
Simple view of attacker sessions and progressive engagement.
"""

import json
from pathlib import Path
from datetime import datetime

import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="VALI Intelligence",
    page_icon="◈",
    layout="wide",
)

SESSION_DIR = Path("/app/sessions")
LOG_DIR = Path("/app/logs")


def load_sessions():
    sessions = []
    if not SESSION_DIR.exists():
        return sessions
    for f in SESSION_DIR.glob("*.json"):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                first = data.get("first_seen")
                last = data.get("last_seen")
                duration = 0
                if first and last:
                    try:
                        t1 = datetime.fromisoformat(first.replace("Z", "+00:00"))
                        t2 = datetime.fromisoformat(last.replace("Z", "+00:00"))
                        duration = (t2 - t1).total_seconds()
                    except Exception:
                        pass
                sessions.append({
                    "session_id": data.get("session_id", "")[:12] + "…",
                    "full_id": data.get("session_id"),
                    "source_ip": data.get("source_ip"),
                    "first_seen": first,
                    "last_seen": last,
                    "duration_s": round(duration, 1),
                    "events": len(data.get("events", [])),
                    "depth": data.get("depth", 0),
                    "unlocks": ", ".join(data.get("unlocks", [])),
                    "paths": len(data.get("paths", [])),
                    "user_agents": data.get("user_agents", []),
                    "raw": data,
                })
        except Exception:
            continue
    sessions.sort(key=lambda x: x.get("last_seen") or "", reverse=True)
    return sessions


def load_recent_events(limit=100):
    events = []
    if not LOG_DIR.exists():
        return events
    files = sorted(LOG_DIR.glob("events-*.jsonl"), reverse=True)
    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    events.append(json.loads(line))
                except Exception:
                    continue
        if len(events) >= limit:
            break
    return events[:limit]


# --- UI ---
st.title("◈ VALI Intelligence Dashboard")
st.caption("Deception-driven adversarial intelligence • Version 1.0")

sessions = load_sessions()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Active Sessions", len(sessions))
col2.metric("Total Events", sum(s["events"] for s in sessions))
col3.metric("Max Depth Reached", max((s["depth"] for s in sessions), default=0))
deep = sum(1 for s in sessions if s["depth"] >= 2)
col4.metric("Deep Engagements", deep)

st.divider()

if not sessions:
    st.info("No attacker sessions recorded yet. Interact with the web decoy at http://localhost:8080 to generate data.")
else:
    st.subheader("Attacker Sessions")
    df = pd.DataFrame([
        {
            "Session": s["session_id"],
            "Source IP": s["source_ip"],
            "First Seen": s["first_seen"][:19] if s["first_seen"] else "",
            "Last Seen": s["last_seen"][:19] if s["last_seen"] else "",
            "Duration (s)": s["duration_s"],
            "Events": s["events"],
            "Depth": s["depth"],
            "Unlocks": s["unlocks"] or "—",
            "Paths": s["paths"],
        }
        for s in sessions
    ])
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.subheader("Session Detail")
    options = {f"{s['session_id']} ({s['source_ip']}) — depth {s['depth']}": s for s in sessions}
    choice = st.selectbox("Select session", list(options.keys()))
    if choice:
        selected = options[choice]
        raw = selected["raw"]

        c1, c2 = st.columns(2)
        with c1:
            st.write("**Source IP:**", selected["source_ip"])
            st.write("**Duration:**", f"{selected['duration_s']} seconds")
            st.write("**Events:**", selected["events"])
            st.write("**Depth:**", selected["depth"])
        with c2:
            st.write("**Unlocks:**")
            if selected["unlocks"]:
                for u in selected["unlocks"].split(", "):
                    st.success(u)
            else:
                st.write("None yet")
            st.write("**User-Agents:**")
            for ua in selected["user_agents"][:3]:
                st.code(ua, language=None)

        st.write("**Path Sequence:**")
        paths = raw.get("paths", [])
        st.write(" → ".join(paths) if paths else "—")

        st.write("**Recent Events in Session:**")
        ev_df = pd.DataFrame([
            {
                "Time": e.get("timestamp", "")[:19],
                "Type": e.get("event_type"),
                "Path": e.get("path"),
                "Details": str(e.get("details", {}))[:80],
            }
            for e in raw.get("events", [])[-30:]
        ])
        st.dataframe(ev_df, use_container_width=True, hide_index=True)

st.divider()
st.subheader("Recent Raw Events (last 50)")
events = load_recent_events(50)
if events:
    ev_df = pd.DataFrame([
        {
            "Time": e.get("timestamp", "")[:19],
            "Session": (e.get("session_id") or "")[:12],
            "IP": e.get("source_ip"),
            "Type": e.get("event_type"),
            "Path": e.get("path"),
            "UA": (e.get("user_agent") or "")[:60],
        }
        for e in events
    ])
    st.dataframe(ev_df, use_container_width=True, hide_index=True)
else:
    st.write("No events yet.")

st.divider()
st.caption("VALI — Turn attacker effort into defensive strength. All data stays local.")
