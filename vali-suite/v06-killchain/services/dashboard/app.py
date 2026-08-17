"""
VALI Intelligence Dashboard v6
Risk • Profiles • Campaigns • Kill-chain • Notes • Timelines
"""

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import streamlit as st
import pandas as pd

st.set_page_config(page_title="VALI Intelligence", page_icon="◈", layout="wide")

SESSION_DIR = Path("/app/sessions")
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
                    "first_seen": first, "last_seen": last,
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
                    "kill_chain_tags": data.get("kill_chain_tags", []),
                    "notes": data.get("notes", []),
                    "paths": data.get("paths", []),
                    "commands": data.get("commands", []),
                    "user_agents": data.get("user_agents", []),
                    "raw": data,
                })
        except Exception:
            continue
    sessions.sort(key=lambda x: (x.get("risk_score", 0), x.get("last_seen") or ""), reverse=True)
    return sessions


def build_campaigns(sessions):
    by_ip = defaultdict(list)
    for s in sessions:
        by_ip[s["source_ip"] or "unknown"].append(s)
    camps = []
    for ip, ss in by_ip.items():
        risks = [s["risk_score"] for s in ss]
        tags = set()
        for s in ss:
            tags.update(s.get("kill_chain_tags", []))
        max_r = max(risks) if risks else 0
        avg_r = round(sum(risks)/len(risks), 1) if risks else 0
        camps.append({
            "source_ip": ip,
            "sessions": len(ss),
            "max_risk": max_r,
            "avg_risk": avg_r,
            "campaign_risk": min(100, int(max_r * 0.7 + avg_r * 0.3)),
            "profiles": list({s["profile"] for s in ss}),
            "services": list({s["service"] for s in ss}),
            "canaries": sum(s["canary_hits"] for s in ss),
            "kill_chain": sorted(tags),
        })
    camps.sort(key=lambda x: x["campaign_risk"], reverse=True)
    return camps


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
st.caption("Version 6.0 • Advanced deception fabric")

sessions = load_sessions()
campaigns = build_campaigns(sessions)
canaries = load_canaries()

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Sessions", len(sessions))
c2.metric("Campaigns", len(campaigns))
c3.metric("High Risk", sum(1 for s in sessions if s["risk_score"] >= 50))
c4.metric("Max Risk", max((s["risk_score"] for s in sessions), default=0))
c5.metric("Canaries", sum(s["canary_hits"] for s in sessions) or len(canaries))
c6.metric("Targeted", sum(1 for s in sessions if s["profile"] == "targeted"))

st.divider()
tab1, tab2, tab3 = st.tabs(["Sessions", "Campaigns", "Canaries"])

with tab1:
    if not sessions:
        st.info("No sessions yet.")
    else:
        df = pd.DataFrame([{
            "Risk": s["risk_score"], "Profile": s["profile"],
            "Session": s["session_id"], "IP": s["source_ip"],
            "Svc": s["service"].upper(), "Depth": s["depth"],
            "Events": s["events"], "Canaries": s["canary_hits"],
            "Kill-chain": ", ".join(s["kill_chain_tags"][:4]) or "—",
            "Tools": ", ".join(s["tools"][:3]) or "—",
        } for s in sessions])
        st.dataframe(df, use_container_width=True, hide_index=True)

        opts = {f"[{s['risk_score']}|{s['profile']}] {s['session_id']} | {s['source_ip']}": s for s in sessions}
        choice = st.selectbox("Select session", list(opts.keys()), key="s1")
        if choice:
            sel = opts[choice]
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Risk", sel["risk_score"])
                st.write("**Profile:**", sel["profile"])
                st.write("**IP:**", sel["source_ip"])
                st.write("**Service:**", sel["service"])
            with col2:
                st.write("**Depth:**", sel["depth"])
                st.write("**Events:**", sel["events"])
                st.write("**Logins:**", sel["login_attempts"])
                st.write("**Canaries:**", sel["canary_hits"])
            with col3:
                st.write("**Kill-chain**")
                for t in sel["kill_chain_tags"] or ["—"]:
                    st.info(t) if t != "—" else st.write(t)
                st.write("**Tools**")
                for t in sel["tools"] or ["—"]:
                    st.warning(t) if t != "—" else st.write(t)

            if sel["notes"]:
                st.markdown("**Analyst Notes**")
                for n in sel["notes"]:
                    st.write(f"- [{n.get('at','')[:19]}] {n.get('tag') or ''} {n.get('text')}")

            if sel["canaries_triggered"]:
                st.error("Canaries: " + ", ".join(sel["canaries_triggered"]))
            if sel["paths"]:
                st.markdown("**Path Sequence**")
                st.code(" → ".join(sel["paths"][:40]))
            if sel["commands"]:
                st.markdown("**SSH Commands**")
                st.code("\n".join(sel["commands"][-30:]))
            events = sel["raw"].get("events", [])[-50:]
            if events:
                st.markdown("**Timeline**")
                tdf = pd.DataFrame([{
                    "Time": (e.get("timestamp") or "")[:19],
                    "Type": e.get("event_type"),
                    "Kill-chain": ", ".join(e.get("kill_chain", [])),
                    "Path/Cmd": e.get("path") or (e.get("details") or {}).get("command", ""),
                } for e in events])
                st.dataframe(tdf, use_container_width=True, hide_index=True)

with tab2:
    if not campaigns:
        st.info("No campaigns yet.")
    else:
        cdf = pd.DataFrame([{
            "IP": c["source_ip"], "Sessions": c["sessions"],
            "Campaign Risk": c["campaign_risk"], "Max": c["max_risk"], "Avg": c["avg_risk"],
            "Profiles": ", ".join(c["profiles"]),
            "Services": ", ".join(c["services"]),
            "Canaries": c["canaries"],
            "Kill-chain": ", ".join(c["kill_chain"][:5]) or "—",
        } for c in campaigns])
        st.dataframe(cdf, use_container_width=True, hide_index=True)

with tab3:
    if not canaries:
        st.info("No canary alerts yet.")
    else:
        adf = pd.DataFrame([{
            "Time": (c.get("timestamp") or "")[:19],
            "Canary": (c.get("details") or {}).get("canary_id", "—"),
            "IP": c.get("source_ip"),
            "Session": (c.get("session_id") or "")[:12],
        } for c in canaries[:30]])
        st.dataframe(adf, use_container_width=True, hide_index=True)

st.divider()
st.caption("VALI v6 — Attackers spend. Defenders learn.")
