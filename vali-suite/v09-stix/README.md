# VALI v9 — Advanced Deception Fabric

**Version 9.0**

> The more they fight, the stronger you become.

VALI is a deception-driven security system that forces attackers into realistic isolated environments, raises their cost, extracts deep behavioral intelligence, and surfaces high-fidelity alerts — without retaliation and without exposing real assets.

---

## What’s New in Version 9

| Capability | Description |
|------------|-------------|
| **STIX-lite Export** | Structured threat-intel style JSON export of sessions/campaigns |
| **Campaign Narrative** | Human-readable summary of attacker activity per IP |
| **High-Risk Webhooks** | Optional alerts on high-risk threshold (not only canaries) |
| **LLM Adaptive Engine** | Optional dynamic SSH + extensible web responses |
| **Attack Path Summary** | Ordered kill-chain progression per session |
| **Auto-Playbooks + Blocklist** | Automatic notes and local high-risk IP tracking |
| **Full Intelligence Suite** | Risk, profile, campaigns, canaries, notes, metrics |

---

## Quick Start

```bash
cd vali-v9
cp .env.example .env
./scripts/start.sh
```

**Access**

| Service | Endpoint |
|---------|----------|
| Web Decoy | http://localhost:8080 |
| SSH Honeypot | `ssh anyuser@localhost -p 2222` |
| Dashboard | http://localhost:8501 |
| Logger API | http://localhost:8001 |
| STIX-lite | http://localhost:8001/export/stix-lite |

---

## Optional Features

```env
ENABLE_LLM=true
OPENAI_API_KEY=sk-...
WEBHOOK_URL=https://hooks.slack.com/services/...
```

---

## Core Principles

- Strict isolation from production
- No retaliation
- Progressive engagement (Vali mechanic)
- Resource drain as defense
- Full observability → actionable intelligence

---

Attackers spend. Defenders learn.
