# VALI v7 — Advanced Deception Fabric

**Version 7.0**

> The more they fight, the stronger you become.

VALI is a deception-driven security system that forces attackers into realistic isolated environments, raises their cost, extracts deep behavioral intelligence, and surfaces high-fidelity alerts — with zero retaliation and strict isolation from real assets.

---

## What’s New in Version 7

| Capability | Description |
|------------|-------------|
| **LLM Adaptive Engine** | Real optional OpenAI-compatible client for dynamic web/SSH responses (offline fallback) |
| **Auto-Playbooks** | Automatic analyst notes on high-risk sessions and canary hits |
| **Local Blocklist** | File-based high-risk IP tracking (for lab / downstream use) |
| **Kill-Chain + Campaign Risk** | Full tagging and campaign scoring |
| **Webhook Alerts** | Optional notifications on canaries |
| **Analyst Notes API** | Manual + automatic notes on sessions |
| **Richer SSH** | More realistic fake FS + optional LLM for unknown commands |
| **Operational Tooling** | Status, rotate, metrics, export |

---

## Quick Start

```bash
cd vali-v7
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

---

## Optional LLM Mode

```env
ENABLE_LLM=true
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
```

---

## Optional Webhook

```env
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
