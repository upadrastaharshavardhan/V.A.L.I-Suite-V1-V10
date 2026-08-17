# VALI v6 — Advanced Deception Fabric

**Version 6.0**

> Turn attacker effort into defensive strength.

VALI is a modern deception-driven security system. It forces attackers into realistic, isolated environments, raises their cost through progressive engagement, extracts deep behavioral intelligence, and surfaces high-fidelity alerts — without retaliation and without exposing real assets.

---

## What’s New in Version 6

| Capability | Description |
|------------|-------------|
| **LLM Adaptive Engine** | Optional OpenAI-compatible dynamic responses for web pages & SSH commands (strong offline fallback) |
| **Kill-Chain Tags** | Automatic event labeling (recon, credential_access, discovery, collection, etc.) |
| **Campaign Risk Scoring** | Aggregate risk per source IP campaign |
| **Webhook Alerts** | Optional webhook on canary hits (Slack/Discord/custom) |
| **Analyst Notes** | Attach simple notes/tags to sessions via API |
| **Adaptive Cost Scaling** | Delays increase with aggressive behavior |
| **Richer Dashboard** | Campaigns, kill-chain summary, notes, timelines |
| **Operational Tooling** | Status, rotate, metrics, export |

---

## Quick Start

```bash
cd vali-v6
cp .env.example .env
./scripts/start.sh
```

**Access**

| Service | Endpoint | Purpose |
|---------|----------|---------|
| Web Decoy | http://localhost:8080 | Progressive portal + canaries |
| SSH Honeypot | `ssh anyuser@localhost -p 2222` | Medium-interaction SSH |
| Dashboard | http://localhost:8501 | Full intelligence view |
| Logger API | http://localhost:8001 | Telemetry, campaigns, notes, export |

---

## Optional LLM Mode

```env
ENABLE_LLM=true
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
```

When enabled, selected web and SSH responses become more dynamic.  
When disabled (default), VALI runs fully offline.

---

## Optional Webhook (Canary Alerts)

```env
WEBHOOK_URL=https://hooks.slack.com/services/...
```

---

## Core Principles

- Strict isolation
- No retaliation
- Progressive engagement (Vali mechanic)
- Resource drain as defense
- Full observability → actionable intelligence

---

Attackers spend. Defenders learn.
