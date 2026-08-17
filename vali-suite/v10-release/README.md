# VALI v10 — Deception Fabric (Release)

**Version 10.0**

> Turn attacker effort into defensive strength.

VALI is a deception-driven security system. It presents realistic, isolated environments that force engagement, raise attacker cost, extract deep behavioral intelligence, and surface high-fidelity alerts — without retaliation and without exposing real assets.

Inspired by the Ramayana principle of Vali: the more the opponent fights, the stronger the defender becomes.

---

## Features (v10)

| Area | Capabilities |
|------|----------------|
| **Deception** | Progressive web portal, SSH honeypot, canaries, honey tokens, secrets vault layer |
| **Intelligence** | Risk scoring, attacker profiling, kill-chain tags, attack paths, campaigns + narratives |
| **Response** | Auto-playbooks, local blocklist, webhooks (canary + high-risk), analyst notes |
| **Export** | JSON, CSV, STIX-lite bundle |
| **Adaptive** | Optional LLM responses (OpenAI-compatible) for SSH unknowns |
| **Ops** | One-command start, rotate, status, metrics, health |

---

## Quick Start

```bash
cd vali-v10
cp .env.example .env
./scripts/start.sh
```

| Service | URL / Command |
|---------|----------------|
| Web Decoy | http://localhost:8080 |
| SSH Honeypot | `ssh anyuser@localhost -p 2222` |
| Dashboard | http://localhost:8501 |
| Logger API | http://localhost:8001/health |
| STIX-lite | http://localhost:8001/export/stix-lite |
| Metrics | http://localhost:8001/metrics |

**Demo the loop**

```bash
./scripts/demo.sh
```

---

## Optional Configuration

```env
# LLM adaptive responses
ENABLE_LLM=true
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini

# Alerts
WEBHOOK_URL=https://hooks.slack.com/services/...
WEBHOOK_ON_HIGH_RISK=true
HIGH_RISK_THRESHOLD=60
```

Tune unlocks, scoring, and canaries in `config/vali.yaml`.

---

## Architecture

```
Internet / Lab traffic
        │
        ▼
┌───────────────────────────────────┐
│         VALI Network              │
│  Web Decoy  │  SSH Honeypot       │
│       │            │              │
│       └────► Logger ◄────┘        │
│                 │                 │
│            Dashboard              │
└───────────────────────────────────┘
```

All decoys are isolated. No real credentials. No retaliation.

---

## Safety & Ethics

- Zero real credentials or production data
- Strict container isolation
- Defensive use only on systems you own or are authorized to protect
- Easy destroy/rotate: `./scripts/rotate.sh`

---

## Project Layout

```
vali-v10/
├── config/vali.yaml          # Unlock rules, scoring, canaries
├── docker-compose.yml
├── scripts/                  # start, demo, rotate, status
├── services/
│   ├── web-decoy/            # Progressive deceptive portal
│   ├── ssh-honeypot/         # Medium-interaction SSH (+ optional LLM)
│   ├── logger/               # Telemetry, scoring, export, playbooks
│   ├── dashboard/            # Intelligence UI
│   └── shared/llm_client.py  # Optional LLM helper
└── data/                     # Sessions, logs, canaries, blocklist
```

---

## Version History (summary)

| Version | Focus |
|---------|--------|
| V1–V3 | Progressive decoy, SSH, risk, canaries |
| V4–V5 | Profiling, correlation, campaigns |
| V6–V7 | Kill-chain, playbooks, blocklist |
| V8–V9 | LLM adaptive, attack paths, STIX-lite, narratives |
| **V10** | **Release packaging, demo script, operational polish** |

---

Built with conviction.  
Attackers spend. Defenders learn.
