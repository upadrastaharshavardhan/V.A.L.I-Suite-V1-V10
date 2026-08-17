# VALI v5 — Advanced Deception Fabric

**Version 5.0**

> The more they fight, the stronger you become.

VALI is a deception-driven security system that forces attackers into controlled environments, raises their cost, extracts deep behavioral intelligence, and surfaces high-fidelity alerts — with zero retaliation and strict isolation from real assets.

---

## What’s New in Version 5

| Capability | Description |
|------------|-------------|
| **LLM Adaptive Responses** | Optional OpenAI-compatible dynamic replies for web & SSH (strong offline fallback) |
| **Campaign View** | Aggregate sessions by source IP into attacker campaigns |
| **Honey Tokens** | Embedded fake tokens in pages/files that fire when copied/used |
| **Enhanced Profiling** | Refined scanner / automated / interactive / targeted labels |
| **Live-ish Intelligence** | Richer timelines, related sessions, risk trends |
| **Admin Status Surface** | Clear operational view of decoys and data volume |
| **Safer Defaults** | Stronger isolation notes + rotation tooling |
| **Export + Metrics** | JSON/CSV export + simple metrics endpoint |
| **Config-Driven Everything** | Unlocks, scoring, canaries, delays, LLM settings |

---

## Quick Start

```bash
cd vali-v5
cp .env.example .env
./scripts/start.sh
```

**Access**

| Service | URL / Command | Purpose |
|---------|---------------|---------|
| Web Decoy | http://localhost:8080 | Progressive deceptive portal + canaries |
| SSH Honeypot | `ssh anyuser@localhost -p 2222` | Medium-interaction SSH |
| Dashboard | http://localhost:8501 | Risk, profiles, campaigns, timelines |
| Logger API | http://localhost:8001 | Telemetry, scoring, export, metrics |

---

## Optional LLM Mode

```env
ENABLE_LLM=true
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
```

When enabled, selected responses become more dynamic and context-aware.  
When disabled (default), VALI runs fully offline with high-quality rule-based deception.

---

## Core Principles

- Strict isolation from production
- No retaliation / no outbound attacks
- Progressive engagement (Vali mechanic)
- Resource drain as defense
- Full observability → actionable intelligence
- Ethical & legal boundaries

---

## Safety

- Zero real credentials or production data
- Easy destroy / rotate
- Defensive use only on systems you own or are authorized to protect

---

Attackers spend. Defenders learn.
