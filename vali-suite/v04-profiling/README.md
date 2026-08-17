# VALI v4 — Advanced Deception Fabric

**Version 4.0**

> Turn attacker effort into defensive strength.

VALI is a modern deception-driven security system. It presents realistic, isolated environments that force engagement, raise attacker cost, extract deep behavioral intelligence, and surface high-fidelity alerts — without retaliation and without exposing real assets.

Inspired by the Ramayana principle of Vali.

---

## What’s New in Version 4

| Capability | Details |
|------------|---------|
| **Optional LLM Adaptive Responses** | OpenAI-compatible endpoint support for dynamic web/SSH replies (fully optional, strong offline fallback) |
| **Attacker Profiling** | Automatic labels: scanner / automated / interactive / targeted |
| **Cross-Service Correlation** | Sessions from the same IP are linked (web + SSH) |
| **Behavior-Triggered Unlocks** | Not only action count — also path patterns and timing |
| **Advanced Risk Engine** | Refined scoring + profile labels + canary boost |
| **Richer Canaries** | Multiple high-value tripwires with priority |
| **Decoy Status API** | Health, session stats, and basic control endpoints |
| **Timeline View** | Clear event timelines in the dashboard |
| **Export Ready** | JSON + CSV with risk, profile, and canary data |
| **Hygiene Toolkit** | Improved rotate / status / start scripts |

---

## Quick Start

```bash
cd vali-v4
cp .env.example .env
# (optional) add OPENAI_API_KEY + OPENAI_BASE_URL for LLM mode
./scripts/start.sh
```

**Access**

| Service | Endpoint | Notes |
|---------|----------|-------|
| Web Decoy | http://localhost:8080 | Progressive + canaries + adaptive feel |
| SSH Honeypot | `ssh anyuser@localhost -p 2222` | Richer fake environment |
| Dashboard | http://localhost:8501 | Risk, profiles, timelines, canaries |
| Logger / API | http://localhost:8001 | Telemetry, scoring, export, status |

---

## Core Philosophy (Unchanged)

- Strict isolation
- No retaliation
- Progressive engagement (the Vali mechanic)
- Resource drain as defense
- Full observability → actionable intelligence
- Ethical boundaries

---

## Optional LLM Mode

Set in `.env`:

```
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1   # or any compatible endpoint
LLM_MODEL=gpt-4o-mini
ENABLE_LLM=true
```

When enabled, certain responses become more dynamic and context-aware.  
When disabled (default), VALI runs fully offline with high-quality rule-based deception.

---

## Safety

- Zero real credentials or production data
- Containers isolated by design
- Easy destroy / rotate
- Defensive use only

---

Built with conviction.  
Attackers spend. Defenders learn.
