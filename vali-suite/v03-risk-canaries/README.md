# VALI v3 — Advanced Deception-Driven Security

**Version 3.0 — Advanced**

> The more they fight, the stronger you become.

VALI is a deception fabric that forces attackers into controlled, realistic environments. It raises their cost, observes their behavior, and turns effort into defensive intelligence — with zero retaliation and strict isolation.

---

## What’s New in Version 3

| Capability | Description |
|------------|-------------|
| **Session Risk Scoring** | Automatic scoring of sessions (depth, tools, speed, login attempts, commands) |
| **Canary Tokens** | Fake secrets / files / endpoints that fire high-priority alerts when touched |
| **Behavior Signals** | Automation vs human indicators (timing, path regularity, tool mix) |
| **Enhanced SSH** | Richer fake filesystem + more realistic command responses |
| **Adaptive Cost** | Configurable delays + progressive friction that scales with engagement |
| **Intel Export** | JSON / CSV export of sessions and events for SIEM or analysis |
| **Central Config** | Single YAML for unlocks, scoring weights, canaries, delays |
| **Rotation Script** | Easy decoy hygiene / session purge |
| **Improved Dashboard** | Risk scores, timelines, tool breakdown, canary hits |
| **Gateway (optional)** | Simple reverse-proxy entrypoint for cleaner exposure |

---

## Quick Start

```bash
cd vali-v3
cp .env.example .env
./scripts/start.sh
```

**Access**

| Service | Endpoint | Notes |
|---------|----------|-------|
| Web Decoy | http://localhost:8080 | Progressive admin portal + canaries |
| SSH Honeypot | `ssh anyuser@localhost -p 2222` | Any password accepted & logged |
| Dashboard | http://localhost:8501 | Risk scores + full intelligence |
| Logger / API | http://localhost:8001 | Telemetry + export endpoints |

---

## Core Vali Mechanics (V3)

1. **Attract** — Realistic web portal + SSH that look valuable.
2. **Engage Progressively** — Deeper exploration unlocks more (fake) value.
3. **Raise Cost** — Adaptive delays, multi-step paths, realistic friction.
4. **Observe Deeply** — Full session reconstruction, tools, timing, commands.
5. **Score & Alert** — Risk score + canary hits for prioritization.
6. **Export** — Clean data for your SOC / SIEM / research.

All of this stays inside isolated containers. No real assets. No retaliation.

---

## Configuration

Primary config: `config/vali.yaml`

You can tune:
- Unlock thresholds
- Scoring weights
- Adaptive delay ranges
- Canary definitions
- Feature flags

---

## Safety & Ethics

- Zero real credentials or production data
- Strict container isolation
- No outbound attacks
- Easy destroy/rotate
- Designed for defensive use only on systems you own or are authorized to protect

---

## Roadmap Beyond V3

- Optional LLM adaptive responses (OpenAI-compatible)
- Automatic decoy generation
- Full STIX/TAXII export
- Multi-node / distributed deployment
- Managed cloud offering

---

Built with conviction.  
Attackers spend. Defenders learn.
