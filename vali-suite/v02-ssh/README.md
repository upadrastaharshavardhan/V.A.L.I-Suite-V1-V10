# VALI v2 — Deception-Driven Security for Adversarial Intelligence

**Version 2.0**

> Turn attacker effort into defensive strength.

VALI presents realistic, fully isolated deceptive environments. Attackers invest time, tools, and infrastructure. VALI observes everything, raises their cost through progressive engagement, and extracts actionable intelligence — without ever touching real assets or retaliating.

Inspired by the Ramayana principle of Vali.

---

## What's New in Version 2

| Feature | V1 | V2 |
|---------|----|----|
| Web Decoy | Basic progressive portal | Enhanced realism + more surfaces + adaptive delays |
| SSH Honeypot | — | Medium-interaction SSH with command logging |
| Telemetry | Basic JSONL | Richer events + tool fingerprinting + session correlation |
| Dashboard | Simple tables | Better UX, depth visualization, tool signals |
| Cost Imposition | Light | Adaptive delays + multi-step friction |
| Configuration | Hardcoded | External config for unlock rules & decoy behavior |
| Isolation | Docker network | Explicit internal network + documented safety |
| Deploy | docker compose | One-script start + health checks |

---

## Core Principles (Unchanged)

- Strict isolation from production
- No retaliation / no outbound attacks
- Full observability
- Progressive engagement (the Vali mechanic)
- Resource drain as defense
- Ethical & legal boundaries

---

## Quick Start

```bash
cd vali-v2
cp .env.example .env
./scripts/start.sh
```

**Access points:**

| Service          | URL / Port              | Purpose                          |
|------------------|-------------------------|----------------------------------|
| Web Decoy        | http://localhost:8080   | Main progressive deceptive surface |
| SSH Honeypot     | ssh localhost -p 2222   | Medium-interaction SSH           |
| Dashboard        | http://localhost:8501   | Intelligence view                |
| Logger           | http://localhost:8001   | Telemetry API                    |

**Default SSH credentials (honeypot only):**  
Any username + any password (or try common ones — everything is logged).

Stop:
```bash
docker compose down
```

---

## Architecture (V2)

```
                    ┌──────────────────────────────┐
                    │     VALI Isolated Network    │
 Incoming           │                              │
 Traffic ──────────►│  ┌────────────┐  ┌────────┐  │
                    │  │ Web Decoy  │  │  SSH   │  │
                    │  │ (FastAPI)  │  │Honeypot│  │
                    │  └─────┬──────┘  └───┬────┘  │
                    │        │             │       │
                    │        └──────┬──────┘       │
                    │               ▼              │
                    │        ┌────────────┐        │
                    │        │   Logger   │        │
                    │        └─────┬──────┘        │
                    │              ▼               │
                    │        ┌────────────┐        │
                    │        │ Dashboard  │        │
                    │        └────────────┘        │
                    └──────────────────────────────┘
```

---

## Progressive Engagement (Vali Mechanic)

Attackers who explore more unlock deeper (fake) value:

1. **Surface** → Public admin portal
2. **API Docs** → Unlocked after basic exploration
3. **Staging** → Unlocked after deeper interaction
4. **Config Panel** → Elevated (fake) settings
5. **Backups** → Juicy file index

Every unlock, path sequence, timing, and tool signal is captured.

SSH sessions are tracked independently and appear in the same intelligence dashboard.

---

## Safety

- No real credentials or production data exist in any decoy
- Containers have no route to your real infrastructure
- Easy destroy/rotate: `docker compose down && docker compose up -d --force-recreate`
- All data stays local under `./data`

---

## Configuration

Edit `config/vali.yaml` (or environment variables) to tune unlock thresholds, delays, and decoy behavior.

---

## Roadmap

- LLM-powered adaptive responses
- Automatic decoy generation & rotation
- SIEM / STIX export
- Behavioral classification (human / bot / targeted)
- Multi-tenant / managed version

---

Built with conviction.  
Attackers spend. Defenders learn.
