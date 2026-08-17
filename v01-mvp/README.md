# VALI — Deception-Driven Security for Adversarial Intelligence

**Version 1.0 (MVP)**

VALI turns attacker effort into defensive advantage.

Attackers interact with realistic but fully isolated deceptive environments.  
While they spend time, tools, and infrastructure, VALI observes everything,  
raises their cost, and extracts actionable intelligence — without ever touching real assets or retaliating.

Inspired by the Ramayana principle of Vali: the more the opponent fights, the stronger the defender becomes.

---

## Core Principles (Non-Negotiable)

- **Strict isolation** — No path to production systems
- **No retaliation** — Purely defensive
- **Full observability** — Every interaction is logged
- **Progressive engagement** — Attackers who dig deeper see more (fake) value
- **Resource drain** — Raise attacker cost through realistic friction and multi-step paths
- **Ethical boundaries** — No malware, no outbound attacks, no real credentials/data

---

## What Version 1 Includes

| Component              | Description                                      |
|------------------------|--------------------------------------------------|
| Web Decoy              | Realistic internal admin portal + progressive layers |
| Progressive Engine     | Session-based unlocking of deeper deceptive surfaces |
| Telemetry Pipeline     | Structured JSON logging of every request & action |
| Intelligence Summary   | Basic attacker session analysis                  |
| Isolation              | Docker network isolation + no outbound from decoys |
| One-command deploy     | `docker compose up`                              |

---

## Quick Start

### Requirements
- Docker + Docker Compose
- 2+ GB free RAM recommended

### Run VALI

```bash
git clone <your-repo>
cd vali
cp .env.example .env
docker compose up --build -d
```

### Access Points

| Service          | URL                          | Notes                          |
|------------------|------------------------------|--------------------------------|
| Web Decoy        | http://localhost:8080        | Main deceptive surface         |
| Dashboard        | http://localhost:8501        | Intelligence view              |
| Logger API       | http://localhost:8001        | Internal telemetry endpoint    |

### Stop

```bash
docker compose down
```

---

## Architecture (V1)

```
Internet / Suspicious Traffic
          │
          ▼
   [ Traefik / Direct ]
          │
          ▼
┌─────────────────────────────┐
│     VALI Isolated Network   │
│                             │
│  ┌─────────────┐  ┌──────┐  │
│  │  Web Decoy  │  │Logger│  │
│  │  (FastAPI)  │──│      │  │
│  └─────────────┘  └──────┘  │
│         │              │    │
│         └──────┬───────┘    │
│                ▼            │
│         ┌──────────┐        │
│         │Dashboard │        │
│         └──────────┘        │
└─────────────────────────────┘
```

All services run in an isolated Docker network with no route to host production services.

---

## Progressive Engagement (Key VALI Feature)

1. Attacker lands on a believable but slightly imperfect admin portal.
2. As they explore (failed logins, directory probing, specific paths), the system **unlocks** additional surfaces:
   - Internal API documentation
   - "Staging" environment links
   - Fake sensitive file download areas
   - Configuration panels
3. Every step is logged with timing, sequence, and context.
4. The longer and deeper they go, the more intelligence VALI extracts and the higher their resource cost.

---

## Telemetry Collected

- Source IP, User-Agent, timestamps
- Full request path sequence per session
- Timing between actions (automation vs human indicators)
- Tool fingerprints (common scanners, exploit frameworks)
- Session duration and depth reached
- Progressive unlock events

---

## Safety Notes

- Decoys contain **zero** real credentials or production data
- Network is isolated by default
- No outbound connections from decoy containers
- Easy to rotate / destroy instances
- All data stays inside the VALI deployment

---

## Roadmap Beyond V1

- SSH / RDP high-interaction honeypots
- LLM-powered adaptive responses
- Automatic decoy rotation & generation
- SIEM / SOAR integrations
- Behavioral classification (human vs bot vs APT)
- Managed cloud version
- Enterprise multi-tenant support

---

## Legal & Ethical

VALI is designed strictly for defensive use on systems you own or are authorized to protect.  
Do not deploy in ways that violate local laws.

---

Built with belief.
Turn attacker effort into defensive strength.
