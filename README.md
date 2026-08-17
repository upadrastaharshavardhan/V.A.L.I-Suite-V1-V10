# VALI Complete Suite — V1 → V10

**Deception-Driven Security for Adversarial Intelligence**

> Turn attacker effort into defensive strength.

This package contains the full evolutionary path of **VALI**, from the first working MVP to the release-grade deception fabric.

Each version is a **complete, runnable codebase** in its own folder under `versions/`.

---

## Quick Map

| Folder | Version | Focus |
|--------|---------|--------|
| `versions/v01-mvp` | V1 | Progressive web decoy + telemetry + dashboard |
| `versions/v02-ssh` | V2 | SSH honeypot + richer logging |
| `versions/v03-risk-canaries` | V3 | Risk scoring + canary tokens + secrets vault |
| `versions/v04-profiling` | V4 | Attacker profiling + correlation + timelines |
| `versions/v05-campaigns` | V5 | Campaign aggregation by IP + metrics |
| `versions/v06-killchain` | V6 | Kill-chain tags + campaign risk + notes + webhooks |
| `versions/v07-playbooks` | V7 | Auto-playbooks + local blocklist |
| `versions/v08-llm-paths` | V8 | LLM adaptive SSH + attack path summaries |
| `versions/v09-stix` | V9 | STIX-lite export + campaign narratives + high-risk webhooks |
| `versions/v10-release` | V10 | **Recommended** — full product packaging + demo script |

**Start here for the full product:** `versions/v10-release`

---

## What is VALI?

VALI is a **defensive deception architecture**:

1. Present believable but isolated environments
2. Force attackers to invest time and tools (progressive engagement)
3. Observe everything
4. Score risk, tag kill-chain stages, detect tools
5. Raise cost through adaptive friction
6. Export intelligence (JSON / CSV / STIX-lite)
7. Never retaliate. Never expose real assets.

Inspired by the Ramayana principle of Vali: the more the opponent fights, the stronger the defender becomes.

---

## How to Run Any Version

```bash
cd versions/v10-release   # or any other version folder
cp .env.example .env
./scripts/start.sh
```

| Service | Default |
|---------|---------|
| Web Decoy | http://localhost:8080 |
| SSH Honeypot | `ssh anyuser@localhost -p 2222` (V2+) |
| Dashboard | http://localhost:8501 |
| Logger API | http://localhost:8001 |

V10 also includes:

```bash
./scripts/demo.sh     # generate sample progressive engagement
./scripts/status.sh
./scripts/rotate.sh
```

---

## Capability Matrix

| Capability | V1 | V2 | V3 | V4 | V5 | V6 | V7 | V8 | V9 | V10 |
|------------|----|----|----|----|----|----|----|----|----|-----|
| Progressive web decoy | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Telemetry + sessions | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Intelligence dashboard | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SSH honeypot | | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Risk scoring | | | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Canary tokens | | | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Secrets vault layer | | | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Attacker profiling | | | | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| IP correlation | | | | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Campaigns by IP | | | | | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Metrics endpoint | | | | | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Kill-chain tags | | | | | | ✓ | ✓ | ✓ | ✓ | ✓ |
| Analyst notes API | | | | | | ✓ | ✓ | ✓ | ✓ | ✓ |
| Canary webhooks | | | | | | ✓ | ✓ | ✓ | ✓ | ✓ |
| Auto-playbooks | | | | | | | ✓ | ✓ | ✓ | ✓ |
| Local blocklist | | | | | | | ✓ | ✓ | ✓ | ✓ |
| LLM adaptive SSH | | | | | | | | ✓ | ✓ | ✓ |
| Attack path summary | | | | | | | | ✓ | ✓ | ✓ |
| STIX-lite export | | | | | | | | | ✓ | ✓ |
| Campaign narratives | | | | | | | | | ✓ | ✓ |
| High-risk webhooks | | | | | | | | | ✓ | ✓ |
| Demo script + packaging | | | | | | | | | | ✓ |

---

## Recommended Path

1. **Learn the idea** → read this README + `docs/ARCHITECTURE.md`
2. **Run the product** → `versions/v10-release`
3. **Study evolution** → open earlier versions folder by folder
4. **Customize** → `config/vali.yaml` in V10

---

## Safety & Ethics

- Strict isolation — no path to production
- No real credentials or production data in decoys
- No retaliation / no outbound offense
- Deploy only on systems you own or are authorized to protect

---

## Documentation

| Doc | Description |
|-----|-------------|
| `docs/ARCHITECTURE.md` | System design across versions |
| `docs/EVOLUTION.md` | What each version added and why |
| `docs/QUICKSTART.md` | Fastest path to a running demo |
| `versions/v10-release/CHANGELOG.md` | Detailed version history |
| `versions/v10-release/LICENSE` | MIT + defensive-use notice |

---

Built with conviction.  
Attackers spend. Defenders learn.
