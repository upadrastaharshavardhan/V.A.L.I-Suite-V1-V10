# VALI Architecture

## Design Principles

1. **Isolation first** — Decoys never touch production
2. **Progressive engagement** — Attackers who dig deeper unlock more (fake) value
3. **Resource drain** — Adaptive delays and multi-step paths raise attacker cost
4. **Full observability** — Every interaction becomes structured intelligence
5. **No retaliation** — Purely defensive; legal and ethical boundaries enforced
6. **Exportable intelligence** — Sessions, campaigns, STIX-lite for SIEM / research

## High-Level Components

```
                    ┌─────────────────────────────────────┐
  Suspicious        │           VALI Fabric               │
  Traffic ─────────►│                                     │
                    │  ┌──────────┐     ┌──────────────┐  │
                    │  │ Web Decoy│     │ SSH Honeypot │  │
                    │  │(FastAPI) │     │  (asyncssh)  │  │
                    │  └────┬─────┘     └──────┬───────┘  │
                    │       │                  │          │
                    │       └────────┬─────────┘          │
                    │                ▼                    │
                    │         ┌────────────┐              │
                    │         │   Logger   │              │
                    │         │  + Intel   │              │
                    │         └─────┬──────┘              │
                    │               ▼                     │
                    │         ┌────────────┐              │
                    │         │ Dashboard  │              │
                    │         └────────────┘              │
                    └─────────────────────────────────────┘
```

## Web Decoy (Progressive Surface)

- Realistic internal admin portal (“NexusOps”)
- Session-based progressive unlocks:
  - API Docs → Staging → Config → Backups → Secrets Vault
- Login friction, adaptive delays
- Canary endpoints (`/api/v1/secrets`, backup download, vault)
- Full request logging to Logger

## SSH Honeypot (V2+)

- Medium-interaction shell
- Fake filesystem and files (notes, secrets.env, config.yaml)
- Command logging
- Optional LLM responses for unknown commands (V8+)

## Logger / Intelligence Engine

Central brain:

| Function | Description |
|----------|-------------|
| Ingest | Structured events from web + SSH |
| Sessions | Per-attacker session reconstruction |
| Risk score | 0–100 weighted model |
| Profiling | scanner / automated / interactive / targeted |
| Kill-chain tags | recon, credential_access, discovery, collection, execution… |
| Campaigns | Aggregate by source IP + narrative (V9+) |
| Canaries | High-priority alerts |
| Playbooks | Auto-notes, blocklist (V7+) |
| Export | JSON, CSV, STIX-lite (V9+) |
| Webhooks | Optional Slack/Discord/custom alerts |

## Dashboard

Streamlit UI:

- Sessions ranked by risk
- Campaigns by IP
- Canary alerts
- Blocklist (V7+)
- Attack path, timeline, tools, notes

## Data Layout (per version)

```
data/
├── logs/          # JSONL event streams
├── sessions/      # Per-session JSON intelligence
├── canaries/      # Canary alert records
├── blocklist/     # High-risk IPs (V7+)
└── ssh/           # SSH runtime (if any)
```

## Configuration

Primary file: `config/vali.yaml`

- Progressive unlock thresholds
- Scoring weights
- Profiling rules
- Canary definitions
- Playbook flags

## Security Model

- Docker network isolation
- No real secrets in decoys
- No outbound offense
- Easy purge / rotate via scripts
- API key on Logger mutating/export endpoints

## Extension Points

- Add protocols (RDP, SMB, HTTP APIs)
- Stronger isolation (Firecracker, K8s NetworkPolicies)
- Full LLM web responses
- Multi-node / distributed decoys
- SIEM connectors beyond STIX-lite
