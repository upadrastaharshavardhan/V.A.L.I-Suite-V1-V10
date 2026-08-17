# VALI Evolution — V1 to V10

Each version is intentionally incremental: ship a working loop, then deepen intelligence and operations.

---

## V1 — MVP (`v01-mvp`)

**Goal:** Prove the Vali mechanic.

- Progressive web decoy (admin portal)
- Session tracking + structured logging
- Basic intelligence dashboard
- Docker Compose one-command start

**Core loop established:** attract → engage → observe → unlock → log

---

## V2 — SSH (`v02-ssh`)

**Goal:** Multi-protocol deception.

- Medium-interaction SSH honeypot
- Shared telemetry pipeline for web + SSH
- Tool fingerprinting foundations
- Adaptive delays

---

## V3 — Risk & Canaries (`v03-risk-canaries`)

**Goal:** Prioritize what matters.

- Session risk scoring (0–100)
- Canary tokens on high-value paths
- Secrets Vault progressive layer
- Export JSON/CSV
- Stronger intelligence view

---

## V4 — Profiling (`v04-profiling`)

**Goal:** Understand the attacker.

- Labels: scanner / automated / interactive / targeted
- Cross-service correlation (same IP)
- Event timelines
- LLM-ready hooks (config only)

---

## V5 — Campaigns (`v05-campaigns`)

**Goal:** See campaigns, not only sessions.

- Aggregate sessions by source IP
- Dashboard campaign tab
- Prometheus-style `/metrics`
- Honey token config

---

## V6 — Kill-Chain (`v06-killchain`)

**Goal:** Map behavior to attack stages.

- Automatic kill-chain tags (recon, credential_access, discovery, collection, execution…)
- Campaign risk score
- Analyst notes API
- Optional canary webhooks

---

## V7 — Playbooks (`v07-playbooks`)

**Goal:** Close the response loop.

- Auto-notes on high-risk threshold
- Auto-notes + blocklist on canary
- Local high-risk IP blocklist file + API + dashboard tab
- Operational response foundation

---

## V8 — LLM + Attack Paths (`v08-llm-paths`)

**Goal:** Adaptive realism + clearer story.

- Shared OpenAI-compatible LLM client
- Dynamic SSH responses for unknown commands (optional)
- Ordered attack path summary per session

---

## V9 — STIX + Narratives (`v09-stix`)

**Goal:** Shareable intelligence.

- STIX-lite export bundle
- Human-readable campaign narratives
- High-risk webhooks (not only canaries)

---

## V10 — Release (`v10-release`)

**Goal:** Product packaging.

- Polished README, CHANGELOG, LICENSE
- `./scripts/demo.sh` to exercise the full loop
- Consistent branding and ops scripts
- **Recommended starting point for users and demos**

---

## Design Philosophy Across Versions

| Principle | How it shows up |
|-----------|------------------|
| Ship working value early | V1 already demos progressive engagement |
| Deepen intelligence | Risk → profile → campaign → kill-chain → narrative |
| Stay defensive | No retaliation in any version |
| Stay operable | Docker, scripts, export, webhooks, blocklist |
| Stay optional on AI | LLM is enhancement, never a hard dependency |
