# Version Folder Index

```
vali-suite/
├── README.md                 ← Start here
├── docs/
│   ├── ARCHITECTURE.md
│   ├── EVOLUTION.md
│   ├── QUICKSTART.md
│   └── VERSIONS.md           ← This file
└── versions/
    ├── v01-mvp/              VALI 1.0 — Progressive web decoy + telemetry
    ├── v02-ssh/              VALI 2.0 — + SSH honeypot
    ├── v03-risk-canaries/    VALI 3.0 — + Risk scoring + canaries + vault
    ├── v04-profiling/        VALI 4.0 — + Profiling + correlation
    ├── v05-campaigns/        VALI 5.0 — + Campaigns + metrics
    ├── v06-killchain/        VALI 6.0 — + Kill-chain + notes + webhooks
    ├── v07-playbooks/        VALI 7.0 — + Auto-playbooks + blocklist
    ├── v08-llm-paths/        VALI 8.0 — + LLM adaptive + attack paths
    ├── v09-stix/             VALI 9.0 — + STIX-lite + narratives
    └── v10-release/          VALI 10.0 — Release packaging + demo (RECOMMENDED)
```

## Typical Layout Inside Each Version

```
vXX-*/
├── README.md
├── .env.example
├── .gitignore
├── docker-compose.yml
├── config/
│   └── vali.yaml             (V2+)
├── scripts/
│   ├── start.sh
│   ├── status.sh             (later versions)
│   ├── rotate.sh             (later versions)
│   └── demo.sh               (V10)
├── services/
│   ├── web-decoy/
│   ├── ssh-honeypot/         (V2+)
│   ├── logger/
│   ├── dashboard/
│   └── shared/               (V8+ LLM client)
└── data/                     (runtime; empty placeholders in this suite)
```

## Which Version Should You Use?

| Goal | Use |
|------|-----|
| Full product demo | **v10-release** |
| Understand progressive decoy only | v01-mvp |
| Add SSH deception | v02-ssh+ |
| Study risk + canaries | v03-risk-canaries |
| Threat intel export | v09-stix or v10-release |
| Learn the evolution | Walk v01 → v10 in order |
