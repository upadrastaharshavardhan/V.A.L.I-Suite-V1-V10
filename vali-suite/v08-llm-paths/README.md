# VALI v8 — Advanced Deception Fabric

**Version 8.0**

> Turn attacker effort into defensive strength.

VALI is a deception-driven security system that forces attackers into realistic, isolated environments, raises their cost through progressive engagement, extracts deep behavioral intelligence, and surfaces high-fidelity alerts — without retaliation and without exposing real assets.

---

## What’s New in Version 8

| Capability | Description |
|------------|-------------|
| **LLM Adaptive Module** | Shared optional OpenAI-compatible client for dynamic SSH (and extensible web) responses |
| **Attack Path Summary** | Per-session ordered summary of kill-chain progression |
| **Auto-Playbooks + Blocklist** | High-risk / canary automatic notes and local IP blocklist |
| **Campaign Risk** | Aggregate scoring by source IP |
| **Kill-Chain Tags** | recon → credential_access → discovery → collection → execution |
| **Webhooks** | Optional canary notifications |
| **Analyst Notes** | Manual + automatic |
| **Full Ops Toolkit** | start, rotate, status, metrics, export, blocklist |

---

## Quick Start

```bash
cd vali-v8
cp .env.example .env
./scripts/start.sh
```

**Access**

| Service | Endpoint |
|---------|----------|
| Web Decoy | http://localhost:8080 |
| SSH Honeypot | `ssh anyuser@localhost -p 2222` |
| Dashboard | http://localhost:8501 |
| Logger API | http://localhost:8001 |

---

## Optional LLM Mode

```env
ENABLE_LLM=true
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
```

When enabled, unknown SSH commands can receive dynamic realistic responses.  
When disabled (default), VALI runs fully offline.

---

## Core Principles

- Strict isolation
- No retaliation
- Progressive engagement (Vali mechanic)
- Resource drain as defense
- Full observability → actionable intelligence

---

Attackers spend. Defenders learn.
