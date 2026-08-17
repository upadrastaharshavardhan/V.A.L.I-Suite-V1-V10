# VALI Quickstart

## Prerequisites

- Docker + Docker Compose
- ~2 GB free RAM recommended
- Ports free: 8080, 2222, 8001, 8501

## Fastest Path (V10 Release)

```bash
cd versions/v10-release
cp .env.example .env
./scripts/start.sh
```

Wait ~20–40 seconds for containers to become healthy.

### Generate sample intelligence

```bash
./scripts/demo.sh
```

### Open the UI

- Dashboard: http://localhost:8501  
- Web Decoy: http://localhost:8080  
- SSH: `ssh anyuser@localhost -p 2222` (any password)

### Useful commands

```bash
./scripts/status.sh
docker compose logs -f
./scripts/rotate.sh          # purge or recreate
docker compose down          # stop
```

## Optional LLM

Edit `.env`:

```env
ENABLE_LLM=true
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
```

Then:

```bash
docker compose up -d --force-recreate ssh-honeypot
```

Unknown SSH commands can then receive dynamic responses.

## Optional Webhooks

```env
WEBHOOK_URL=https://hooks.slack.com/services/...
WEBHOOK_ON_HIGH_RISK=true
```

## Try an Earlier Version

```bash
cd versions/v03-risk-canaries
cp .env.example .env
./scripts/start.sh   # or: docker compose up --build -d
```

Note: script names differ slightly in early versions; V1–V2 may use `docker compose up --build -d` directly if `start.sh` is minimal.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Port in use | Change ports in `.env` |
| Empty dashboard | Run `./scripts/demo.sh` or browse :8080 yourself |
| SSH fails | Ensure port 2222 published; try `ssh -p 2222 anyuser@127.0.0.1` |
| Logger 401 | Use `LOGGER_API_KEY` from `.env` as `X-API-Key` header |

## Safety Reminder

Only deploy on systems you own or are authorized to protect. Decoys contain no real production credentials by design.
