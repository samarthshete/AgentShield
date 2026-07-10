# Deploying AgentShield — Vercel (web) + Render (API)

The frontend is a static Vite bundle (hosted on Vercel's CDN); the API is a FastAPI
container (hosted on Render). They communicate over HTTPS, gated by a shared token.

```
 Browser ──HTTPS──▶ Vercel (static web)
    │
    └──fetch /api/* (Authorization: Bearer <token>)──▶ Render (agentshield-api)
```

## Prerequisites
- A GitHub repo connected to both Render and Vercel.
- A strong API token, e.g. `python -c "import secrets; print(secrets.token_urlsafe(32))"`.

## 1. API on Render
1. Render dashboard → **New → Blueprint** → pick this repo. Render reads [`render.yaml`](../render.yaml)
   and provisions the `agentshield-api` Docker service (`./Dockerfile`, health check `/api/health`).
2. Set the env vars marked `sync: false`:
   - `AGENTSHIELD_API_TOKEN` = your generated token.
   - `AGENTSHIELD_CORS_ORIGINS` = your Vercel URL (set after step 2; e.g. `https://agentshield.vercel.app`).
   - `OPENAI_API_KEY` / `CLAUDE_API_KEY` — only if you use the LLM judge.
3. Deploy, then confirm: `curl https://<api>.onrender.com/api/health` → `{"status":"ok",...}`.

> Note: the free plan sleeps on idle; the first request after a sleep is slow. SQLite lives on
> the container's ephemeral disk — a Render Disk mount is documented in `render.yaml`
> (requires a paid plan), or move to Postgres, if you need scan history to survive restarts.
> The schema already enforces FK cascades + indexes either way.

## 2. Web on Vercel
1. Vercel dashboard → **Add New → Project** → import this repo.
2. Set **Root Directory** to `web/`. Framework auto-detects as Vite; build config is in
   [`web/vercel.json`](../web/vercel.json) (build `npm run build`, output `dist`, SPA rewrite).
3. Add a build-time env var: `VITE_API_BASE_URL` = your Render API URL (e.g.
   `https://agentshield-api.onrender.com`). **Do not** set `VITE_API_TOKEN` — the token is
   entered at runtime in the Settings page so it never ships in the static bundle.
4. Deploy. Copy the resulting Vercel URL.

## 3. Wire CORS + verify end-to-end
1. Back in Render, set `AGENTSHIELD_CORS_ORIGINS` to the exact Vercel origin and redeploy.
2. Open the Vercel URL → **Settings** page → paste the API token → **Test connection**:
   the connection indicator should read ● **reachable**.
3. Run a Static Scan on `benchmarks/fixtures` — findings render with no 401.

## Rollback / local parity
The whole stack also runs locally via [`docker-compose.yml`](../docker-compose.yml)
(`AGENTSHIELD_API_TOKEN=... docker compose up`) — useful for verifying a release candidate
before promoting it.
