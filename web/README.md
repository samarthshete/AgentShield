# AgentShield Web Console

React/Vite console for the AgentShield FastAPI backend.

## Development

```bash
npm install
npm run dev
```

Default dev URL: `http://127.0.0.1:5173`.

## API Connection

The console reads API settings in this order:

1. Settings page values saved in `localStorage`
2. `VITE_API_BASE_URL` / `VITE_API_TOKEN`
3. `http://127.0.0.1:8000` and no token

Create `web/.env` when you want defaults for local development:

```bash
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_API_TOKEN=
```

When the backend has `AGENTSHIELD_API_TOKEN` set, enter the same token in the
Settings page. The Docker image does not bake the token into the bundle.

## Build, Preview, And Test

```bash
npm run build
npm run preview
npm run test
```

## Docker

Build the web image:

```bash
docker build -t agentshield-web ./web
```

Run the full API + web stack from the repository root:

```bash
AGENTSHIELD_API_TOKEN=change-me docker compose up --build
```

The web console is served by nginx on `http://localhost:8080`.
