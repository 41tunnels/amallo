# amallo

Securely expose your **local Ollama** instance to the internet from a tray/menu-bar app.

amallo runs an authenticated reverse proxy in front of Ollama and publishes it through an [ngrok](https://ngrok.com) tunnel. Every request must carry a bearer token, so only clients you've given the token can reach your models — no matter that the URL is public.

```
Internet ──ngrok tunnel──▶ amallo proxy (127.0.0.1:11435) ──▶ Ollama (127.0.0.1:11434)
                              └ Bearer-token auth (401 otherwise)
LAN (optional) ───────────────┘
```

- **macOS** — lives in the menu bar (top).
- **Windows** — lives in the system tray (bottom).

## Features

- Reverse proxy with **bearer-token auth** — auto-generated 256-bit token, one click to copy or regenerate.
- **ngrok tunnel** using your own authtoken; optional **static domain** (the free tier includes one) for a stable URL.
- Streams responses (NDJSON / SSE) so `ollama` and OpenAI-compatible clients work unchanged.
- Optional **LAN mode** — bind to `0.0.0.0` and use the same token on your local network without a tunnel.
- Launch at login and auto-start the tunnel.
- Secrets (ngrok authtoken, bearer token) are stored in a `0600` file in amallo's data dir — the same approach ngrok, the AWS CLI and Docker use.

## Setup

1. Have [Ollama](https://ollama.com) running locally (default `127.0.0.1:11434`).
2. Create a free [ngrok account](https://dashboard.ngrok.com) and copy your **authtoken**. (Optionally reserve a free static domain.)
3. Launch amallo → **Settings…** from the tray.
   - Paste the ngrok authtoken → **Save**.
   - (Optional) enter your static domain.
   - Copy the **bearer token** — this is your clients' API key.
4. Click **Start Tunnel** (tray or settings). Copy the public URL from the tray.

## Using it

Point any Ollama or OpenAI-compatible client at the public URL with the bearer token:

```bash
# native Ollama API
curl https://<your-url>/api/tags -H "Authorization: Bearer <token>"

# OpenAI-compatible endpoint (use <token> as the API key)
curl https://<your-url>/v1/chat/completions \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"model":"<model>","messages":[{"role":"user","content":"hi"}]}'
```

## Development

Prerequisites: [Rust](https://rustup.rs), Node 20+, and the [Tauri prerequisites](https://tauri.app/start/prerequisites/) for your OS.

```bash
npm install
npm run tauri dev      # run in development
npm run tauri build    # produce a release bundle for the current OS
```

Cross-platform releases are built in CI — see [`.github/workflows/release.yml`](.github/workflows/release.yml) (matrix over macOS arm64/x64 and Windows). Tauri does not cross-compile, so Windows binaries are produced on a Windows runner. Push a `v*` tag to cut a draft release.

## Notes & caveats

- **ngrok free tier** shows a browser interstitial on the first visit from a browser and has bandwidth caps. API/CLI clients are unaffected.
- Secrets live in `<app-data-dir>/secrets.json` with `0600` permissions (e.g. `~/Library/Application Support/io.github.opencharui.amallo/secrets.json` on macOS). It is **not encrypted at rest** — any process running as your user can read it, and it is not excluded from backups. This matches how ngrok/AWS/Docker store their tokens. Delete the file to reset (a new bearer token is generated on next launch).
- amallo assumes Ollama's default loopback host. A custom `OLLAMA_HOST` upstream isn't configurable yet.
