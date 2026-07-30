# Security Detection Game

[![CI](https://github.com/fid098/AI_Security_Audit_Game/actions/workflows/ci.yml/badge.svg)](https://github.com/fid098/AI_Security_Audit_Game/actions/workflows/ci.yml)

An Among-Us-inspired security training game. Players inspect short code snippets,
label them as SAFE or VULNERABLE, and receive a post-game audit powered by
Hacktron and Claude. Optional voice summaries are generated via ElevenLabs.

**Winner, ICHack 2026 — Best use of Hacktron CLI and the Claude API.**

## Quick Start (Docker)

The whole stack in one command. No Python, Node, or API keys required to get it
running — see [Running without API keys](#running-without-api-keys).

```bash
docker compose up --build
```

- Game: http://localhost:8080
- API: http://localhost:8000
- Interactive API docs: http://localhost:8000/docs

## Features
- LLM-generated tasks with realistic vulnerabilities (XSS, SQLi, SSRF, RCE, etc.)
- Claude-generated per-snippet hints (tutorial mode, reveal on demand)
- Real-time gameplay with timer, scoring, and system status
- Hacktron CLI scan of missed tasks only (fast, focused audits)
- Claude "Security Mentor" post-mortem summary
- Optional ElevenLabs voice output
- Live scan log overlay + staggered findings reveal
- Audit split-screen (live logs + progress ring)
- Tutorial mode toggle with per-snippet hints
- Accuracy by vulnerability type in the report
- Endless mode: 5 easy → 5 medium → 5 hard until first mistake

## Tech Stack
- Frontend: React + Vite + TypeScript
- Backend: FastAPI (Python)
- LLM: Anthropic Claude
- Scanner: Hacktron CLI (WSL supported)
- TTS: ElevenLabs

## Project Structure
```
client/            # React UI
server/
  app/             # FastAPI application
    integrations/  # Claude, Hacktron and ElevenLabs clients
  tests/           # pytest suite
  benchmarks/      # scan latency benchmark
```

## Local Development

### 1) Backend
```
cd server
python -m venv .venv
.\.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2) Frontend
```
cd client
npm install
npm run dev
```

Open http://localhost:5173

## Tests

222 tests covering scoring, session lifecycle, request validation, the Claude
response parser, and the failure path of every third-party integration. No test
touches the network.

```
cd server
pytest                                    # run the suite
pytest --cov=app --cov-report=term-missing  # with coverage (99%)
ruff check app tests benchmarks           # lint
```

## Running Without API Keys

Every external provider is optional, and each degrades independently rather than
breaking the app:

| Missing | Effect |
| --- | --- |
| `HACKTRON_CMD` | Snippets are not statically scanned; the audit notes it and the game plays normally. |
| `ANTHROPIC_API_KEY` | `/generate` returns 503; the mentor summary falls back to a locally generated one. |
| `ELEVENLABS_API_KEY` | `/tts` returns 503; the voice button is unavailable. |

This is why `docker compose up` works on a clean machine with no configuration.

## Environment Variables

Create a `.env` in the repo root. All values are optional.

```ini
ANTHROPIC_API_KEY=your_key
ANTHROPIC_MODEL=claude-sonnet-5
ANTHROPIC_VERSION=2023-06-01

ELEVENLABS_API_KEY=your_key
ELEVENLABS_VOICE_ID=your_voice_id

CORS_ORIGINS=http://localhost:5173,http://localhost:8080

# Hacktron CLI. Use HACKTRON_CMD=wsl on Windows and give the Linux-side path;
# {file} is replaced with the snippet path. Leave unset to skip scanning.
HACKTRON_CMD=wsl
HACKTRON_ARGS=$HOME/.local/bin/hacktron --format json {file}
HACKTRON_MAX_WORKERS=4      # concurrent scans per audit
HACKTRON_TIMEOUT=30         # seconds per scan
```

### Frontend `.env` (client/.env)
```
VITE_API_URL=http://localhost:8000
```

Vite inlines `VITE_*` at build time, so Docker takes it as a build arg instead.

## Scan Concurrency

An audit scans every missed snippet, and each scan is an independent subprocess
that spends nearly all its time blocked. Scans therefore run on a thread pool
sized by `HACKTRON_MAX_WORKERS`, with results returned in request order and a
failing scan isolated to its own snippet rather than aborting the batch.

`server/benchmarks/bench_scan.py` measures the effect. It stubs the scanner with
a fixed latency by default so the result is reproducible without the CLI
installed, isolating scheduling from scanner speed:

```
cd server
python benchmarks/bench_scan.py --snippets 10
```

At a simulated 0.8s per scan with 4 workers:

| Snippets | Sequential | Concurrent | Speedup |
| --- | --- | --- | --- |
| 5 | 4.02s | 1.61s | 2.50x |
| 10 | 8.04s | 2.42s | 3.32x |

Pass `--real` to benchmark against an actual configured Hacktron CLI.

## How It Works
1) Frontend calls `/generate` to get tasks from Claude.
2) Player marks snippets SAFE/VULNERABLE.
3) Frontend calls `/audit` with missed tasks.
4) Backend runs Hacktron on those snippets.
5) Claude summarizes the vulnerabilities + fixes.
6) ElevenLabs can generate voice summary.
7) Tutorial mode can reveal Claude-generated hints per snippet.
8) Report shows accuracy by vulnerability type.
9) Endless mode advances difficulty after perfect streaks.

## API Endpoints (Backend)

Full interactive documentation is generated from the Pydantic schemas at
http://localhost:8000/docs.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Liveness check |
| GET | `/health/elevenlabs` | Verifies the configured TTS credentials |
| POST | `/generate` | Generate snippets for a difficulty |
| POST | `/audit` | Scan snippets and summarise findings |
| POST | `/tts` | Render a summary to speech |
| POST | `/session` | Create a scored session |
| GET | `/session/{id}/tasks` | Fetch snippets without the answers |
| POST | `/session/{id}/submit` | Submit answers and get a score |
| POST | `/session/{id}/finish` | Finalise and build the audit report |
| GET | `/session/{id}/results` | Fetch the report, computing it if needed |

Snippets are served through a separate schema that omits `isVulnerable` and
`vulnerabilityType`, so the answers are never sent to the client.

## Troubleshooting
**/generate returns 503**
- Check Anthropic model name and API key.
- Ensure `.env` is loaded and uvicorn restarted.

**Hints are missing**
- Claude may not be returning `hints`; the UI falls back to static language tips.

**/tts returns 503**
- Check ElevenLabs API key.
- Verify `.env` is loaded (restart uvicorn).

**Hacktron errors on Windows**
- Use `HACKTRON_CMD=wsl` and give `HACKTRON_ARGS` the Linux-side binary path.
  Windows temp paths are converted with `wslpath` automatically.
- Test the CLI directly first:
  ```
  wsl $HOME/.local/bin/hacktron --help
  ```
- Leave `HACKTRON_CMD` unset to skip scanning entirely; the game still works.

**Audits feel slow**
- Raise `HACKTRON_MAX_WORKERS` (default 4) to scan more snippets concurrently,
  or lower `HACKTRON_TIMEOUT` (default 30s) to fail slow scans faster.

## License
MIT (see LICENSE)
