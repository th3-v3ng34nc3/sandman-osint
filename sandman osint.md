# ◈ sandman osint

A fast, self-contained OSINT tool written in Go. Enter a person, username, or company — it fans out to 7 sources concurrently, checks 60+ social platforms, and streams results in real time to a web dashboard.

```
  ███████╗ █████╗ ███╗   ██╗██████╗ ███╗   ███╗ █████╗ ███╗   ██╗
  ██╔════╝██╔══██╗████╗  ██║██╔══██╗████╗ ████║██╔══██╗████╗  ██║
  ███████╗███████║██╔██╗ ██║██║  ██║██╔████╔██║███████║██╔██╗ ██║
  ╚════██║██╔══██║██║╚██╗██║██║  ██║██║╚██╔╝██║██╔══██║██║╚██╗██║
  ███████║██║  ██║██║ ╚████║██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

---

## Features

- **Permutation engine** — generates 50+ username, email, and domain variants from a single input
- **60+ platform username checker** — GitHub, Reddit, Twitter, LinkedIn, Steam, Keybase, and more — checked in parallel
- **Real-time dashboard** — findings stream in via SSE as they are discovered
- **AI analysis** — Claude summarises all findings, assigns a 0–100 risk score, and identifies cross-source connections
- **Tor support** — optionally routes requests through Tor and searches `.onion` indexes (Ahmia)
- **JSON export** — one-click download of the full structured result
- **Page recovery** — URL hash preserves the query ID; reloading reconnects to cached results
- **Graceful degradation** — sources without API keys are skipped cleanly; the tool always runs

---

## Sources

| Source | Target Types | Requires Key |
|---|---|---|
| [HaveIBeenPwned](https://haveibeenpwned.com) | Person | Yes |
| [GitHub](https://github.com) | Person, Username, Company | No (token increases rate limit) |
| [Shodan](https://shodan.io) | Person, Company | Yes |
| [Hunter.io](https://hunter.io) | Person, Company | Yes |
| DuckDuckGo (scraper) | All | No |
| Username checker (60+ platforms) | All | No |
| Tor / Ahmia `.onion` | All | No (requires Tor running) |
| Claude AI analysis | — | Yes (post-search) |

All keys are optional. Sources without a configured key are skipped and shown as `skipped` in the dashboard.

---

## Quick Start

### Requirements

- [Go 1.22+](https://go.dev/dl/)
- (Optional) [Tor](https://www.torproject.org/) for `.onion` routing

### Run

```bash
git clone <repo>
cd sandman-osint

cp .env.example .env
# edit .env and add your API keys

go run .
# open http://localhost:8080
```

### Build a binary

```bash
go build -o sandman .
./sandman
```

### Linux / cross-compile from Windows

```bash
# Run natively on Linux
go run .

# Cross-compile from Windows → Linux
GOOS=linux GOARCH=amd64 go build -o sandman-linux .
```

---

## Configuration

Copy `.env.example` to `.env` and fill in the keys you have. All are optional.

| Variable | Description |
|---|---|
| `SANDMAN_HIBP_KEY` | HaveIBeenPwned v3 API key |
| `SANDMAN_HUNTER_KEY` | Hunter.io API key |
| `SANDMAN_SHODAN_KEY` | Shodan API key |
| `SANDMAN_GITHUB_TOKEN` | GitHub personal access token (increases rate limit) |
| `SANDMAN_CLAUDE_KEY` | Anthropic API key (enables AI analysis) |
| `SANDMAN_CLAUDE_MODEL` | Claude model (default: `claude-opus-4-6`) |
| `SANDMAN_TOR` | Set to `1` to enable Tor routing |
| `SANDMAN_TOR_ADDR` | Tor SOCKS5 address (default: `127.0.0.1:9050`) |
| `PORT` | Server listen port (default: `8080`) |

Variables can also be set directly in the environment — they take precedence over `.env`.

### CLI flags

```
--addr       listen address (e.g. :9090)
--tor        enable Tor proxy
--tor-addr   Tor SOCKS5 address (default 127.0.0.1:9050)
```

---

## Usage

1. Open `http://localhost:8080`
2. Enter a **person name**, **username/handle**, or **company name**
3. Select the target type
4. (Optional) toggle **Route via Tor**
5. Click **SEARCH**

Results stream in real time. Each source shows its status (`running` → `done`/`error`/`skipped`) and finding count. Click any finding card to expand its raw data. When the search completes, click **Export JSON** to download the full structured report.

### Filters

Use the **Severity** and **Type** dropdowns to filter the findings list:

- **Severity**: Critical · High · Medium · Low · Info
- **Type**: Breach · Profile · Social · Email · Network · Search · Dark Web

---

## Permutation Engine

Given a raw input, Sandman generates variants before querying sources:

| Input | Example variants generated |
|---|---|
| `John Doe` | `johndoe`, `john.doe`, `j.doe`, `jdoe`, `john.doe@gmail.com`, … |
| `j0hn_d03` | `j0hnd03`, `j0hn-d03`, `john_doe` (leet decode), … |
| `Acme Corp` | `acmecorp`, `acme-corp`, `acme.com`, `acme.io`, `@acmecorp.com`, … |

Up to 60 variants are generated per search. Each source filters the list to only the shapes it can use (e.g. HIBP only uses email-shaped variants, Shodan only uses domain-shaped ones).

---

## Architecture

```
sandman-osint/
├── main.go
├── internal/
│   ├── config/        load API keys from env
│   ├── query/         TargetType, SearchStatus types
│   ├── result/        Finding, SourceMeta, AIAnalysis types
│   ├── permutation/   variant generation for all target types
│   ├── sse/           non-blocking SSE broker (goroutine-safe)
│   ├── engine/        concurrent fan-out orchestrator + in-memory store
│   ├── sources/       one file per source + shared HTTP client builder
│   └── ai/            Claude API integration
└── web/
    ├── server.go      HTTP handlers (POST /api/search, GET /api/stream, ...)
    └── static/        dashboard UI (embedded in binary at build time)
```

The web UI and all static assets are embedded into the binary at build time — no separate files need to be deployed.

### API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/search` | Submit a search; returns `{ query_id }` |
| `GET` | `/api/stream?id=<id>` | SSE stream of live events |
| `GET` | `/api/status?id=<id>` | Current search status (for page-reload recovery) |
| `GET` | `/api/export?id=<id>` | Download full result as indented JSON |

### SSE events

| Event | Payload | When |
|---|---|---|
| `source_update` | `SourceMeta` | Each time a source changes state |
| `finding` | `Finding` | Each finding as it arrives |
| `ai_analysis` | `AIAnalysis` | After all sources complete (if Claude key set) |
| `done` | `{ query_id, total_findings }` | Search fully complete |
| `error` | `{ message }` | Fatal engine error |

---

## Legal & Ethics

This tool is intended for **authorised** security research, penetration testing engagements, journalism, and personal OSINT investigations where you have a legitimate interest in the target information.

- Do not use against individuals without authorisation
- Respect rate limits and terms of service of queried platforms
- Dark web features are provided for defensive research only
- The authors are not responsible for misuse

---

## License

MIT
