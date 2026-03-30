# DependencyGuard MCP

An MCP tool that returns a single risk verdict for any CVE by combining three authoritative data sources:

| Source         | What it provides                                                    |
| -------------- | ------------------------------------------------------------------- |
| **NIST NVD**   | CVSS severity score                                                 |
| **CISA KEV**   | Known Exploited Vulnerabilities — confirmed real-world exploitation |
| **FIRST EPSS** | 30-day exploit probability score                                    |

The only target user is AI agents. This is not a developer-facing product.

Listed on the [CTX Protocol](https://ctxprotocol.com) marketplace — a decentralized marketplace where AI agents autonomously discover and purchase data tools. Payments are in USDC on the Base blockchain.

---

## Tool Schema

### `check_cve`

Returns a prioritized risk verdict for a CVE.

**Input**

| Field    | Type     | Description                           |
| -------- | -------- | ------------------------------------- |
| `cve_id` | `string` | CVE identifier, e.g. `CVE-2021-44228` |

**Output**

```json
{
  "cve_id": "CVE-2021-44228",
  "verdict": "EXPLOIT_ACTIVE",
  "confidence": "full",
  "cvss_score": 10.0,
  "epss_score": 0.975,
  "in_kev": true,
  "description": "Apache Log4j2 JNDI features...",
  "recommended_action": "Patch immediately — this CVE is actively exploited in the wild.",
  "sources": {
    "nvd": { "cve_id": "...", "cvss_score": 10.0, "cvss_severity": "CRITICAL", ... },
    "cisa": { "cve_id": "...", "in_kev": true, "date_added": "2021-12-10", ... },
    "epss": { "cve_id": "...", "epss_score": 0.975, "percentile": 0.999, ... }
  }
}
```

**Verdicts**

| Verdict          | Meaning                                          | Action                |
| ---------------- | ------------------------------------------------ | --------------------- |
| `EXPLOIT_ACTIVE` | On CISA KEV list — confirmed active exploitation | Patch immediately     |
| `HIGH_RISK`      | EPSS ≥ 0.70 or CVSS ≥ 9.0                        | Patch within 24 hours |
| `ELEVATED_RISK`  | EPSS ≥ 0.40 or CVSS ≥ 7.0                        | Address this week     |
| `LOW_RISK`       | No active exploitation signals                   | Monitor               |

**Confidence**

| Value     | Meaning                                                                 |
| --------- | ----------------------------------------------------------------------- |
| `full`    | All three data sources returned scores                                  |
| `partial` | One or more sources returned no data (CVE not found or API unavailable) |

---

## Running the Server

### Prerequisites

- [Bun](https://bun.sh) v1.x or Node.js ≥ 20
- (Optional) Free NVD API key from [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)

### Install

```bash
bun install
```

### Development

```bash
bun run dev
```

### Production

```bash
bun run build
bun start
```

The server starts two listeners:

- **MCP stdio transport** — handles `check_cve` tool calls over stdin/stdout
- **HTTP server** on `PORT` (default `8000`) — exposes `/health`

### Health check

```
GET /health
→ { "status": "OK", "service": "DependencyGuard MCP", "version": "1.0.0" }
```

---

## Environment Variables

| Variable      | Default      | Description                                                                                                                |
| ------------- | ------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `PORT`        | `8000`       | HTTP server port                                                                                                           |
| `DB_PATH`     | `./cache.db` | SQLite cache file path. Set to `:memory:` for tests.                                                                       |
| `NVD_API_KEY` | —            | NVD API key. Increases rate limit from 5 to 50 req/30s. Without a key the server works but may hit rate limits under load. |

---

## Tests

```bash
bun test
```

Tests run against an in-memory SQLite database (`DB_PATH=:memory:`). Test files live in `tests/`.

---

## Project Layout

```
src/
  index.ts          — entry point: starts MCP + HTTP
  mcp.ts            — MCP server, registers check_cve tool
  server.ts         — Express HTTP server, /health endpoint
  tools/
    nvd.ts          — NIST NVD fetcher
    cisa.ts         — CISA KEV fetcher
    epss.ts         — FIRST EPSS fetcher
    verdict.ts      — scoring logic, runVerdict orchestrator
  cache/
    db.ts           — SQLite init (WAL mode, graceful degradation)
    cve.ts          — NVD/EPSS per-CVE cache (24h TTL)
    kev.ts          — KEV list snapshot cache (6h TTL)
    log.ts          — query log (permanent)
  types/
    index.ts        — shared TypeScript interfaces
  utils/
    http.ts         — fetchWithTimeout
    logger.ts       — structured JSON logger (stderr)
tests/              — Bun test suites
```
