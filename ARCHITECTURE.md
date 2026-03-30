# DependencyGuard MCP — Architecture

---

## Overview

DependencyGuard MCP is a single-tool MCP server. It exposes one tool — `check_cve` — that accepts a CVE ID, fetches data from three authoritative security databases in parallel, scores the result against a fixed threshold table, and returns a structured JSON verdict.

The system has no user-facing UI. All callers are AI agents communicating over the MCP stdio transport.

---

## Request Lifecycle

```
AI Agent
  │
  │  MCP stdio (check_cve { cve_id })
  ▼
src/mcp.ts
  │  Validates CVE ID format (regex)
  │  Normalizes to uppercase
  ▼
src/tools/verdict.ts — runVerdict()
  │
  ├── src/tools/nvd.ts  ─────── cache → NVD API
  ├── src/tools/cisa.ts ─────── memory → SQLite → CISA KEV URL
  └── src/tools/epss.ts ─────── cache → EPSS API
        (Promise.all — all three fetched in parallel)
  │
  │  scoreVerdict(in_kev, cvss_score, epss_score)
  │  scoreConfidence(nvd, cisa, epss)
  ▼
VerdictResult { cve_id, verdict, confidence, ... }
  │
  │  JSON.stringify → MCP text content
  ▼
AI Agent
```

The total budget for the full round-trip is under 60 seconds (CTX Protocol platform requirement). In practice most requests complete in under 5 seconds — NVD and EPSS fetches are the dominant latency, and both are cached.

---

## Data Agents

### NVD (`src/tools/nvd.ts`)

**Endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`

**Rate limits:**
- Unauthenticated: 5 requests / 30 seconds
- With `NVD_API_KEY`: 50 requests / 30 seconds

**CVSS version priority:** v3.1 → v3.0 → v2. The first available metric is used.

**Output shape (`NvdResult`):**

```ts
{
  cve_id: string;
  cvss_score: number | null;      // null if CVE not found or no CVSS metric
  cvss_severity: string | null;   // "CRITICAL", "HIGH", etc.
  description: string | null;     // English description from NVD
  published: string | null;       // ISO 8601
  last_modified: string | null;
}
```

**Error handling:**
- Non-2xx response → returns null-score result (not a throw)
- CVE not in NVD (`totalResults: 0`) → returns null-score result
- Network failure / timeout → attempts stale cache; falls back to null-score result
- Cache TTL: 24 hours

---

### CISA KEV (`src/tools/cisa.ts`)

**Endpoint:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

The CISA KEV list is a single large JSON file containing all known exploited vulnerabilities. It is downloaded in full and indexed by CVE ID.

**Two-layer cache:**
1. **In-memory `Map<string, KevEntry>`** — built once per process, avoids re-parsing SQLite on every request. TTL: 6 hours from last load.
2. **SQLite `kev_cache` table** — persists the full snapshot across restarts.

**Lookup flow:**
1. Memory hit → return immediately
2. SQLite hit → hydrate memory cache, return
3. Neither → fetch from CISA, write to SQLite, hydrate memory
4. Fetch failure → attempt stale SQLite data; if none, throw

**Output shape (`CisaResult`):**

```ts
{
  cve_id: string;
  in_kev: boolean;
  date_added: string | null;       // "YYYY-MM-DD"
  due_date: string | null;
  vendor_project: string | null;
  product: string | null;
  required_action: string | null;
}
```

**Error handling:**
- Any error during lookup → returns `{ in_kev: false, ...nulls }` (never throws from `fetchCisa`)
- Stale fallback is served silently when upstream is unreachable

---

### EPSS (`src/tools/epss.ts`)

**Endpoint:** `https://api.first.org/data/v1/epss?cve=<id>`

EPSS scores are a 30-day forward-looking probability of exploitation (0.0–1.0). Not all CVEs have EPSS scores — this is expected for very recent or very obscure CVEs.

**Output shape (`EpssResult`):**

```ts
{
  cve_id: string;
  epss_score: number | null;   // 0.0–1.0; null if no score available
  percentile: number | null;   // relative ranking among all CVEs
  date: string | null;         // score calculation date
}
```

**Error handling:**
- No score in response (`total: 0`) → returns null-score result (info log, not a warning)
- Non-2xx or network error → attempts stale cache; falls back to null-score result
- Cache TTL: 24 hours

---

## Verdict Agent (`src/tools/verdict.ts`)

### Scoring logic

```
if in_kev                              → EXPLOIT_ACTIVE
else if epss ≥ 0.70 OR cvss ≥ 9.0    → HIGH_RISK
else if epss ≥ 0.40 OR cvss ≥ 7.0    → ELEVATED_RISK
else                                   → LOW_RISK
```

CISA KEV membership is the highest-priority signal and overrides all score-based signals. A CVE with CVSS 2.0 that is on the KEV list is still `EXPLOIT_ACTIVE`.

### Threshold rationale

| Threshold | Value | Rationale |
|-----------|-------|-----------|
| `HIGH_RISK_EPSS` | 0.70 | Top ~1% of all CVEs by exploit probability |
| `HIGH_RISK_CVSS` | 9.0 | Near-maximum CVSS — typically unauthenticated RCE |
| `ELEVATED_RISK_EPSS` | 0.40 | Meaningful exploitation probability — above baseline noise |
| `ELEVATED_RISK_CVSS` | 7.0 | Standard "High" CVSS boundary |

### Confidence scoring

`full` — all three sources returned meaningful data (NVD with a CVSS score, CISA lookup succeeded, EPSS with a score).

`partial` — one or more sources returned no data. This covers: CVE too new to have scores, CVE not in NVD, EPSS score not yet calculated, or an API failure that fell through to a null-score result.

Note: `in_kev: false` from CISA _is_ meaningful — it counts as an available source. Only null CVSS or EPSS scores indicate a missing source.

### Edge cases

- **All sources null** — verdict is `LOW_RISK` with `confidence: partial`. This is the safest default when no data is available.
- **KEV + low CVSS** — `EXPLOIT_ACTIVE` wins. CVSS measures theoretical severity; KEV measures confirmed exploitation.
- **EPSS null, CVSS ≥ 9.0** — scores as `HIGH_RISK`. Single-source data is sufficient for escalation.

---

## MCP Interface (`src/mcp.ts`)

**Transport:** stdio (`StdioServerTransport`)

The MCP server communicates exclusively over stdin/stdout. All logging uses stderr to avoid corrupting the MCP stream.

**Tool registration:**

```ts
server.registerTool('check_cve', {
  title: 'Check CVE Risk',
  description: '...',
  inputSchema: {
    cve_id: z.string().regex(/^CVE-\d{4}-\d{4,}$/i)
  }
}, handler)
```

**Input validation:** The CVE ID is validated against `^CVE-\d{4}-\d{4,}$` (case-insensitive) before reaching the verdict layer. The normalized uppercase form is used throughout.

**Response shape:** Always a single MCP text content block containing `JSON.stringify(VerdictResult)`. The output is always valid JSON — never plain text, never an error string.

**Startup sequence:**
1. `src/index.ts` calls `startServer()` and `startMcp()` concurrently
2. `startServer()` — Express binds on `PORT`, `/health` is immediately available
3. `startMcp()` — SQLite is initialized (via `src/cache/db.ts` module-level side effect), MCP server connects to stdio transport

---

## Caching Strategy

### Why cache?

- NVD rate-limits unauthenticated requests to 5/30s
- CISA KEV is a large file (~1MB+) that changes infrequently
- CTX Protocol requires <60s response time and 95%+ uptime — stale fallback is a platform requirement, not a nice-to-have

### Layers

#### Layer 1 — In-memory Map (CISA KEV only)

`src/tools/cisa.ts` maintains a module-level `Map<string, KevEntry>` that is populated on first request and reused for 6 hours. Avoids deserializing the KEV list from SQLite on every request.

Invalidated by: TTL expiry, or explicit call to `invalidateKevCache()` (used by `/refresh-data`).

#### Layer 2 — SQLite (`src/cache/db.ts`)

Three tables:

| Table | Contents | TTL |
|-------|----------|-----|
| `cve_cache` | NVD and EPSS results per CVE (keyed by `cve_id + source`) | 24 hours |
| `kev_cache` | Full CISA KEV snapshot (single row, `id = 1`) | 6 hours |
| `query_log` | Every CVE lookup with cache hit/miss flag | Permanent |

SQLite runs in **WAL mode** for better concurrent read performance.

**Graceful degradation:** If SQLite init fails (e.g. no write permission at `DB_PATH`), `db` is set to `null`. All cache functions check for null and return early — the server runs without caching, fetching live data on every request.

### Stale fallback

When an upstream API fetch fails:
1. `getCveCache(cveId, source, true)` — `allowStale = true` — returns the most recent cached result regardless of TTL
2. If no stale data exists, the agent returns a null-score result

This ensures the server can still return a verdict (possibly `LOW_RISK` with `partial` confidence) even when all three APIs are unreachable — satisfying the 95%+ uptime requirement.

### Cache writes

Cache writes are fire-and-forget: failures are caught and swallowed silently. A failed cache write never blocks a response.

---

## Utility Layer

### `src/utils/http.ts` — `fetchWithTimeout`

All HTTP requests use `fetchWithTimeout`, which wraps `fetch` with an `AbortController` timeout (default 20 seconds). This prevents any single slow upstream API from blocking the entire request past the 60-second platform deadline.

### `src/utils/logger.ts` — structured JSON logger

All log output is written to **stderr** as newline-delimited JSON:

```json
{"timestamp":"2024-01-01T00:00:00.000Z","level":"info","source":"nvd-agent","message":"Cache hit","context":{"cveId":"CVE-2021-44228"}}
```

stdout is reserved exclusively for MCP protocol messages. Writing anything to stdout outside of the MCP SDK would corrupt the transport.

Log levels: `info`, `warn`, `error`.

---

## Conclusions

### What works well

**Parallel fetching** — `Promise.all` across NVD, CISA, and EPSS means the end-to-end latency is bounded by the slowest single source, not their sum. In practice this keeps most responses under 2 seconds.

**Two-layer CISA cache** — The in-memory Map eliminates the SQLite round-trip for the most frequent operation (KEV membership check). The SQLite layer provides persistence across restarts without a separate cache service.

**Stale fallback** — The `allowStale` pattern in both `getCveCache` and `getKevCache` means the server degrades gracefully under network partition rather than returning errors. This directly satisfies the 95%+ uptime contract.

**Verdict simplicity** — The scoring function is a pure function of three inputs with no external dependencies. It is trivially testable and the thresholds are easy to adjust in one place (`THRESHOLDS` constant in `verdict.ts`).

### Trade-offs accepted

**No authentication on the HTTP server** — The `/health` endpoint is public. This is intentional: it exists only for uptime monitoring and contains no sensitive data.

**SQLite over Redis** — A single-process SQLite cache is sufficient for this workload. The tool is stateless from the caller's perspective and doesn't need distributed cache invalidation.

**CISA KEV as a bulk download** — The CISA API doesn't support per-CVE queries; the full list must be fetched. The 6-hour TTL and in-memory index make this practical without significant overhead.

**Confidence is binary** — `full` vs `partial` is intentionally simple. Finer-grained confidence (e.g. distinguishing "NVD unavailable" from "CVE not found") would add complexity without changing the recommended action for an AI agent caller.

**No retry logic** — Upstream APIs are treated as fail-fast. The stale cache fallback handles the transient failure case more reliably than retries, without adding latency to the hot path.
