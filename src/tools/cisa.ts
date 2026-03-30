// CISA — fetches and parses the CISA Known Exploited Vulnerabilities (KEV) catalog

import type { CisaResult } from "../types/index.js";
import { fetchWithTimeout } from "../utils/http.js";
import { logger } from "../utils/logger.js";
import { getKevCache, setKevCache, type KevSnapshot } from "../cache/kev.js";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
}

// Layer 1: in-memory Map — avoids re-parsing on every request
let kevCache: Map<string, KevEntry> | null = null;
let kevCachedAt: number | null = null;
const KEV_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

function buildIndex(vulnerabilities: KevSnapshot["vulnerabilities"]): Map<string, KevEntry> {
  const index = new Map<string, KevEntry>();
  for (const entry of vulnerabilities) {
    index.set(entry.cveID.toUpperCase(), entry);
  }
  return index;
}

async function getKevIndex(): Promise<Map<string, KevEntry>> {
  const now = Date.now();

  // Layer 1: in-memory hit
  if (kevCache && kevCachedAt && now - kevCachedAt < KEV_TTL_MS) {
    return kevCache;
  }

  // Layer 2: SQLite hit
  const snapshot = getKevCache();
  if (snapshot) {
    logger.info("cisa-agent", "KEV loaded from SQLite cache", {
      count: snapshot.vulnerabilities.length,
    });
    kevCache = buildIndex(snapshot.vulnerabilities);
    kevCachedAt = now;
    return kevCache;
  }

  // Layer 3: fetch from upstream
  const start = Date.now();
  let fetchedSnapshot: KevSnapshot;

  try {
    const response = await fetchWithTimeout(KEV_URL);

    if (!response.ok) {
      throw new Error(`CISA KEV fetch returned ${response.status}`);
    }

    fetchedSnapshot = (await response.json()) as KevSnapshot;
  } catch (err) {
    // Stale fallback: serve expired SQLite data when upstream is unreachable
    const stale = getKevCache(true);
    if (stale) {
      logger.warn("cisa-agent", "Serving stale KEV cache", {
        count: stale.vulnerabilities.length,
      });
      kevCache = buildIndex(stale.vulnerabilities);
      kevCachedAt = now;
      return kevCache;
    }
    throw err;
  }

  setKevCache(fetchedSnapshot);

  kevCache = buildIndex(fetchedSnapshot.vulnerabilities);
  kevCachedAt = now;

  logger.info("cisa-agent", "KEV list refreshed", {
    count: kevCache.size,
    ms: Date.now() - start,
  });

  return kevCache;
}

export async function fetchCisa(cveId: string): Promise<CisaResult> {
  try {
    const index = await getKevIndex();
    const entry = index.get(cveId.toUpperCase());

    if (!entry) {
      return {
        cve_id: cveId,
        in_kev: false,
        date_added: null,
        due_date: null,
        vendor_project: null,
        product: null,
        required_action: null,
      };
    }

    return {
      cve_id: cveId,
      in_kev: true,
      date_added: entry.dateAdded,
      due_date: entry.dueDate,
      vendor_project: entry.vendorProject,
      product: entry.product,
      required_action: entry.requiredAction,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error("cisa-agent", "Fetch failed", { cveId, message });
    return {
      cve_id: cveId,
      in_kev: false,
      date_added: null,
      due_date: null,
      vendor_project: null,
      product: null,
      required_action: null,
    };
  }
}

/** Force-invalidates the in-memory KEV cache. Used by /refresh-data. */
export function invalidateKevCache(): void {
  kevCache = null;
  kevCachedAt = null;
}
