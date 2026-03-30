// CISA Agent — fetches and parses the CISA Known Exploited Vulnerabilities (KEV) catalog

import type { CisaResult } from '../types/index.js';
import { fetchWithTimeout } from '../utils/http.js';
import { logger } from '../utils/logger.js';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
}

interface KevResponse {
  vulnerabilities: KevEntry[];
}

// In-memory cache — KEV list is ~1,200 entries and fits comfortably in memory.
// Avoids re-fetching the full list on every query.
let kevCache: Map<string, KevEntry> | null = null;
let kevCachedAt: number | null = null;
const KEV_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

async function getKevIndex(): Promise<Map<string, KevEntry>> {
  const now = Date.now();

  if (kevCache && kevCachedAt && now - kevCachedAt < KEV_TTL_MS) {
    return kevCache;
  }

  const start = Date.now();
  const response = await fetchWithTimeout(KEV_URL);

  if (!response.ok) {
    throw new Error(`CISA KEV fetch returned ${response.status}`);
  }

  const data = (await response.json()) as KevResponse;

  const index = new Map<string, KevEntry>();
  for (const entry of data.vulnerabilities) {
    index.set(entry.cveID.toUpperCase(), entry);
  }

  kevCache = index;
  kevCachedAt = now;

  logger.info('cisa-agent', 'KEV list refreshed', {
    count: index.size,
    ms: Date.now() - start,
  });

  return index;
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
    logger.error('cisa-agent', 'Fetch failed', { cveId, message });
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
