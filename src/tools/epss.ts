// EPSS — fetches exploit probability scores from the FIRST.org EPSS API

import type { EpssResult } from "../types/index.js";
import { fetchWithTimeout } from "../utils/http.js";
import { logger } from "../utils/logger.js";
import { getCveCache, setCveCache } from "../cache/cve.js";

const EPSS_BASE_URL = "https://api.first.org/data/v1/epss";

interface EpssEntry {
  cve: string;
  epss: string;
  percentile: string;
  date: string;
}

interface EpssApiResponse {
  status: string;
  total: number;
  data: EpssEntry[];
}

export async function fetchEpss(cveId: string): Promise<EpssResult> {
  const cached = getCveCache(cveId, "epss");
  if (cached) {
    logger.info("epss-agent", "Cache hit", { cveId });
    return cached;
  }

  const url = `${EPSS_BASE_URL}?cve=${encodeURIComponent(cveId)}`;
  const start = Date.now();

  try {
    const response = await fetchWithTimeout(url);

    if (!response.ok) {
      logger.warn("epss-agent", `EPSS returned ${response.status}`, { cveId });
      return { cve_id: cveId, epss_score: null, percentile: null, date: null };
    }

    const data = (await response.json()) as EpssApiResponse;

    if (!data.total || !data.data.length) {
      // Not all CVEs have EPSS scores — this is expected, not an error
      logger.info("epss-agent", "No EPSS score available", { cveId });
      return { cve_id: cveId, epss_score: null, percentile: null, date: null };
    }

    const entry = data.data[0]!;

    logger.info("epss-agent", "Fetched EPSS score", {
      cveId,
      ms: Date.now() - start,
    });

    const result: EpssResult = {
      cve_id: cveId,
      epss_score: parseFloat(entry.epss),
      percentile: parseFloat(entry.percentile),
      date: entry.date,
    };

    setCveCache(cveId, "epss", result);
    return result;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error("epss-agent", "Fetch failed", { cveId, message });

    const stale = getCveCache(cveId, "epss", true);
    if (stale) {
      logger.warn("epss-agent", "Serving stale cache", { cveId });
      return stale;
    }

    return { cve_id: cveId, epss_score: null, percentile: null, date: null };
  }
}
