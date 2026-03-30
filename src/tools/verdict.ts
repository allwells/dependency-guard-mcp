// Verdict — combines NVD, CISA KEV, and EPSS signals into a single risk verdict

import type {
  NvdResult,
  CisaResult,
  EpssResult,
  Verdict,
  Confidence,
  VerdictResult,
} from "../types/index.js";
import { fetchNvd } from "./nvd.js";
import { fetchCisa } from "./cisa.js";
import { fetchEpss } from "./epss.js";
import { logger } from "../utils/logger.js";
import { getCveCache } from "../cache/cve.js";
import { logQuery } from "../cache/log.js";

const THRESHOLDS = {
  HIGH_RISK_EPSS: 0.7,
  HIGH_RISK_CVSS: 9.0,
  ELEVATED_RISK_EPSS: 0.4,
  ELEVATED_RISK_CVSS: 7.0,
} as const;

const RECOMMENDED_ACTIONS: Record<Verdict, string> = {
  EXPLOIT_ACTIVE:
    "Patch immediately — this CVE is actively exploited in the wild.",
  HIGH_RISK: "Patch within 24 hours.",
  ELEVATED_RISK: "Address this week.",
  LOW_RISK: "Monitor — no active exploitation signals.",
};

export function scoreVerdict(
  in_kev: boolean,
  cvss_score: number | null,
  epss_score: number | null,
): Verdict {
  if (in_kev) return "EXPLOIT_ACTIVE";

  if (
    (epss_score !== null && epss_score >= THRESHOLDS.HIGH_RISK_EPSS) ||
    (cvss_score !== null && cvss_score >= THRESHOLDS.HIGH_RISK_CVSS)
  ) {
    return "HIGH_RISK";
  }

  if (
    (epss_score !== null && epss_score >= THRESHOLDS.ELEVATED_RISK_EPSS) ||
    (cvss_score !== null && cvss_score >= THRESHOLDS.ELEVATED_RISK_CVSS)
  ) {
    return "ELEVATED_RISK";
  }

  return "LOW_RISK";
}

function scoreConfidence(
  nvd: NvdResult | null,
  cisa: CisaResult | null,
  epss: EpssResult | null,
): Confidence {
  // A source is "available" only if it returned meaningful data, not just an
  // empty-field object. NVD and EPSS return result objects with null scores on
  // 404/not-found — those don't count as available.
  const nvdAvailable = nvd !== null && nvd.cvss_score !== null;
  const cisaAvailable = cisa !== null; // in_kev: false is still meaningful
  const epssAvailable = epss !== null && epss.epss_score !== null;

  const sourcesAvailable = [nvdAvailable, cisaAvailable, epssAvailable].filter(
    Boolean,
  ).length;
  if (sourcesAvailable === 3) return "full";
  return "partial";
}

export async function runVerdict(cveId: string): Promise<VerdictResult> {
  const start = Date.now();

  const cacheHit =
    !!(getCveCache(cveId, "nvd") ?? getCveCache(cveId, "epss"));
  logQuery(cveId, cacheHit);

  // Fetch all three sources in parallel
  const [nvd, cisa, epss] = await Promise.all([
    fetchNvd(cveId).catch(() => null),
    fetchCisa(cveId).catch(() => null),
    fetchEpss(cveId).catch(() => null),
  ]);

  const in_kev = cisa?.in_kev ?? false;
  const cvss_score = nvd?.cvss_score ?? null;
  const epss_score = epss?.epss_score ?? null;
  const description = nvd?.description ?? null;

  const verdict = scoreVerdict(in_kev, cvss_score, epss_score);
  const confidence = scoreConfidence(nvd, cisa, epss);

  logger.info("verdict-agent", "Verdict computed", {
    cveId,
    verdict,
    confidence,
    ms: Date.now() - start,
  });

  return {
    cve_id: cveId,
    verdict,
    confidence,
    cvss_score,
    epss_score,
    in_kev,
    description,
    recommended_action: RECOMMENDED_ACTIONS[verdict],
    sources: { nvd, cisa, epss },
  };
}
