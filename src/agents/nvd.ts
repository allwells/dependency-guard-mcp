// NVD Agent — fetches CVE data from the NIST National Vulnerability Database API v2.0

import type { NvdResult } from '../types/index.js';
import { fetchWithTimeout } from '../utils/http.js';
import { logger } from '../utils/logger.js';

const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// NVD rate-limits unauthenticated requests to 5 per 30s.
// Set NVD_API_KEY env var to increase to 50 per 30s (free key from nvd.nist.gov).
function buildUrl(cveId: string): string {
  const params = new URLSearchParams({ cveId });
  const apiKey = process.env['NVD_API_KEY'];
  if (apiKey) params.set('apiKey', apiKey);
  return `${NVD_BASE_URL}?${params.toString()}`;
}

interface NvdCvssMetric {
  cvssData: {
    baseScore: number;
    baseSeverity: string;
  };
}

interface NvdApiResponse {
  totalResults: number;
  vulnerabilities?: Array<{
    cve: {
      id: string;
      published: string;
      lastModified: string;
      descriptions: Array<{ lang: string; value: string }>;
      metrics?: {
        cvssMetricV31?: NvdCvssMetric[];
        cvssMetricV30?: NvdCvssMetric[];
        cvssMetricV2?: NvdCvssMetric[];
      };
    };
  }>;
}

type NvdMetrics = {
  cvssMetricV31?: NvdCvssMetric[];
  cvssMetricV30?: NvdCvssMetric[];
  cvssMetricV2?: NvdCvssMetric[];
};

function extractCvss(metrics: NvdMetrics | undefined): {
  score: number | null;
  severity: string | null;
} {
  if (!metrics) return { score: null, severity: null };

  // Prefer v3.1, fall back to v3.0, then v2
  const metric =
    metrics.cvssMetricV31?.[0] ??
    metrics.cvssMetricV30?.[0] ??
    metrics.cvssMetricV2?.[0] ??
    null;

  if (!metric) return { score: null, severity: null };

  return {
    score: metric.cvssData.baseScore,
    severity: metric.cvssData.baseSeverity,
  };
}

function extractDescription(
  descriptions: Array<{ lang: string; value: string }>,
): string | null {
  return descriptions.find((d) => d.lang === 'en')?.value ?? null;
}

export async function fetchNvd(cveId: string): Promise<NvdResult> {
  const url = buildUrl(cveId);
  const start = Date.now();

  try {
    const response = await fetchWithTimeout(url);

    if (!response.ok) {
      logger.warn('nvd-agent', `NVD returned ${response.status}`, { cveId });
      return { cve_id: cveId, cvss_score: null, cvss_severity: null, description: null, published: null, last_modified: null };
    }

    const data = (await response.json()) as NvdApiResponse;

    if (!data.totalResults || !data.vulnerabilities?.length) {
      logger.warn('nvd-agent', 'CVE not found in NVD', { cveId });
      return { cve_id: cveId, cvss_score: null, cvss_severity: null, description: null, published: null, last_modified: null };
    }

    const cve = data.vulnerabilities[0]!.cve;
    const { score, severity } = extractCvss(cve.metrics);

    logger.info('nvd-agent', 'Fetched NVD data', { cveId, ms: Date.now() - start });

    return {
      cve_id: cveId,
      cvss_score: score,
      cvss_severity: severity,
      description: extractDescription(cve.descriptions),
      published: cve.published,
      last_modified: cve.lastModified,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error('nvd-agent', 'Fetch failed', { cveId, message });
    return { cve_id: cveId, cvss_score: null, cvss_severity: null, description: null, published: null, last_modified: null };
  }
}
