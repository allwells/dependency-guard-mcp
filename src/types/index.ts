// Shared types for all data agents and the verdict layer

export interface NvdResult {
  cve_id: string;
  cvss_score: number | null;
  cvss_severity: string | null;
  description: string | null;
  published: string | null;
  last_modified: string | null;
}

export interface CisaResult {
  cve_id: string;
  in_kev: boolean;
  date_added: string | null;
  due_date: string | null;
  vendor_project: string | null;
  product: string | null;
  required_action: string | null;
}

export interface EpssResult {
  cve_id: string;
  epss_score: number | null;
  percentile: number | null;
  date: string | null;
}

export type Verdict =
  | "EXPLOIT_ACTIVE"
  | "HIGH_RISK"
  | "ELEVATED_RISK"
  | "LOW_RISK";
export type Confidence = "full" | "partial" | "stale";

export interface VerdictResult {
  cve_id: string;
  verdict: Verdict;
  confidence: Confidence;
  cvss_score: number | null;
  epss_score: number | null;
  in_kev: boolean;
  description: string | null;
  recommended_action: string;
  sources: {
    nvd: NvdResult | null;
    cisa: CisaResult | null;
    epss: EpssResult | null;
  };
}
