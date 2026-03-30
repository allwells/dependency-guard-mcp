// CVE cache — NVD and EPSS results per CVE ID, 24h TTL

import type { NvdResult, EpssResult } from '../types/index.js';
import type { Database } from 'bun:sqlite';
import { db as defaultDb } from './db.js';

const TTL_MS = 24 * 60 * 60 * 1000;

type CveSource = 'nvd' | 'epss';

interface CacheRow {
  data: string;
  expires_at: number;
}

export function getCveCache(cveId: string, source: 'nvd', allowStale?: boolean, dbOverride?: Database | null): NvdResult | null;
export function getCveCache(cveId: string, source: 'epss', allowStale?: boolean, dbOverride?: Database | null): EpssResult | null;
export function getCveCache(
  cveId: string,
  source: CveSource,
  allowStale = false,
  dbOverride?: Database | null,
): NvdResult | EpssResult | null {
  const db = dbOverride !== undefined ? dbOverride : defaultDb;
  if (!db) return null;

  try {
    const row = db
      .query<CacheRow, [string, string]>(
        'SELECT data, expires_at FROM cve_cache WHERE cve_id = ? AND source = ?',
      )
      .get(cveId, source);

    if (!row) return null;

    const expired = Date.now() > row.expires_at;
    if (expired && !allowStale) return null;

    return JSON.parse(row.data) as NvdResult | EpssResult;
  } catch {
    return null;
  }
}

export function setCveCache(cveId: string, source: 'nvd', data: NvdResult, dbOverride?: Database | null): void;
export function setCveCache(cveId: string, source: 'epss', data: EpssResult, dbOverride?: Database | null): void;
export function setCveCache(cveId: string, source: CveSource, data: NvdResult | EpssResult, dbOverride?: Database | null): void {
  const db = dbOverride !== undefined ? dbOverride : defaultDb;
  if (!db) return;

  try {
    db.query(
      `INSERT INTO cve_cache (cve_id, source, data, expires_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (cve_id, source) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at`,
    ).run(cveId, source, JSON.stringify(data), Date.now() + TTL_MS);
  } catch {
    // cache write failures are silent
  }
}
