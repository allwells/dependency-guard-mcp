// Query log — permanent record of all CVE lookups

import type { Database } from 'bun:sqlite';
import { db as defaultDb } from './db.js';

export function logQuery(cveId: string, cacheHit: boolean, dbOverride?: Database | null): void {
  const db = dbOverride !== undefined ? dbOverride : defaultDb;
  if (!db) return;

  try {
    db.query(
      'INSERT INTO query_log (cve_id, queried_at, cache_hit) VALUES (?, ?, ?)',
    ).run(cveId, Date.now(), cacheHit ? 1 : 0);
  } catch {
    // log failures are silent
  }
}
