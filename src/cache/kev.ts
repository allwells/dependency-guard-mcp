// KEV cache — full CISA KEV list snapshot, 6h TTL

import type { Database } from 'bun:sqlite';
import { db as defaultDb } from './db.js';

const TTL_MS = 6 * 60 * 60 * 1000;

interface KevRow {
  data: string;
  expires_at: number;
}

export interface KevSnapshot {
  vulnerabilities: Array<{
    cveID: string;
    vendorProject: string;
    product: string;
    dateAdded: string;
    dueDate: string;
    requiredAction: string;
  }>;
}

export function getKevCache(allowStale = false, dbOverride?: Database | null): KevSnapshot | null {
  const db = dbOverride !== undefined ? dbOverride : defaultDb;
  if (!db) return null;

  try {
    const row = db
      .query<KevRow, []>('SELECT data, expires_at FROM kev_cache WHERE id = 1')
      .get();

    if (!row) return null;

    const expired = Date.now() > row.expires_at;
    if (expired && !allowStale) return null;

    return JSON.parse(row.data) as KevSnapshot;
  } catch {
    return null;
  }
}

export function setKevCache(snapshot: KevSnapshot, dbOverride?: Database | null): void {
  const db = dbOverride !== undefined ? dbOverride : defaultDb;
  if (!db) return;

  try {
    db.query(
      `INSERT INTO kev_cache (id, data, expires_at)
       VALUES (1, ?, ?)
       ON CONFLICT (id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at`,
    ).run(JSON.stringify(snapshot), Date.now() + TTL_MS);
  } catch {
    // cache write failures are silent
  }
}
