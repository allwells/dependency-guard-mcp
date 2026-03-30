// Cache database — SQLite via bun:sqlite, WAL mode, graceful degradation

import { Database } from 'bun:sqlite';
import { logger } from '../utils/logger.js';

const DB_PATH = process.env['DB_PATH'] ?? './cache.db';

const CREATE_CVE_CACHE = `
  CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('nvd', 'epss')),
    data   TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (cve_id, source)
  )
`;

const CREATE_KEV_CACHE = `
  CREATE TABLE IF NOT EXISTS kev_cache (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    data       TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )
`;

const CREATE_QUERY_LOG = `
  CREATE TABLE IF NOT EXISTS query_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id     TEXT NOT NULL,
    queried_at INTEGER NOT NULL,
    cache_hit  INTEGER NOT NULL CHECK (cache_hit IN (0, 1))
  )
`;

let db: Database | null = null;

try {
  db = new Database(DB_PATH, { create: true });
  db.exec('PRAGMA journal_mode = WAL');
  db.exec(CREATE_CVE_CACHE);
  db.exec(CREATE_KEV_CACHE);
  db.exec(CREATE_QUERY_LOG);
  logger.info('cache', 'SQLite cache initialized', { path: DB_PATH });
} catch (err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  logger.warn('cache', 'SQLite init failed — cache disabled', { message });
  db = null;
}

export { db };
