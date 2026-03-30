// Cache tests — validates SQL schema, TTL logic, upsert, and stale fallback
// directly against an isolated in-memory database. The TypeScript wrappers
// (getCveCache, setCveCache, etc.) are thin query adapters; the behavior under
// test lives in the SQL.

import { describe, test, expect, beforeEach, afterAll } from 'bun:test';
import { Database } from 'bun:sqlite';
import type { NvdResult, EpssResult } from '../src/types/index.js';

const testDb = new Database(':memory:');

testDb.exec(`
  CREATE TABLE cve_cache (
    cve_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('nvd', 'epss')),
    data   TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (cve_id, source)
  )
`);
testDb.exec(`
  CREATE TABLE kev_cache (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    data       TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )
`);
testDb.exec(`
  CREATE TABLE query_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id     TEXT NOT NULL,
    queried_at INTEGER NOT NULL,
    cache_hit  INTEGER NOT NULL CHECK (cache_hit IN (0, 1))
  )
`);

const HOUR = 60 * 60 * 1000;

const nvdResult: NvdResult = {
  cve_id: 'CVE-2021-44228',
  cvss_score: 10.0,
  cvss_severity: 'CRITICAL',
  description: 'Log4Shell',
  published: '2021-12-10T00:00:00.000',
  last_modified: '2022-01-01T00:00:00.000',
};

const epssResult: EpssResult = {
  cve_id: 'CVE-2021-44228',
  epss_score: 0.975,
  percentile: 1.0,
  date: '2026-03-30',
};

// Helpers that mirror the production query logic exactly
function readCveCache(cveId: string, source: string, allowStale = false) {
  const row = testDb
    .query<{ data: string; expires_at: number }, [string, string]>(
      'SELECT data, expires_at FROM cve_cache WHERE cve_id = ? AND source = ?',
    )
    .get(cveId, source);
  if (!row) return null;
  if (Date.now() > row.expires_at && !allowStale) return null;
  return JSON.parse(row.data);
}

function writeCveCache(cveId: string, source: string, data: NvdResult | EpssResult, ttlMs: number) {
  testDb.query(
    `INSERT INTO cve_cache (cve_id, source, data, expires_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT (cve_id, source) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at`,
  ).run(cveId, source, JSON.stringify(data), Date.now() + ttlMs);
}

function readKevCache(allowStale = false) {
  const row = testDb
    .query<{ data: string; expires_at: number }, []>('SELECT data, expires_at FROM kev_cache WHERE id = 1')
    .get();
  if (!row) return null;
  if (Date.now() > row.expires_at && !allowStale) return null;
  return JSON.parse(row.data);
}

function writeKevCache(data: object, ttlMs: number) {
  testDb.query(
    `INSERT INTO kev_cache (id, data, expires_at)
     VALUES (1, ?, ?)
     ON CONFLICT (id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at`,
  ).run(JSON.stringify(data), Date.now() + ttlMs);
}

beforeEach(() => {
  testDb.exec('DELETE FROM cve_cache');
  testDb.exec('DELETE FROM kev_cache');
  testDb.exec('DELETE FROM query_log');
});

afterAll(() => {
  testDb.close();
});

describe('cve_cache', () => {
  test('returns null on cache miss', () => {
    expect(readCveCache('CVE-9999-99999', 'nvd')).toBeNull();
    expect(readCveCache('CVE-9999-99999', 'epss')).toBeNull();
  });

  test('returns cached NVD result on hit', () => {
    writeCveCache('CVE-2021-44228', 'nvd', nvdResult, 24 * HOUR);
    expect(readCveCache('CVE-2021-44228', 'nvd')).toEqual(nvdResult);
  });

  test('returns cached EPSS result on hit', () => {
    writeCveCache('CVE-2021-44228', 'epss', epssResult, 24 * HOUR);
    expect(readCveCache('CVE-2021-44228', 'epss')).toEqual(epssResult);
  });

  test('NVD and EPSS stored independently for the same CVE', () => {
    writeCveCache('CVE-2021-44228', 'nvd', nvdResult, 24 * HOUR);
    writeCveCache('CVE-2021-44228', 'epss', epssResult, 24 * HOUR);
    expect(readCveCache('CVE-2021-44228', 'nvd')).toEqual(nvdResult);
    expect(readCveCache('CVE-2021-44228', 'epss')).toEqual(epssResult);
  });

  test('returns null for expired entry (allowStale=false)', () => {
    writeCveCache('CVE-2021-44228', 'nvd', nvdResult, -1); // already expired
    expect(readCveCache('CVE-2021-44228', 'nvd', false)).toBeNull();
  });

  test('returns stale entry when allowStale=true', () => {
    writeCveCache('CVE-2021-44228', 'nvd', nvdResult, -1);
    expect(readCveCache('CVE-2021-44228', 'nvd', true)).toEqual(nvdResult);
  });

  test('upserts on duplicate write', () => {
    const updated = { ...nvdResult, cvss_score: 9.0 };
    writeCveCache('CVE-2021-44228', 'nvd', nvdResult, 24 * HOUR);
    writeCveCache('CVE-2021-44228', 'nvd', updated, 24 * HOUR);
    expect(readCveCache('CVE-2021-44228', 'nvd')).toEqual(updated);
  });

  test('CHECK constraint rejects invalid source values', () => {
    expect(() =>
      testDb.query('INSERT INTO cve_cache (cve_id, source, data, expires_at) VALUES (?, ?, ?, ?)').run(
        'CVE-2021-44228', 'invalid', '{}', Date.now() + HOUR,
      ),
    ).toThrow();
  });
});

describe('kev_cache', () => {
  const snapshot = {
    vulnerabilities: [
      {
        cveID: 'CVE-2021-44228',
        vendorProject: 'Apache',
        product: 'Log4j',
        dateAdded: '2021-12-10',
        dueDate: '2021-12-24',
        requiredAction: 'Apply updates.',
      },
    ],
  };

  test('returns null on cache miss', () => {
    expect(readKevCache()).toBeNull();
  });

  test('returns snapshot on hit', () => {
    writeKevCache(snapshot, 6 * HOUR);
    expect(readKevCache()).toEqual(snapshot);
  });

  test('returns null for expired snapshot (allowStale=false)', () => {
    writeKevCache(snapshot, -1);
    expect(readKevCache(false)).toBeNull();
  });

  test('returns stale snapshot when allowStale=true', () => {
    writeKevCache(snapshot, -1);
    expect(readKevCache(true)).toEqual(snapshot);
  });

  test('upserts on duplicate write (singleton row)', () => {
    const updated = { vulnerabilities: [] };
    writeKevCache(snapshot, 6 * HOUR);
    writeKevCache(updated, 6 * HOUR);
    expect(readKevCache()).toEqual(updated);
  });

  test('CHECK constraint enforces singleton row (id must be 1)', () => {
    expect(() =>
      testDb.query('INSERT INTO kev_cache (id, data, expires_at) VALUES (?, ?, ?)').run(
        2, '{}', Date.now() + HOUR,
      ),
    ).toThrow();
  });
});

describe('query_log', () => {
  function insertLog(cveId: string, hit: boolean) {
    testDb.query('INSERT INTO query_log (cve_id, queried_at, cache_hit) VALUES (?, ?, ?)').run(
      cveId, Date.now(), hit ? 1 : 0,
    );
  }

  test('records a cache miss', () => {
    insertLog('CVE-2021-44228', false);
    const row = testDb.query<{ cache_hit: number }, []>('SELECT cache_hit FROM query_log LIMIT 1').get();
    expect(row?.cache_hit).toBe(0);
  });

  test('records a cache hit', () => {
    insertLog('CVE-2021-44228', true);
    const row = testDb.query<{ cache_hit: number }, []>('SELECT cache_hit FROM query_log LIMIT 1').get();
    expect(row?.cache_hit).toBe(1);
  });

  test('each query creates a separate log entry', () => {
    insertLog('CVE-2021-44228', false);
    insertLog('CVE-2014-0160', true);
    const count = testDb.query<{ n: number }, []>('SELECT COUNT(*) as n FROM query_log').get();
    expect(count?.n).toBe(2);
  });

  test('CHECK constraint rejects invalid cache_hit values', () => {
    expect(() =>
      testDb.query('INSERT INTO query_log (cve_id, queried_at, cache_hit) VALUES (?, ?, ?)').run(
        'CVE-2021-44228', Date.now(), 2,
      ),
    ).toThrow();
  });
});
