import { describe, test, expect, mock, beforeEach, afterAll } from 'bun:test';

const mockFetch = mock();

const realHttp = await import('../src/utils/http.js');
const realCve = await import('../src/cache/cve.js');
mock.module('../src/utils/http.js', () => ({ fetchWithTimeout: mockFetch }));
mock.module('../src/cache/cve.js', () => ({ getCveCache: mock(() => null), setCveCache: mock() }));

afterAll(() => {
  mock.module('../src/utils/http.js', () => realHttp);
  mock.module('../src/cache/cve.js', () => realCve);
});

mock.module('../src/utils/logger.js', () => ({
  logger: { info: mock(), warn: mock(), error: mock() },
}));

const { fetchEpss } = await import('../src/tools/epss.js');

function makeEpssResponse(cveId: string, epss: string, percentile: string) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      status: 'OK',
      total: 1,
      data: [{ cve: cveId, epss, percentile, date: '2026-03-30' }],
    }),
  } as unknown as Response;
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe('fetchEpss', () => {
  test('parses epss_score and percentile as floats', async () => {
    mockFetch.mockResolvedValueOnce(makeEpssResponse('CVE-2021-44228', '0.97531', '1.00000'));

    const result = await fetchEpss('CVE-2021-44228');

    expect(result.cve_id).toBe('CVE-2021-44228');
    expect(result.epss_score).toBeCloseTo(0.97531);
    expect(result.percentile).toBeCloseTo(1.0);
    expect(result.date).toBe('2026-03-30');
  });

  test('returns null fields when CVE has no EPSS score (total: 0)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ status: 'OK', total: 0, data: [] }),
    } as unknown as Response);

    const result = await fetchEpss('CVE-9999-99999');

    expect(result.epss_score).toBeNull();
    expect(result.percentile).toBeNull();
    expect(result.date).toBeNull();
  });

  test('returns null fields on non-200 response', async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 400 } as unknown as Response);

    const result = await fetchEpss('CVE-2021-44228');

    expect(result.epss_score).toBeNull();
  });

  test('returns null fields on fetch error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('timeout'));

    const result = await fetchEpss('CVE-2021-44228');

    expect(result.epss_score).toBeNull();
  });
});
