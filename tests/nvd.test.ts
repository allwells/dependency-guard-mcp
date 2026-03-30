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

const { fetchNvd } = await import('../src/tools/nvd.js');

function makeResponse(ok: boolean, body: unknown): Response {
  return {
    ok,
    status: ok ? 200 : 404,
    json: async () => body,
  } as unknown as Response;
}

function makeNvdBody(score: number, severity: string, version: 'v31' | 'v30' | 'v2' = 'v31') {
  const metricKey =
    version === 'v31' ? 'cvssMetricV31' : version === 'v30' ? 'cvssMetricV30' : 'cvssMetricV2';
  return {
    totalResults: 1,
    vulnerabilities: [
      {
        cve: {
          id: 'CVE-2021-44228',
          published: '2021-12-10T00:00:00.000',
          lastModified: '2022-01-01T00:00:00.000',
          descriptions: [{ lang: 'en', value: 'Log4Shell RCE vulnerability' }],
          metrics: {
            [metricKey]: [{ cvssData: { baseScore: score, baseSeverity: severity } }],
          },
        },
      },
    ],
  };
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe('fetchNvd', () => {
  test('parses CVSS v3.1 score and description', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse(true, makeNvdBody(10.0, 'CRITICAL', 'v31')));

    const result = await fetchNvd('CVE-2021-44228');

    expect(result.cve_id).toBe('CVE-2021-44228');
    expect(result.cvss_score).toBe(10.0);
    expect(result.cvss_severity).toBe('CRITICAL');
    expect(result.description).toBe('Log4Shell RCE vulnerability');
    expect(result.published).toBe('2021-12-10T00:00:00.000');
  });

  test('falls back to CVSS v3.0 when v3.1 absent', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse(true, makeNvdBody(9.8, 'CRITICAL', 'v30')));

    const result = await fetchNvd('CVE-2021-44228');

    expect(result.cvss_score).toBe(9.8);
  });

  test('falls back to CVSS v2 when v3 absent', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse(true, makeNvdBody(9.3, 'HIGH', 'v2')));

    const result = await fetchNvd('CVE-2021-44228');

    expect(result.cvss_score).toBe(9.3);
  });

  test('returns null fields on non-200 response', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse(false, {}));

    const result = await fetchNvd('CVE-2021-44228');

    expect(result.cvss_score).toBeNull();
    expect(result.description).toBeNull();
  });

  test('returns null fields when CVE not found (totalResults: 0)', async () => {
    mockFetch.mockResolvedValueOnce(
      makeResponse(true, { totalResults: 0, vulnerabilities: [] }),
    );

    const result = await fetchNvd('CVE-9999-99999');

    expect(result.cvss_score).toBeNull();
  });

  test('returns null fields on fetch error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network timeout'));

    const result = await fetchNvd('CVE-2021-44228');

    expect(result.cvss_score).toBeNull();
    expect(result.description).toBeNull();
  });
});
