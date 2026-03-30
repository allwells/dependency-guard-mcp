import { describe, test, expect, mock, beforeEach, afterAll } from 'bun:test';

const mockFetch = mock();

const realHttp = await import('../src/utils/http.js');
const realKev = await import('../src/cache/kev.js');
mock.module('../src/utils/http.js', () => ({ fetchWithTimeout: mockFetch }));
mock.module('../src/cache/kev.js', () => ({ getKevCache: mock(() => null), setKevCache: mock() }));

afterAll(() => {
  mock.module('../src/utils/http.js', () => realHttp);
  mock.module('../src/cache/kev.js', () => realKev);
});

mock.module('../src/utils/logger.js', () => ({
  logger: { info: mock(), warn: mock(), error: mock() },
}));

const { fetchCisa, invalidateKevCache } = await import('../src/tools/cisa.js');

function makeKevResponse(cveIds: string[]) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      vulnerabilities: cveIds.map((id) => ({
        cveID: id,
        vendorProject: 'Apache',
        product: 'Log4j',
        dateAdded: '2021-12-10',
        dueDate: '2021-12-24',
        requiredAction: 'Apply updates per vendor instructions.',
      })),
    }),
  } as unknown as Response;
}

beforeEach(() => {
  mockFetch.mockReset();
  invalidateKevCache();
});

describe('fetchCisa', () => {
  test('returns in_kev: true for a CVE on the KEV list', async () => {
    mockFetch.mockResolvedValueOnce(makeKevResponse(['CVE-2021-44228']));

    const result = await fetchCisa('CVE-2021-44228');

    expect(result.in_kev).toBe(true);
    expect(result.cve_id).toBe('CVE-2021-44228');
    expect(result.date_added).toBe('2021-12-10');
    expect(result.vendor_project).toBe('Apache');
  });

  test('returns in_kev: false for a CVE not on the KEV list', async () => {
    mockFetch.mockResolvedValueOnce(makeKevResponse(['CVE-2021-44228']));

    const result = await fetchCisa('CVE-9999-99999');

    expect(result.in_kev).toBe(false);
    expect(result.date_added).toBeNull();
  });

  test('normalizes CVE ID to uppercase before lookup', async () => {
    mockFetch.mockResolvedValueOnce(makeKevResponse(['CVE-2021-44228']));

    const result = await fetchCisa('cve-2021-44228');

    expect(result.in_kev).toBe(true);
  });

  test('serves from in-memory cache on second call', async () => {
    mockFetch.mockResolvedValue(makeKevResponse(['CVE-2021-44228']));

    await fetchCisa('CVE-2021-44228');
    await fetchCisa('CVE-2021-44228');

    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  test('refetches after invalidateKevCache()', async () => {
    mockFetch.mockResolvedValue(makeKevResponse(['CVE-2021-44228']));

    await fetchCisa('CVE-2021-44228');
    invalidateKevCache();
    await fetchCisa('CVE-2021-44228');

    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  test('returns in_kev: false on fetch error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network error'));

    const result = await fetchCisa('CVE-2021-44228');

    expect(result.in_kev).toBe(false);
  });

  test('returns in_kev: false on non-200 response', async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 503 } as unknown as Response);

    const result = await fetchCisa('CVE-2021-44228');

    expect(result.in_kev).toBe(false);
  });
});
