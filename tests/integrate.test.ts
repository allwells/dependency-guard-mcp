import { describe, test, expect } from 'bun:test';
import { runVerdict } from '../src/tools/verdict.js';

// These tests hit live external APIs. They are intentionally not mocked.
// They validate the full fetch → parse → score pipeline end-to-end.

describe('runVerdict integration', () => {
  test('CVE-2021-44228 (Log4Shell) returns EXPLOIT_ACTIVE', async () => {
    const result = await runVerdict('CVE-2021-44228');

    expect(result.cve_id).toBe('CVE-2021-44228');
    expect(result.verdict).toBe('EXPLOIT_ACTIVE');
    expect(result.in_kev).toBe(true);
    expect(result.recommended_action).toContain('immediately');
    expect(result.sources.cisa).not.toBeNull();
    expect(result.sources.epss).not.toBeNull();
  }, 30_000);

  test('result shape is always complete and JSON-serializable', async () => {
    const result = await runVerdict('CVE-2021-44228');

    // Must never throw — output must be valid JSON
    expect(() => JSON.stringify(result)).not.toThrow();

    // Required fields always present
    expect(result.cve_id).toBeDefined();
    expect(result.verdict).toBeDefined();
    expect(result.confidence).toBeDefined();
    expect(result.recommended_action).toBeDefined();
    expect(result.sources).toBeDefined();
  }, 30_000);
});
