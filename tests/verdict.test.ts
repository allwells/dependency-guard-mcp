import { describe, test, expect } from 'bun:test';
import { scoreVerdict } from '../src/tools/verdict.js';

describe('scoreVerdict', () => {
  test('EXPLOIT_ACTIVE when in_kev is true, regardless of scores', () => {
    expect(scoreVerdict(true, 0, 0)).toBe('EXPLOIT_ACTIVE');
    expect(scoreVerdict(true, 10.0, 0.99)).toBe('EXPLOIT_ACTIVE');
    expect(scoreVerdict(true, null, null)).toBe('EXPLOIT_ACTIVE');
  });

  test('HIGH_RISK when epss_score >= 0.7', () => {
    expect(scoreVerdict(false, null, 0.7)).toBe('HIGH_RISK');
    expect(scoreVerdict(false, null, 0.95)).toBe('HIGH_RISK');
  });

  test('HIGH_RISK when cvss_score >= 9.0', () => {
    expect(scoreVerdict(false, 9.0, null)).toBe('HIGH_RISK');
    expect(scoreVerdict(false, 10.0, null)).toBe('HIGH_RISK');
  });

  test('HIGH_RISK when both EPSS and CVSS are high', () => {
    expect(scoreVerdict(false, 9.8, 0.85)).toBe('HIGH_RISK');
  });

  test('ELEVATED_RISK when epss_score >= 0.4 and < 0.7', () => {
    expect(scoreVerdict(false, null, 0.4)).toBe('ELEVATED_RISK');
    expect(scoreVerdict(false, null, 0.65)).toBe('ELEVATED_RISK');
  });

  test('ELEVATED_RISK when cvss_score >= 7.0 and < 9.0', () => {
    expect(scoreVerdict(false, 7.0, null)).toBe('ELEVATED_RISK');
    expect(scoreVerdict(false, 8.9, null)).toBe('ELEVATED_RISK');
  });

  test('LOW_RISK when all signals are below thresholds', () => {
    expect(scoreVerdict(false, 3.0, 0.1)).toBe('LOW_RISK');
    expect(scoreVerdict(false, null, null)).toBe('LOW_RISK');
    expect(scoreVerdict(false, 0, 0)).toBe('LOW_RISK');
  });

  test('KEV takes priority over HIGH_RISK signals', () => {
    expect(scoreVerdict(true, 10.0, 0.99)).toBe('EXPLOIT_ACTIVE');
  });

  test('HIGH_RISK takes priority over ELEVATED_RISK', () => {
    // EPSS in HIGH_RISK range even though CVSS is in ELEVATED range
    expect(scoreVerdict(false, 8.0, 0.75)).toBe('HIGH_RISK');
  });

  test('ELEVATED_RISK takes priority over LOW_RISK', () => {
    // CVSS just at ELEVATED threshold, EPSS below
    expect(scoreVerdict(false, 7.0, 0.1)).toBe('ELEVATED_RISK');
  });

  test('boundary: epss 0.699 is ELEVATED not HIGH', () => {
    expect(scoreVerdict(false, null, 0.699)).toBe('ELEVATED_RISK');
  });

  test('boundary: cvss 8.99 is ELEVATED not HIGH', () => {
    expect(scoreVerdict(false, 8.99, null)).toBe('ELEVATED_RISK');
  });

  test('boundary: epss 0.399 is LOW not ELEVATED', () => {
    expect(scoreVerdict(false, null, 0.399)).toBe('LOW_RISK');
  });

  test('boundary: cvss 6.99 is LOW not ELEVATED', () => {
    expect(scoreVerdict(false, 6.99, null)).toBe('LOW_RISK');
  });
});
