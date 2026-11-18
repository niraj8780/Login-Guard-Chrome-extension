/**
 * LoginGuard - Risk Scoring & Verdict Generation Unit Tests
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { calculateRiskScore, VERDICTS } from '../utils/scoring.js';

test('Scoring: Completely clean HTTPS domain yields SAFE verdict (Score 0)', () => {
  const result = calculateRiskScore({
    isHttp: false,
    isConfirmedPhishing: false,
    isLookalike: false,
    isBrandImpersonation: false,
    isRawIP: false,
    isPunycode: false,
    rdapScorePenalty: 0,
    structuralScorePenalty: 0
  });

  assert.strictEqual(result.score, 0);
  assert.strictEqual(result.verdict, VERDICTS.SAFE);
  assert.ok(result.reasons.length > 0);
});

test('Scoring: Insecure HTTP login yields SUSPICIOUS (+30)', () => {
  const result = calculateRiskScore({
    isHttp: true,
    isConfirmedPhishing: false,
    isLookalike: false
  });

  assert.strictEqual(result.score, 30);
  assert.strictEqual(result.verdict, VERDICTS.SUSPICIOUS);
});

test('Scoring: Confirmed phishing match always yields DANGEROUS (+70)', () => {
  const result = calculateRiskScore({
    isConfirmedPhishing: true,
    phishingNote: 'Match found in Google Safe Browsing database',
    isHttp: false
  });

  assert.strictEqual(result.score, 70);
  assert.strictEqual(result.verdict, VERDICTS.DANGEROUS);
});

test('Scoring: Lookalike + HTTP yields DANGEROUS (+65)', () => {
  const result = calculateRiskScore({
    isHttp: true,              // +30
    isLookalike: true,         // +35
    lookalikeReason: 'Typosquatting Google'
  });

  assert.strictEqual(result.score, 65);
  assert.strictEqual(result.verdict, VERDICTS.DANGEROUS);
});

test('Scoring: Cumulative score is strictly bounded at 100', () => {
  const result = calculateRiskScore({
    isConfirmedPhishing: true,  // +70
    isHttp: true,               // +30
    isLookalike: true,          // +35
    isRawIP: true,              // +25
    isPunycode: true            // +15
  });

  assert.strictEqual(result.score, 100);
  assert.strictEqual(result.verdict, VERDICTS.DANGEROUS);
});

test('Scoring: Whitelisted domain suppresses heuristic warnings', () => {
  // Ordinary heuristics (e.g. lookalike or structure)
  const result = calculateRiskScore({
    isHttp: false,
    isLookalike: true,
    lookalikeReason: 'Resembles brand',
    isWhitelisted: true
  });

  assert.strictEqual(result.verdict, VERDICTS.SAFE);
  assert.strictEqual(result.score, 0);
  assert.strictEqual(result.whitelistSuppressed, true);
});

test('Scoring: Whitelist NEVER overrides confirmed phishing matches', () => {
  // Even if user whitelisted domain, a confirmed phishing threat MUST stay DANGEROUS!
  const result = calculateRiskScore({
    isConfirmedPhishing: true,
    phishingNote: 'Malicious threat match',
    isWhitelisted: true
  });

  assert.strictEqual(result.verdict, VERDICTS.DANGEROUS);
  assert.ok(result.score >= 70);
  assert.ok(result.reasons[0].includes('CRITICAL'));
});
