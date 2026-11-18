/**
 * LoginGuard - Lookalike & Typosquatting Detection Unit Tests
 */

import { test } from 'node:test';
import assert from 'node:assert';
import {
  levenshteinDistance,
  normalizeSubstitutions,
  detectLookalike
} from '../utils/lookalike-detection.js';

test('Levenshtein Distance: Basic edit calculations', () => {
  assert.strictEqual(levenshteinDistance('google', 'google'), 0);
  assert.strictEqual(levenshteinDistance('google', 'gogle'), 1);
  assert.strictEqual(levenshteinDistance('paypal', 'paypa1'), 1);
  assert.strictEqual(levenshteinDistance('apple', 'aple'), 1);
  assert.strictEqual(levenshteinDistance('microsoft', 'microsft'), 1);
});

test('Character Substitution Normalization: Leetspeak & homoglyphs', () => {
  assert.strictEqual(normalizeSubstitutions('g00gle'), 'google');
  assert.strictEqual(normalizeSubstitutions('paypa1'), 'paypal');
  assert.strictEqual(normalizeSubstitutions('micros0ft'), 'microsoft');
  assert.strictEqual(normalizeSubstitutions('app1e'), 'apple');
});

test('Lookalike Detection: Legitimate brand domains are passed', () => {
  const googleCheck = detectLookalike('google.com', 'accounts.google.com');
  assert.strictEqual(googleCheck.isLegitimateBrand, true);
  assert.strictEqual(googleCheck.isLookalike, false);
  assert.strictEqual(googleCheck.scorePenalty, 0);

  const paypalCheck = detectLookalike('paypal.com', 'www.paypal.com');
  assert.strictEqual(paypalCheck.isLegitimateBrand, true);
  assert.strictEqual(paypalCheck.isLookalike, false);
});

test('Lookalike Detection: Impersonated domains flag with high penalty', () => {
  // Character substitution: g00gle.com
  const g00gle = detectLookalike('g00gle.com', 'g00gle.com');
  assert.strictEqual(g00gle.isLookalike, true);
  assert.strictEqual(g00gle.matchedBrand, 'Google');
  assert.strictEqual(g00gle.scorePenalty, 35);

  // Character substitution: paypa1.com
  const paypa1 = detectLookalike('paypa1.com', 'paypa1.com');
  assert.strictEqual(paypa1.isLookalike, true);
  assert.strictEqual(paypa1.matchedBrand, 'PayPal');
  assert.strictEqual(paypa1.scorePenalty, 35);

  // Levenshtein typo: goog1e-login.com
  const goog1eLogin = detectLookalike('goog1e-login.com', 'goog1e-login.com');
  assert.strictEqual(goog1eLogin.isLookalike, true);
  assert.ok(goog1eLogin.scorePenalty >= 30);

  // Brand keyword combination: paypal-security.com
  const paypalSec = detectLookalike('paypal-security.com', 'paypal-security.com');
  assert.strictEqual(paypalSec.isLookalike, true);
  assert.strictEqual(paypalSec.matchedBrand, 'PayPal');
  assert.ok(paypalSec.scorePenalty >= 30);
});

test('Lookalike Detection: Independent unbranded domains pass without false positives', () => {
  const universityCheck = detectLookalike('stanford.edu', 'portal.stanford.edu');
  assert.strictEqual(universityCheck.isLookalike, false);
  assert.strictEqual(universityCheck.scorePenalty, 0);

  const blogCheck = detectLookalike('techblog.org', 'techblog.org');
  assert.strictEqual(blogCheck.isLookalike, false);
  assert.strictEqual(blogCheck.scorePenalty, 0);
});
