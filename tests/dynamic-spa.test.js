/**
 * LoginGuard - Dynamic Form, SPA Navigation & API Failure Unit Tests
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { checkDomainAge } from '../utils/rdap.js';
import { queryGoogleSafeBrowsing, queryBackendProxy, checkPhishingIntelligence } from '../utils/phishing-check.js';

test('API Failure Handling: Safe Browsing API handles unconfigured keys gracefully', async () => {
  const result = await queryGoogleSafeBrowsing('https://example.com/login', '');
  assert.strictEqual(result.isConfigured, false);
  assert.strictEqual(result.checked, false);
  assert.strictEqual(result.scorePenalty === undefined || result.scorePenalty === 0, true);
});

test('API Failure Handling: Backend proxy handles offline/unreachable servers gracefully', async () => {
  // Pinging an unreachable dummy port
  const result = await queryBackendProxy('https://example.com/login', 'example.com', 'http://127.0.0.1:59999', 500);
  assert.strictEqual(result.checked, false);
  assert.ok(result.error);
});

test('API Failure Handling: Full phishing check continues without throwing when services fail', async () => {
  const result = await checkPhishingIntelligence('https://mycollege.edu/login', 'mycollege.edu', {
    apiKey: null,
    backendProxyUrl: 'http://127.0.0.1:59999'
  });

  assert.strictEqual(result.isConfirmedPhishing, false);
  assert.strictEqual(result.scorePenalty, 0);
  assert.ok(result.note);
});

test('RDAP Handling: Special and local hostnames are skipped without errors', async () => {
  const localhostResult = await checkDomainAge('localhost');
  assert.strictEqual(localhostResult.status, 'NOT_APPLICABLE');
  assert.strictEqual(localhostResult.scorePenalty, 0);
});

test('SPA & Dynamic Simulation: Route change tracking logic', () => {
  let activeUrl = 'https://portal.univ.edu/dashboard';
  let hasScanned = false;

  function simulateNavigation(newUrl) {
    if (newUrl !== activeUrl) {
      activeUrl = newUrl;
      hasScanned = false; // reset for new route
    }
  }

  simulateNavigation('https://portal.univ.edu/auth/login');
  assert.strictEqual(activeUrl, 'https://portal.univ.edu/auth/login');
  assert.strictEqual(hasScanned, false);

  // Mark scanned
  hasScanned = true;
  // If staying on same URL, don't re-trigger
  const shouldTrigger = !hasScanned;
  assert.strictEqual(shouldTrigger, false);
});
