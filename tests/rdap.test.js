/**
 * LoginGuard - RDAP & Threat Intelligence Unit Tests
 */

import { test } from 'node:test';
import assert from 'node:assert';
import {
  extractRegistrationDate,
  calculateDomainAgeInDays
} from '../utils/rdap.js';
import {
  checkLocalThreatSignatures
} from '../utils/phishing-check.js';

test('RDAP Parsing: Extracts registration date correctly from RDAP event arrays', () => {
  const mockRdap = {
    events: [
      { eventAction: 'last changed', eventDate: '2024-05-10T12:00:00Z' },
      { eventAction: 'registration', eventDate: '2020-01-15T00:00:00Z' },
      { eventAction: 'expiration', eventDate: '2027-01-15T00:00:00Z' }
    ]
  };

  const regDate = extractRegistrationDate(mockRdap);
  assert.ok(regDate instanceof Date);
  assert.strictEqual(regDate.toISOString(), '2020-01-15T00:00:00.000Z');
});

test('RDAP Domain Age: Calculates days from creation date', () => {
  const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
  const age = calculateDomainAgeInDays(threeDaysAgo);
  assert.strictEqual(age, 3);

  const invalidDate = new Date('invalid');
  assert.strictEqual(calculateDomainAgeInDays(invalidDate), null);
});

test('RDAP Fallback: Missing or malformed events do not crash or produce false penalties', () => {
  assert.strictEqual(extractRegistrationDate(null), null);
  assert.strictEqual(extractRegistrationDate({}), null);
  assert.strictEqual(extractRegistrationDate({ events: [] }), null);
});

test('Phishing Threat Signatures: Detects known blocklisted test signatures', () => {
  const testMatch = checkLocalThreatSignatures('https://testsafebrowsing.appspot.com/s/phishing.html', 'testsafebrowsing.appspot.com');
  assert.strictEqual(testMatch.matched, true);
  assert.strictEqual(testMatch.scorePenalty, 70);

  const cleanMatch = checkLocalThreatSignatures('https://mit.edu/login', 'mit.edu');
  assert.strictEqual(cleanMatch.matched, false);
});
