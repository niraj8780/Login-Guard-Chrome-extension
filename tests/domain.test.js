/**
 * LoginGuard - Domain Extraction & Structural Analysis Unit Tests
 */

import { test } from 'node:test';
import assert from 'node:assert';
import {
  parseDomainInfo,
  isIPv4,
  isIPv6,
  isRawIP,
  isPunycode,
  analyzeStructuralSuspicion
} from '../utils/domain-check.js';

test('Domain Extraction: Normal HTTPS login page', () => {
  const result = parseDomainInfo('https://portal.myuniversity.edu/auth/login');
  assert.strictEqual(result.isValid, true);
  assert.strictEqual(result.protocol, 'https:');
  assert.strictEqual(result.hostname, 'portal.myuniversity.edu');
  assert.strictEqual(result.registrableDomain, 'myuniversity.edu');
  assert.strictEqual(result.tld, 'edu');
  assert.strictEqual(result.subdomains, 'portal');
  assert.strictEqual(result.isIP, false);
  assert.strictEqual(result.isPunycode, false);
});

test('Domain Extraction: Insecure HTTP login page', () => {
  const result = parseDomainInfo('http://insecure-login.example.com/signin.php');
  assert.strictEqual(result.isValid, true);
  assert.strictEqual(result.protocol, 'http:');
  assert.strictEqual(result.hostname, 'insecure-login.example.com');
  assert.strictEqual(result.registrableDomain, 'example.com');
});

test('Domain Extraction: Multi-part TLD parsing (.co.uk, .edu.in)', () => {
  const ukResult = parseDomainInfo('https://login.student.oxford.ac.uk/login');
  assert.strictEqual(ukResult.registrableDomain, 'oxford.ac.uk');
  assert.strictEqual(ukResult.tld, 'ac.uk');

  const inResult = parseDomainInfo('https://portal.iitb.ac.in/stud-login');
  assert.strictEqual(inResult.registrableDomain, 'iitb.ac.in');
  assert.strictEqual(inResult.tld, 'ac.in');
});

test('IP Address Detection: Raw IPv4 and IPv6 hosts', () => {
  assert.strictEqual(isIPv4('192.168.1.1'), true);
  assert.strictEqual(isIPv4('10.0.0.254'), true);
  assert.strictEqual(isIPv4('999.1.1.1'), false);
  assert.strictEqual(isIPv4('example.com'), false);

  assert.strictEqual(isIPv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), true);
  assert.strictEqual(isIPv6('::1'), true);

  const ipv4Result = parseDomainInfo('http://192.168.1.100/admin/login');
  assert.strictEqual(ipv4Result.isIP, true);
  assert.strictEqual(ipv4Result.hostname, '192.168.1.100');
});

test('Punycode Detection: Internationalized homoglyphs', () => {
  assert.strictEqual(isPunycode('xn--pple-43d.com'), true);
  assert.strictEqual(isPunycode('apple.com'), false);

  const parsed = parseDomainInfo('https://xn--gogle-qqa.com/login');
  assert.strictEqual(parsed.isPunycode, true);
});

test('Structural Suspicion: Long domains, hyphens, excessive subdomains', () => {
  // Excessive hyphens
  const hyphenResult = parseDomainInfo('https://secure-login-account-update-verify.com/login');
  const hyphenAnalysis = analyzeStructuralSuspicion(hyphenResult);
  assert.ok(hyphenResult.hyphenCount >= 3);
  assert.ok(hyphenAnalysis.suspicionPoints > 0);

  // Excessive subdomains
  const subResult = parseDomainInfo('https://a.b.c.d.portal.example.com/login');
  const subAnalysis = analyzeStructuralSuspicion(subResult);
  assert.ok(subResult.subdomainCount >= 4);
  assert.ok(subAnalysis.suspicionPoints >= 10);

  // Raw IP usage penalty
  const ipResult = parseDomainInfo('http://192.168.1.1/login');
  const ipAnalysis = analyzeStructuralSuspicion(ipResult);
  assert.strictEqual(ipAnalysis.suspicionPoints, 25);
});
