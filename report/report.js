/**
 * LoginGuard - Detailed Security Audit Report Controller
 */

import { getHistory, isDomainWhitelisted } from '../utils/storage.js';

document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetDomain = urlParams.get('domain');

  const reportDomainEl = document.getElementById('report-domain');
  const reportUrlEl = document.getElementById('report-url');
  const reportVerdictBadgeEl = document.getElementById('report-verdict-badge');
  const reportScoreEl = document.getElementById('report-score');
  const reportRiskBarEl = document.getElementById('report-risk-bar');
  const summaryReasonsListEl = document.getElementById('summary-reasons-list');
  const reportTimestampEl = document.getElementById('report-timestamp');

  // Check cards & badges
  const badgeHttps = document.getElementById('badge-https');
  const descHttps = document.getElementById('desc-https');

  const badgeLookalike = document.getElementById('badge-lookalike');
  const descLookalike = document.getElementById('desc-lookalike');

  const badgeStructure = document.getElementById('badge-structure');
  const descStructure = document.getElementById('desc-structure');

  const badgeRdap = document.getElementById('badge-rdap');
  const descRdap = document.getElementById('desc-rdap');

  const badgeThreat = document.getElementById('badge-threat');
  const descThreat = document.getElementById('desc-threat');

  const badgeWhitelist = document.getElementById('badge-whitelist');
  const descWhitelist = document.getElementById('desc-whitelist');

  const adviceBox = document.getElementById('advice-box');
  const adviceTitle = document.getElementById('advice-title');
  const adviceBody = document.getElementById('advice-body');

  const btnPrint = document.getElementById('btn-print');

  if (btnPrint) {
    btnPrint.addEventListener('click', () => window.print());
  }

  // Load history records to find the match
  const history = await getHistory();
  let matchedRecord = null;

  if (targetDomain) {
    matchedRecord = history.find(item =>
      (item.hostname && item.hostname.toLowerCase() === targetDomain.toLowerCase()) ||
      (item.registrableDomain && item.registrableDomain.toLowerCase() === targetDomain.toLowerCase())
    );
  }

  // If no specific match, use the most recent scan record
  if (!matchedRecord && history.length > 0) {
    matchedRecord = history[0];
  }

  if (!matchedRecord) {
    reportDomainEl.textContent = targetDomain || 'No Scan Records Found';
    reportUrlEl.textContent = 'Visit a login page or perform a manual scan from the toolbar popup.';
    reportVerdictBadgeEl.textContent = 'NO DATA';
    reportVerdictBadgeEl.className = 'verdict-tag tag-SAFE';
    summaryReasonsListEl.innerHTML = '<li>No security audits recorded yet.</li>';
    return;
  }

  renderReport(matchedRecord);

  async function renderReport(data) {
    const hostname = data.hostname || 'Unknown Domain';
    const url = data.url || `https://${hostname}`;
    const verdict = data.verdict || 'SAFE';
    const score = typeof data.score === 'number' ? data.score : 0;

    reportDomainEl.textContent = hostname;
    reportUrlEl.textContent = url;
    reportScoreEl.textContent = score;

    reportVerdictBadgeEl.textContent = verdict;
    reportVerdictBadgeEl.className = `verdict-tag tag-${verdict}`;

    reportRiskBarEl.style.width = `${score}%`;
    if (verdict === 'SAFE') {
      reportRiskBarEl.style.backgroundColor = '#10b981';
    } else if (verdict === 'SUSPICIOUS') {
      reportRiskBarEl.style.backgroundColor = '#f59e0b';
    } else {
      reportRiskBarEl.style.backgroundColor = '#ef4444';
    }

    reportTimestampEl.textContent = data.timestamp
      ? new Date(data.timestamp).toLocaleString()
      : new Date().toLocaleString();

    // Summary Reasons
    summaryReasonsListEl.innerHTML = '';
    const reasons = Array.isArray(data.reasons) && data.reasons.length > 0
      ? data.reasons
      : ['No negative security traits detected. Website heuristics passed normal criteria.'];

    reasons.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;
      summaryReasonsListEl.appendChild(li);
    });

    // 1. HTTPS Check
    if (data.isHttp) {
      setBadge(badgeHttps, 'FAILED', 'badge-failed');
      descHttps.textContent = 'CRITICAL: Connection is unencrypted HTTP. Login passwords and credentials can be intercepted by anyone on the network.';
    } else {
      setBadge(badgeHttps, 'PASSED', 'badge-passed');
      descHttps.textContent = 'Connection uses HTTPS encryption. Chrome validates certificate authenticity and transport cipher suites.';
    }

    // 2. Lookalike Check
    const lookalike = data.lookalike;
    if (lookalike && lookalike.isLookalike) {
      setBadge(badgeLookalike, 'FAILED', 'badge-failed');
      descLookalike.textContent = lookalike.reason || `Domain resembles protected brand "${lookalike.matchedBrand}".`;
    } else if (lookalike && lookalike.isBrandImpersonation) {
      setBadge(badgeLookalike, 'WARNING', 'badge-warning');
      descLookalike.textContent = `Potential brand impersonation identified for "${lookalike.matchedBrand}".`;
    } else {
      setBadge(badgeLookalike, 'PASSED', 'badge-passed');
      descLookalike.textContent = 'No lookalike typosquatting or brand impersonation patterns detected against protected brand registries.';
    }

    // 3. Structure Check
    if (data.isIP) {
      setBadge(badgeStructure, 'WARNING', 'badge-warning');
      descStructure.textContent = 'Login page is served directly from a numeric IP address, bypassing standard domain name verification.';
    } else if (data.isPunycode) {
      setBadge(badgeStructure, 'WARNING', 'badge-warning');
      descStructure.textContent = 'Punycode (IDN) detected. Can be used for homoglyph spoofing attacks using foreign characters.';
    } else if (data.hyphenCount >= 3 || data.subdomainCount >= 3) {
      setBadge(badgeStructure, 'WARNING', 'badge-warning');
      descStructure.textContent = `Structural anomalies: ${data.hyphenCount} hyphens, ${data.subdomainCount} subdomain levels.`;
    } else {
      setBadge(badgeStructure, 'PASSED', 'badge-passed');
      descStructure.textContent = 'Domain structure adheres to standard naming standards with normal subdomain depth and length.';
    }

    // 4. RDAP Check
    const rdap = data.rdap;
    if (rdap && rdap.status === 'SUCCESS') {
      if (rdap.ageInDays < 30) {
        setBadge(badgeRdap, 'FAILED', 'badge-failed');
        descRdap.textContent = `Very newly registered domain (${rdap.ageInDays} days old). High statistical correlation with phishing campaigns.`;
      } else if (rdap.ageInDays < 90) {
        setBadge(badgeRdap, 'WARNING', 'badge-warning');
        descRdap.textContent = `Recently registered domain (${rdap.ageInDays} days old).`;
      } else {
        setBadge(badgeRdap, 'PASSED', 'badge-passed');
        descRdap.textContent = `Established domain registration (Age: ${rdap.ageInDays} days).`;
      }
    } else if (rdap && rdap.status === 'NOT_FOUND') {
      setBadge(badgeRdap, 'NOT AVAILABLE', 'badge-na');
      descRdap.textContent = 'RDAP record not found. Note: Missing registration data does not imply the site is malicious.';
    } else {
      setBadge(badgeRdap, 'NOT AVAILABLE', 'badge-na');
      descRdap.textContent = 'RDAP registration service query was skipped or unavailable for this TLD/host.';
    }

    // 5. Threat Intelligence Check
    const threat = data.threatIntel;
    if (threat && threat.isConfirmedPhishing) {
      setBadge(badgeThreat, 'FAILED', 'badge-failed');
      descThreat.textContent = `CONFIRMED THREAT: Flagged on active threat intelligence database (${threat.source || 'Phishing Feeds'}).`;
    } else if (threat && threat.error) {
      setBadge(badgeThreat, 'NOT AVAILABLE', 'badge-na');
      descThreat.textContent = `Threat lookup service error: ${threat.error}`;
    } else {
      setBadge(badgeThreat, 'PASSED', 'badge-passed');
      descThreat.textContent = 'No records found on verified phishing blocklists or Google Safe Browsing threat databases.';
    }

    // 6. Whitelist Check
    const isWhitelisted = await isDomainWhitelisted(data.hostname);
    if (isWhitelisted) {
      setBadge(badgeWhitelist, 'TRUSTED', 'badge-passed');
      descWhitelist.textContent = 'Domain is on your personal Trusted Whitelist. Standard heuristic warnings are suppressed.';
    } else {
      setBadge(badgeWhitelist, 'NOT LISTED', 'badge-na');
      descWhitelist.textContent = 'Domain is not in your personal Trusted Whitelist.';
    }

    // User Advice
    if (verdict === 'DANGEROUS') {
      adviceBox.className = 'advice-box advice-dangerous';
      adviceTitle.textContent = 'DANGER: Do NOT Enter Credentials';
      adviceBody.textContent = 'This website exhibits critical security risks consistent with credential harvesting or phishing. Close this tab immediately and do not submit passwords.';
    } else if (verdict === 'SUSPICIOUS') {
      adviceBox.className = 'advice-box advice-suspicious';
      adviceTitle.textContent = 'Caution: Verify Identity Before Logging In';
      adviceBody.textContent = 'Several structural or heuristic anomalies were detected. Check the address bar carefully to ensure this is indeed the official portal.';
    } else {
      adviceBox.className = 'advice-box advice-safe';
      adviceTitle.textContent = 'Safe Browsing Advice';
      adviceBody.textContent = 'No known risk indicators were identified. Always remain cautious and confirm that you recognize the organization.';
    }
  }

  function setBadge(el, text, className) {
    if (!el) return;
    el.textContent = text;
    el.className = `check-badge ${className}`;
  }
});
