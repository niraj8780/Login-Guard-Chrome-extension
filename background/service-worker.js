/**
 * LoginGuard - Background Service Worker (Manifest V3)
 * Orchestrates security pipelines, manages tab state, and communicates with UI components.
 */

import { parseDomainInfo, analyzeStructuralSuspicion } from '../utils/domain-check.js';
import { detectLookalike } from '../utils/lookalike-detection.js';
import { checkDomainAge } from '../utils/rdap.js';
import { checkPhishingIntelligence } from '../utils/phishing-check.js';
import { calculateRiskScore, VERDICTS } from '../utils/scoring.js';
import {
  getSettings,
  isDomainWhitelisted,
  addHistoryRecord,
  getCachedAnalysis,
  setCachedAnalysis
} from '../utils/storage.js';

// In-memory tab states: tabId -> latest security report
const tabSecurityStates = new Map();

// Badge colors
const BADGE_COLORS = {
  [VERDICTS.SAFE]: '#10b981',       // Emerald Green
  [VERDICTS.SUSPICIOUS]: '#f59e0b', // Amber
  [VERDICTS.DANGEROUS]: '#ef4444'   // Red
};

/**
 * Updates extension action badge for a tab.
 */
function updateTabBadge(tabId, verdict, score) {
  if (!tabId || typeof chrome === 'undefined' || !chrome.action) return;

  let text = '';
  if (verdict === VERDICTS.SAFE) {
    text = 'SAFE';
  } else if (verdict === VERDICTS.SUSPICIOUS) {
    text = String(score);
  } else if (verdict === VERDICTS.DANGEROUS) {
    text = '!';
  }

  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[verdict] || '#6b7280' });
}

/**
 * Runs full security analysis pipeline for a URL.
 */
export async function performFullSecurityAnalysis(url, tabId = null) {
  const parsed = parseDomainInfo(url);
  if (!parsed.isValid) {
    return {
      success: false,
      error: parsed.error,
      verdict: VERDICTS.DANGEROUS,
      score: 80,
      reasons: ['Malformed or invalid URL scheme.']
    };
  }

  const settings = await getSettings();

  // Check memory/storage cache
  const cacheKey = `${parsed.protocol}//${parsed.hostname}`;
  const cached = await getCachedAnalysis(cacheKey);
  if (cached) {
    if (tabId) {
      tabSecurityStates.set(tabId, cached);
      updateTabBadge(tabId, cached.verdict, cached.score);
    }
    return { success: true, ...cached, fromCache: true };
  }

  // 1. Local HTTPS protocol check
  const isHttp = parsed.protocol === 'http:';

  // 2. Structural anomalies (length, hyphens, subdomains, raw IP, punycode, keywords)
  const structural = analyzeStructuralSuspicion(parsed);

  // 3. Lookalike & brand impersonation check
  const lookalike = detectLookalike(parsed.registrableDomain, parsed.hostname);

  // 4. RDAP domain age check
  let rdapResult = { status: 'SKIPPED', scorePenalty: 0 };
  if (settings.checkRdap && !parsed.isIP && !lookalike.isLegitimateBrand) {
    rdapResult = await checkDomainAge(parsed.registrableDomain);
  }

  // 5. Threat Intelligence (Safe Browsing / local signatures)
  let threatResult = { isConfirmedPhishing: false, scorePenalty: 0 };
  if (settings.checkThreatIntel) {
    threatResult = await checkPhishingIntelligence(url, parsed.hostname, {
      apiKey: settings.googleApiKey,
      backendProxyUrl: settings.backendProxyUrl
    });
  }

  // 6. Whitelist check
  const isWhitelisted = await isDomainWhitelisted(parsed.hostname) ||
                        await isDomainWhitelisted(parsed.registrableDomain);

  // 7. Calculate consolidated risk score & verdict
  const scoring = calculateRiskScore({
    isHttp,
    isConfirmedPhishing: threatResult.isConfirmedPhishing,
    phishingNote: threatResult.note,
    isLookalike: lookalike.isLookalike,
    lookalikeReason: lookalike.reason,
    isBrandImpersonation: lookalike.isBrandImpersonation,
    isRawIP: parsed.isIP,
    isPunycode: parsed.isPunycode,
    rdapScorePenalty: rdapResult.scorePenalty,
    rdapWarning: rdapResult.warning,
    structuralScorePenalty: structural.suspicionPoints,
    structuralIssues: structural.issues,
    isWhitelisted
  });

  const fullReport = {
    url,
    hostname: parsed.hostname,
    registrableDomain: parsed.registrableDomain,
    protocol: parsed.protocol,
    isHttp,
    isIP: parsed.isIP,
    isPunycode: parsed.isPunycode,
    subdomainCount: parsed.subdomainCount,
    hyphenCount: parsed.hyphenCount,
    lookalike,
    rdap: rdapResult,
    threatIntel: threatResult,
    score: scoring.score,
    verdict: scoring.verdict,
    breakdown: scoring.breakdown,
    reasons: scoring.reasons,
    isWhitelisted: scoring.isWhitelisted,
    whitelistSuppressed: scoring.whitelistSuppressed,
    timestamp: new Date().toISOString()
  };

  // Cache result for 30 minutes
  await setCachedAnalysis(cacheKey, fullReport, 30);

  // Record into history
  await addHistoryRecord(fullReport);

  // Cache in tab state
  if (tabId) {
    tabSecurityStates.set(tabId, fullReport);
    updateTabBadge(tabId, fullReport.verdict, fullReport.score);
  }

  return { success: true, ...fullReport };
}

// Runtime message dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender && sender.tab ? sender.tab.id : null;

  if (message.type === 'LOGIN_PAGE_DETECTED') {
    getSettings().then(async (settings) => {
      if (!settings.autoScanEnabled) {
        sendResponse({ ignored: true, reason: 'Auto-scan disabled by user' });
        return;
      }

      const result = await performFullSecurityAnalysis(message.url, tabId);
      sendResponse({
        showOverlay: settings.showOverlay,
        ...result
      });
    });
    return true; // Keep message port open for async response
  }

  if (message.type === 'GET_TAB_STATUS') {
    const targetTabId = message.tabId || tabId;
    const state = tabSecurityStates.get(targetTabId);
    if (state) {
      sendResponse({ hasData: true, ...state });
    } else {
      sendResponse({ hasData: false });
    }
    return false;
  }

  if (message.type === 'MANUAL_SCAN_REQUEST') {
    performFullSecurityAnalysis(message.url, message.tabId).then(result => {
      sendResponse(result);
    });
    return true;
  }

  if (message.type === 'OPEN_REPORT') {
    const reportUrl = chrome.runtime.getURL(`report/report.html?domain=${encodeURIComponent(message.domain || '')}`);
    chrome.tabs.create({ url: reportUrl });
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === 'OPEN_HISTORY') {
    const historyUrl = chrome.runtime.getURL('history/history.html');
    chrome.tabs.create({ url: historyUrl });
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === 'OPEN_SETTINGS') {
    const settingsUrl = chrome.runtime.getURL('settings/settings.html');
    chrome.tabs.create({ url: settingsUrl });
    sendResponse({ ok: true });
    return false;
  }
});

// Clean up tab states on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  tabSecurityStates.delete(tabId);
});

// Reset badge if tab navigates
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
});
