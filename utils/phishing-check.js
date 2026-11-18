/**
 * LoginGuard - Phishing Threat Intelligence Utility
 * Integrates Google Safe Browsing API (v4), backend proxy, and local threat signatures.
 */

// Well-known curated test signatures for verification and offline protection
const KNOWN_PHISHING_SIGNATURES = new Set([
  'testsafebrowsing.appspot.com/s/phishing.html',
  'phishing.test',
  'paypal-verification-update.com',
  'apple-security-check.account-login.cc',
  'secure-login-chase-update.info',
  'goog1e-login.com'
]);

/**
 * Checks domain or URL against local blocklist / signature feed.
 */
export function checkLocalThreatSignatures(url, hostname) {
  const cleanUrl = url.toLowerCase().replace(/^https?:\/\//, '');
  const cleanHost = hostname.toLowerCase();

  for (const sig of KNOWN_PHISHING_SIGNATURES) {
    if (cleanUrl.includes(sig) || cleanHost === sig) {
      return {
        matched: true,
        source: 'LoginGuard Known Phishing Threat Database',
        threatType: 'SOCIAL_ENGINEERING / PHISHING',
        scorePenalty: 70
      };
    }
  }

  return { matched: false };
}

/**
 * Queries Google Safe Browsing API v4 Lookup endpoint.
 * Returns { isPhishing: boolean, details: object, error?: string }
 */
export async function queryGoogleSafeBrowsing(url, apiKey, timeoutMs = 4000) {
  if (!apiKey) {
    return { isConfigured: false, checked: false, note: 'Safe Browsing API Key not configured' };
  }

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;
  const body = {
    client: {
      clientId: 'loginguard-extension',
      clientVersion: '1.0.0'
    },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    clearTimeout(timer);

    if (!res.ok) {
      return {
        isConfigured: true,
        checked: false,
        error: `Safe Browsing API HTTP error: ${res.status}`,
        scorePenalty: 0
      };
    }

    const data = await res.json();
    const matches = data.matches || [];

    if (matches.length > 0) {
      const first = matches[0];
      return {
        isConfigured: true,
        checked: true,
        isPhishing: true,
        threatType: first.threatType || 'MALICIOUS_SITE',
        source: 'Google Safe Browsing v4',
        scorePenalty: 70,
        details: matches
      };
    }

    return {
      isConfigured: true,
      checked: true,
      isPhishing: false,
      threatType: null,
      source: 'Google Safe Browsing v4',
      scorePenalty: 0
    };
  } catch (err) {
    clearTimeout(timer);
    return {
      isConfigured: true,
      checked: false,
      error: `Safe Browsing network error: ${err.name === 'AbortError' ? 'Timeout' : err.message}`,
      scorePenalty: 0
    };
  }
}

/**
 * Queries the optional LoginGuard backend proxy (if running).
 */
export async function queryBackendProxy(url, domain, proxyUrl, timeoutMs = 3500) {
  if (!proxyUrl) {
    return { checked: false, note: 'No backend proxy URL configured' };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const endpoint = `${proxyUrl.replace(/\/$/, '')}/api/check-domain`;
    const res = await fetch(endpoint, {
      method: 'POST',
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, domain })
    });

    clearTimeout(timer);

    if (!res.ok) {
      return { checked: false, error: `Backend returned ${res.status}` };
    }

    const data = await res.json();
    return { checked: true, ...data };
  } catch (err) {
    clearTimeout(timer);
    return { checked: false, error: `Backend offline or unreachable (${err.message})` };
  }
}

/**
 * Combined Phishing Intelligence Orchestrator
 */
export async function checkPhishingIntelligence(url, hostname, options = {}) {
  const { apiKey = null, backendProxyUrl = null } = options;

  // 1. Check local threat signatures first
  const localMatch = checkLocalThreatSignatures(url, hostname);
  if (localMatch.matched) {
    return {
      isConfirmedPhishing: true,
      threatType: localMatch.threatType,
      source: localMatch.source,
      scorePenalty: localMatch.scorePenalty,
      note: 'Known active phishing threat pattern identified'
    };
  }

  // 2. If backend proxy configured, try it
  if (backendProxyUrl) {
    const backendResult = await queryBackendProxy(url, hostname, backendProxyUrl);
    if (backendResult.checked && backendResult.isConfirmedPhishing) {
      return {
        isConfirmedPhishing: true,
        threatType: backendResult.threatType,
        source: 'LoginGuard Backend Threat Intel',
        scorePenalty: 70,
        note: 'Confirmed malicious by threat intelligence backend'
      };
    }
  }

  // 3. If direct Google Safe Browsing API key provided, try it
  if (apiKey) {
    const gsbResult = await queryGoogleSafeBrowsing(url, apiKey);
    if (gsbResult.checked && gsbResult.isPhishing) {
      return {
        isConfirmedPhishing: true,
        threatType: gsbResult.threatType,
        source: gsbResult.source,
        scorePenalty: 70,
        note: `Flagged as ${gsbResult.threatType} by Google Safe Browsing`
      };
    }
  }

  // No confirmed match found
  return {
    isConfirmedPhishing: false,
    threatType: null,
    source: null,
    scorePenalty: 0,
    note: 'No matches found in active threat intelligence databases'
  };
}
