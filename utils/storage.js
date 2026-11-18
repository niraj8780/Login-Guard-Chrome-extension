/**
 * LoginGuard - Chrome Storage Helper
 * Manages user settings, trusted domain whitelist, scan history, and lookup caches.
 */

const DEFAULT_SETTINGS = {
  autoScanEnabled: true,
  showOverlay: true,
  checkRdap: true,
  checkThreatIntel: true,
  googleApiKey: '',
  backendProxyUrl: '',
  soundAlert: false
};

const DEFAULT_WHITELIST = [
  'accounts.google.com',
  'login.microsoftonline.com',
  'appleid.apple.com',
  'github.com',
  'paypal.com'
];

const MAX_HISTORY_ITEMS = 1000;

// Memory fallback for Node.js test environment
const memoryStorage = {
  settings: { ...DEFAULT_SETTINGS },
  whitelist: [...DEFAULT_WHITELIST],
  history: [],
  cache: {}
};

function hasChromeStorage() {
  return typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;
}

/**
 * Retrieves current extension settings.
 */
export async function getSettings() {
  if (!hasChromeStorage()) {
    return memoryStorage.settings;
  }
  return new Promise((resolve) => {
    chrome.storage.local.get(['settings'], (result) => {
      resolve({ ...DEFAULT_SETTINGS, ...(result.settings || {}) });
    });
  });
}

/**
 * Saves updated settings.
 */
export async function saveSettings(newSettings) {
  if (!hasChromeStorage()) {
    memoryStorage.settings = { ...memoryStorage.settings, ...newSettings };
    return memoryStorage.settings;
  }
  return new Promise((resolve) => {
    chrome.storage.local.get(['settings'], (result) => {
      const merged = { ...DEFAULT_SETTINGS, ...(result.settings || {}), ...newSettings };
      chrome.storage.local.set({ settings: merged }, () => resolve(merged));
    });
  });
}

/**
 * Retrieves trusted domains whitelist.
 */
export async function getWhitelist() {
  if (!hasChromeStorage()) {
    return memoryStorage.whitelist;
  }
  return new Promise((resolve) => {
    chrome.storage.local.get(['whitelist'], (result) => {
      resolve(result.whitelist || DEFAULT_WHITELIST);
    });
  });
}

/**
 * Checks if a hostname or domain is in the whitelist.
 */
export async function isDomainWhitelisted(domain) {
  if (!domain) return false;
  const list = await getWhitelist();
  const clean = domain.toLowerCase().trim();
  return list.some(item => {
    const target = item.toLowerCase().trim();
    return clean === target || clean.endsWith('.' + target);
  });
}

/**
 * Adds a domain to the whitelist.
 */
export async function addWhitelistDomain(domain) {
  const clean = domain.toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!clean) return false;

  const current = await getWhitelist();
  if (!current.includes(clean)) {
    const updated = [...current, clean];
    if (!hasChromeStorage()) {
      memoryStorage.whitelist = updated;
      return true;
    }
    return new Promise((resolve) => {
      chrome.storage.local.set({ whitelist: updated }, () => resolve(true));
    });
  }
  return true;
}

/**
 * Removes a domain from the whitelist.
 */
export async function removeWhitelistDomain(domain) {
  const clean = domain.toLowerCase().trim();
  const current = await getWhitelist();
  const updated = current.filter(d => d !== clean);

  if (!hasChromeStorage()) {
    memoryStorage.whitelist = updated;
    return true;
  }
  return new Promise((resolve) => {
    chrome.storage.local.set({ whitelist: updated }, () => resolve(true));
  });
}

/**
 * Clears all whitelist domains.
 */
export async function clearWhitelist() {
  if (!hasChromeStorage()) {
    memoryStorage.whitelist = [];
    return true;
  }
  return new Promise((resolve) => {
    chrome.storage.local.set({ whitelist: [] }, () => resolve(true));
  });
}

/**
 * Retrieves scan history list.
 */
export async function getHistory() {
  if (!hasChromeStorage()) {
    return memoryStorage.history;
  }
  return new Promise((resolve) => {
    chrome.storage.local.get(['history'], (result) => {
      resolve(result.history || []);
    });
  });
}

/**
 * Adds a scan result to history.
 * Never stores passwords, form inputs, or credentials.
 */
export async function addHistoryRecord(record) {
  const safeRecord = {
    id: 'scan_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
    timestamp: new Date().toISOString(),
    url: record.url,
    hostname: record.hostname,
    registrableDomain: record.registrableDomain,
    protocol: record.protocol,
    verdict: record.verdict,
    score: record.score,
    reasons: record.reasons || [],
    isWhitelisted: !!record.isWhitelisted
  };

  const current = await getHistory();
  // Prepend and cap at MAX_HISTORY_ITEMS
  const updated = [safeRecord, ...current].slice(0, MAX_HISTORY_ITEMS);

  if (!hasChromeStorage()) {
    memoryStorage.history = updated;
    return safeRecord;
  }

  return new Promise((resolve) => {
    chrome.storage.local.set({ history: updated }, () => resolve(safeRecord));
  });
}

/**
 * Deletes a single history record by ID.
 */
export async function deleteHistoryRecord(id) {
  const current = await getHistory();
  const updated = current.filter(item => item.id !== id);

  if (!hasChromeStorage()) {
    memoryStorage.history = updated;
    return true;
  }
  return new Promise((resolve) => {
    chrome.storage.local.set({ history: updated }, () => resolve(true));
  });
}

/**
 * Clears entire scan history.
 */
export async function clearAllHistory() {
  if (!hasChromeStorage()) {
    memoryStorage.history = [];
    return true;
  }
  return new Promise((resolve) => {
    chrome.storage.local.set({ history: [] }, () => resolve(true));
  });
}

/**
 * Analysis cache to avoid repeated RDAP / API calls within 1 hour
 */
export async function getCachedAnalysis(key) {
  if (!hasChromeStorage()) {
    const item = memoryStorage.cache[key];
    if (item && item.expiresAt > Date.now()) return item.data;
    return null;
  }
  return new Promise((resolve) => {
    chrome.storage.local.get([`cache_${key}`], (res) => {
      const item = res[`cache_${key}`];
      if (item && item.expiresAt > Date.now()) {
        resolve(item.data);
      } else {
        resolve(null);
      }
    });
  });
}

export async function setCachedAnalysis(key, data, ttlMinutes = 60) {
  const item = {
    data,
    expiresAt: Date.now() + ttlMinutes * 60 * 1000
  };
  if (!hasChromeStorage()) {
    memoryStorage.cache[key] = item;
    return;
  }
  return new Promise((resolve) => {
    chrome.storage.local.set({ [`cache_${key}`]: item }, () => resolve());
  });
}
