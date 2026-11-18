/**
 * LoginGuard - Popup Controller
 * Connects UI with background service worker to display instant tab security status.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const scannedView = document.getElementById('scanned-view');
  const emptyView = document.getElementById('empty-view');

  const siteHostnameEl = document.getElementById('site-hostname');
  const emptySiteHostnameEl = document.getElementById('empty-site-hostname');
  const verdictBadgeEl = document.getElementById('verdict-badge');
  const verdictTextEl = document.getElementById('verdict-text');
  const meterBarFillEl = document.getElementById('meter-bar-fill');
  const riskScoreValueEl = document.getElementById('risk-score-value');
  const reasonsListEl = document.getElementById('reasons-list');
  const scanTimestampEl = document.getElementById('scan-timestamp');

  const btnFullReport = document.getElementById('btn-full-report');
  const btnRescan = document.getElementById('btn-rescan');
  const btnManualScan = document.getElementById('btn-manual-scan');
  const btnOpenSettings = document.getElementById('btn-open-settings');
  const btnOpenHistory = document.getElementById('btn-open-history');

  let currentTab = null;
  let currentDomain = '';

  // 1. Get active tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs.length > 0) {
      currentTab = tabs[0];
      if (currentTab.url) {
        try {
          const urlObj = new URL(currentTab.url);
          currentDomain = urlObj.hostname;
        } catch (e) {
          currentDomain = currentTab.url;
        }
      }
    }
  } catch (err) {
    console.error('Error fetching active tab:', err);
  }

  // 2. Query tab status from background worker
  function refreshStatus() {
    if (!currentTab || !currentTab.id) {
      showEmptyState('Unknown Tab');
      return;
    }

    chrome.runtime.sendMessage({
      type: 'GET_TAB_STATUS',
      tabId: currentTab.id
    }, (response) => {
      if (chrome.runtime.lastError || !response || !response.hasData) {
        showEmptyState(currentDomain || 'Unknown Site');
      } else {
        renderScanData(response);
      }
    });
  }

  function showEmptyState(domain) {
    scannedView.style.display = 'none';
    emptyView.style.display = 'block';
    emptySiteHostnameEl.textContent = domain;
  }

  function renderScanData(data) {
    emptyView.style.display = 'none';
    scannedView.style.display = 'block';

    const hostname = data.hostname || currentDomain;
    siteHostnameEl.textContent = hostname;
    siteHostnameEl.title = hostname;

    const verdict = data.verdict || 'SAFE';
    const score = typeof data.score === 'number' ? data.score : 0;

    // Update verdict badge
    verdictBadgeEl.className = `verdict-pill pill-${verdict}`;
    verdictTextEl.textContent = verdict;

    // Update risk meter
    riskScoreValueEl.textContent = `${score}/100`;
    meterBarFillEl.style.width = `${score}%`;

    if (verdict === 'SAFE') {
      meterBarFillEl.style.backgroundColor = '#10b981';
    } else if (verdict === 'SUSPICIOUS') {
      meterBarFillEl.style.backgroundColor = '#f59e0b';
    } else {
      meterBarFillEl.style.backgroundColor = '#ef4444';
    }

    // Render highlights / reasons
    reasonsListEl.innerHTML = '';
    const reasons = Array.isArray(data.reasons) && data.reasons.length > 0
      ? data.reasons
      : ['Website passed core security heuristics.'];

    reasons.slice(0, 3).forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;
      reasonsListEl.appendChild(li);
    });

    // Timestamp
    if (data.timestamp) {
      const date = new Date(data.timestamp);
      scanTimestampEl.textContent = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } else {
      scanTimestampEl.textContent = 'Just now';
    }
  }

  // 3. Manual scan trigger
  function triggerManualScan() {
    if (!currentTab || !currentTab.url) return;

    siteHostnameEl.textContent = currentDomain;
    verdictBadgeEl.className = 'verdict-pill';
    verdictTextEl.textContent = 'SCANNING...';
    scannedView.style.display = 'block';
    emptyView.style.display = 'none';

    chrome.runtime.sendMessage({
      type: 'MANUAL_SCAN_REQUEST',
      url: currentTab.url,
      tabId: currentTab.id
    }, (res) => {
      if (res && res.success) {
        renderScanData(res);
      } else {
        showEmptyState(currentDomain);
      }
    });
  }

  // 4. Attach event listeners
  if (btnFullReport) {
    btnFullReport.addEventListener('click', () => {
      chrome.runtime.sendMessage({
        type: 'OPEN_REPORT',
        domain: currentDomain
      });
    });
  }

  if (btnRescan) {
    btnRescan.addEventListener('click', triggerManualScan);
  }

  if (btnManualScan) {
    btnManualScan.addEventListener('click', triggerManualScan);
  }

  if (btnOpenSettings) {
    btnOpenSettings.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'OPEN_SETTINGS' });
    });
  }

  if (btnOpenHistory) {
    btnOpenHistory.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'OPEN_HISTORY' });
    });
  }

  // Initial load
  refreshStatus();
});
