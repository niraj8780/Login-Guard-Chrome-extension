/**
 * LoginGuard - Settings Controller
 */

import {
  getSettings,
  saveSettings,
  getWhitelist,
  addWhitelistDomain,
  removeWhitelistDomain,
  clearAllHistory
} from '../utils/storage.js';

document.addEventListener('DOMContentLoaded', async () => {
  const settingAutoScan = document.getElementById('setting-auto-scan');
  const settingShowOverlay = document.getElementById('setting-show-overlay');
  const settingCheckRdap = document.getElementById('setting-check-rdap');
  const settingCheckThreat = document.getElementById('setting-check-threat');
  const settingGoogleApiKey = document.getElementById('setting-google-api-key');
  const settingBackendProxy = document.getElementById('setting-backend-proxy');

  const btnToggleKeyVis = document.getElementById('btn-toggle-key-vis');
  const btnTestConnection = document.getElementById('btn-test-connection');
  const testConnectionStatus = document.getElementById('test-connection-status');

  const whitelistInput = document.getElementById('whitelist-input');
  const btnAddWhitelist = document.getElementById('btn-add-whitelist');
  const whitelistTagsContainer = document.getElementById('whitelist-tags-container');

  const btnSave = document.getElementById('btn-save');
  const btnPurgeHistory = document.getElementById('btn-purge-history');
  const saveStatus = document.getElementById('save-status');

  // 1. Load initial settings
  const settings = await getSettings();
  settingAutoScan.checked = settings.autoScanEnabled;
  settingShowOverlay.checked = settings.showOverlay;
  settingCheckRdap.checked = settings.checkRdap;
  settingCheckThreat.checked = settings.checkThreatIntel;
  settingGoogleApiKey.value = settings.googleApiKey || '';
  settingBackendProxy.value = settings.backendProxyUrl || '';

  // 2. Load whitelist
  async function renderWhitelist() {
    const list = await getWhitelist();
    whitelistTagsContainer.innerHTML = '';

    if (list.length === 0) {
      whitelistTagsContainer.innerHTML = '<span style="font-size: 11px; color: #64748b;">No trusted domains configured yet.</span>';
      return;
    }

    list.forEach(domain => {
      const pill = document.createElement('div');
      pill.className = 'whitelist-pill';
      pill.innerHTML = `
        <span>${escapeHtml(domain)}</span>
        <button class="whitelist-remove" data-domain="${escapeHtml(domain)}" title="Remove">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
      `;
      whitelistTagsContainer.appendChild(pill);
    });

    whitelistTagsContainer.querySelectorAll('.whitelist-remove').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const domain = e.currentTarget.getAttribute('data-domain');
        await removeWhitelistDomain(domain);
        await renderWhitelist();
      });
    });
  }

  await renderWhitelist();

  // Add whitelist domain
  async function handleAddWhitelist() {
    const val = whitelistInput.value.trim();
    if (!val) return;
    await addWhitelistDomain(val);
    whitelistInput.value = '';
    await renderWhitelist();
  }

  if (btnAddWhitelist) {
    btnAddWhitelist.addEventListener('click', handleAddWhitelist);
  }

  if (whitelistInput) {
    whitelistInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleAddWhitelist();
      }
    });
  }

  // Toggle API key visibility
  if (btnToggleKeyVis) {
    btnToggleKeyVis.addEventListener('click', () => {
      if (settingGoogleApiKey.type === 'password') {
        settingGoogleApiKey.type = 'text';
        btnToggleKeyVis.textContent = 'Hide';
      } else {
        settingGoogleApiKey.type = 'password';
        btnToggleKeyVis.textContent = 'Show';
      }
    });
  }

  // Test backend proxy connection
  if (btnTestConnection) {
    btnTestConnection.addEventListener('click', async () => {
      const url = settingBackendProxy.value.trim();
      if (!url) {
        testConnectionStatus.textContent = 'Please enter a proxy URL to test.';
        testConnectionStatus.style.color = '#f59e0b';
        return;
      }

      testConnectionStatus.textContent = 'Testing connection...';
      testConnectionStatus.style.color = '#38bdf8';

      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3500);
        const endpoint = `${url.replace(/\/$/, '')}/api/health`;
        const res = await fetch(endpoint, { signal: controller.signal });
        clearTimeout(timer);

        if (res.ok) {
          testConnectionStatus.textContent = 'Connection Successful! Backend is online and responding.';
          testConnectionStatus.style.color = '#34d399';
        } else {
          testConnectionStatus.textContent = `Backend responded with status ${res.status}.`;
          testConnectionStatus.style.color = '#f87171';
        }
      } catch (err) {
        testConnectionStatus.textContent = `Connection failed: ${err.message}`;
        testConnectionStatus.style.color = '#f87171';
      }
    });
  }

  // Save changes
  if (btnSave) {
    btnSave.addEventListener('click', async () => {
      const updated = {
        autoScanEnabled: settingAutoScan.checked,
        showOverlay: settingShowOverlay.checked,
        checkRdap: settingCheckRdap.checked,
        checkThreatIntel: settingCheckThreat.checked,
        googleApiKey: settingGoogleApiKey.value.trim(),
        backendProxyUrl: settingBackendProxy.value.trim()
      };

      await saveSettings(updated);

      saveStatus.style.display = 'block';
      saveStatus.className = 'status-banner status-success';
      saveStatus.textContent = 'Settings successfully saved to local storage.';

      setTimeout(() => {
        saveStatus.style.display = 'none';
      }, 4000);
    });
  }

  // Purge history
  if (btnPurgeHistory) {
    btnPurgeHistory.addEventListener('click', async () => {
      if (confirm('Permanently delete all stored domain scan history? This action cannot be reversed.')) {
        await clearAllHistory();
        alert('Scan history has been completely purged.');
      }
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
