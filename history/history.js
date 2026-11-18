/**
 * LoginGuard - Scan History Controller
 */

import { getHistory, deleteHistoryRecord, clearAllHistory } from '../utils/storage.js';

document.addEventListener('DOMContentLoaded', async () => {
  const historyListEl = document.getElementById('history-list');
  const emptyHistoryEl = document.getElementById('empty-history');
  const searchInput = document.getElementById('search-input');
  const filterTabs = document.querySelectorAll('.filter-tab');

  const countAll = document.getElementById('count-all');
  const countSafe = document.getElementById('count-safe');
  const countSuspicious = document.getElementById('count-suspicious');
  const countDangerous = document.getElementById('count-dangerous');
  const historyTotalInfo = document.getElementById('history-total-info');

  const btnExportJson = document.getElementById('btn-export-json');
  const btnClearAll = document.getElementById('btn-clear-all');

  let fullHistory = [];
  let currentFilter = 'ALL';
  let searchQuery = '';

  async function loadHistory() {
    fullHistory = await getHistory();
    updateCounts();
    renderFiltered();
  }

  function updateCounts() {
    const total = fullHistory.length;
    const safe = fullHistory.filter(h => h.verdict === 'SAFE').length;
    const suspicious = fullHistory.filter(h => h.verdict === 'SUSPICIOUS').length;
    const dangerous = fullHistory.filter(h => h.verdict === 'DANGEROUS').length;

    countAll.textContent = total;
    countSafe.textContent = safe;
    countSuspicious.textContent = suspicious;
    countDangerous.textContent = dangerous;

    historyTotalInfo.textContent = `Total records: ${total} / 1000 max`;
  }

  function renderFiltered() {
    let filtered = fullHistory;

    // Apply Verdict Filter
    if (currentFilter !== 'ALL') {
      filtered = filtered.filter(item => item.verdict === currentFilter);
    }

    // Apply Search Query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      filtered = filtered.filter(item =>
        (item.hostname && item.hostname.toLowerCase().includes(q)) ||
        (item.url && item.url.toLowerCase().includes(q))
      );
    }

    if (filtered.length === 0) {
      historyListEl.innerHTML = '';
      emptyHistoryEl.style.display = 'flex';
      return;
    }

    emptyHistoryEl.style.display = 'none';
    historyListEl.innerHTML = '';

    filtered.forEach(item => {
      const row = document.createElement('div');
      row.className = 'history-item';

      const timeStr = item.timestamp
        ? new Date(item.timestamp).toLocaleString(undefined, {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
          })
        : 'Unknown time';

      row.innerHTML = `
        <div class="history-main-info">
          <span class="verdict-badge badge-${item.verdict || 'SAFE'}">${item.verdict || 'SAFE'}</span>
          <div class="history-domain-info">
            <span class="history-domain">${escapeHtml(item.hostname || 'Unknown')}</span>
            <span class="history-url" title="${escapeHtml(item.url || '')}">${escapeHtml(item.url || '')}</span>
          </div>
        </div>
        <div class="history-meta-info">
          <span class="history-score">${item.score || 0}/100</span>
          <span class="history-time">${timeStr}</span>
          <div class="history-item-actions">
            <button class="btn-icon view-report" title="View Full Report" data-domain="${escapeHtml(item.hostname)}">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                <circle cx="12" cy="12" r="3"></circle>
              </svg>
            </button>
            <button class="btn-icon delete delete-record" title="Delete Record" data-id="${item.id}">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"></polyline>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
              </svg>
            </button>
          </div>
        </div>
      `;

      historyListEl.appendChild(row);
    });

    // Wire action buttons
    historyListEl.querySelectorAll('.view-report').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const domain = e.currentTarget.getAttribute('data-domain');
        chrome.runtime.sendMessage({
          type: 'OPEN_REPORT',
          domain
        });
      });
    });

    historyListEl.querySelectorAll('.delete-record').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        await deleteHistoryRecord(id);
        await loadHistory();
      });
    });
  }

  // Filter tabs click
  filterTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      filterTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentFilter = tab.getAttribute('data-filter');
      renderFiltered();
    });
  });

  // Search input
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value;
      renderFiltered();
    });
  }

  // Clear all history
  if (btnClearAll) {
    btnClearAll.addEventListener('click', async () => {
      if (confirm('Are you sure you want to permanently clear all scan history? This action cannot be undone.')) {
        await clearAllHistory();
        await loadHistory();
      }
    });
  }

  // Export JSON
  if (btnExportJson) {
    btnExportJson.addEventListener('click', () => {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(fullHistory, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `loginguard-history-${new Date().toISOString().slice(0, 10)}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
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

  // Initial load
  loadHistory();
});
