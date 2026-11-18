/**
 * LoginGuard - In-Page Security Overlay Renderer
 * Creates an isolated Shadow DOM container and displays an interactive security banner.
 */

(function () {
  // Shield SVG Icon
  const SHIELD_SVG = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  `;

  const CLOSE_SVG = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <line x1="18" y1="6" x2="6" y2="18"></line>
      <line x1="6" y1="6" x2="18" y2="18"></line>
    </svg>
  `;

  // Inline CSS for the Shadow DOM to guarantee instant rendering without external network latency
  const OVERLAY_STYLES = `
    :host {
      all: initial;
      position: fixed;
      top: 24px;
      right: 24px;
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      box-sizing: border-box;
    }
    *, *::before, *::after {
      box-sizing: inherit;
      margin: 0;
      padding: 0;
    }
    .loginguard-card {
      width: 360px;
      max-width: calc(100vw - 48px);
      background: #0f172a;
      color: #f8fafc;
      border-radius: 14px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.12);
      overflow: hidden;
      animation: lgSlide 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      border-left: 5px solid #10b981;
    }
    .verdict-SAFE { border-left-color: #10b981; }
    .verdict-SUSPICIOUS { border-left-color: #f59e0b; }
    .verdict-DANGEROUS { border-left-color: #ef4444; }

    @keyframes lgSlide {
      from { opacity: 0; transform: translateY(-16px) scale(0.96); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }

    .lg-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: rgba(30, 41, 59, 0.85);
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }
    .lg-brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .lg-icon {
      width: 20px;
      height: 20px;
      stroke: #38bdf8;
    }
    .lg-titles {
      display: flex;
      flex-direction: column;
    }
    .lg-app-name {
      font-size: 13px;
      font-weight: 700;
      color: #ffffff;
      letter-spacing: 0.3px;
    }
    .lg-app-sub {
      font-size: 10px;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .lg-close {
      background: transparent;
      border: none;
      color: #94a3b8;
      cursor: pointer;
      padding: 4px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.15s ease;
    }
    .lg-close:hover {
      background: rgba(255, 255, 255, 0.1);
      color: #ffffff;
    }

    .lg-body {
      padding: 14px 16px;
    }
    .lg-domain-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
      font-size: 12px;
    }
    .lg-label {
      color: #94a3b8;
      font-weight: 500;
    }
    .lg-val {
      font-weight: 600;
      color: #f1f5f9;
      max-width: 210px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .lg-verdict-box {
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: #1e293b;
      padding: 10px 12px;
      border-radius: 8px;
      margin-bottom: 12px;
      border: 1px solid rgba(255, 255, 255, 0.05);
    }
    .lg-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      font-weight: 800;
      padding: 4px 10px;
      border-radius: 6px;
      letter-spacing: 0.6px;
      text-transform: uppercase;
    }
    .badge-SAFE {
      background: rgba(16, 185, 129, 0.18);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .badge-SUSPICIOUS {
      background: rgba(245, 158, 11, 0.18);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.35);
    }
    .badge-DANGEROUS {
      background: rgba(239, 68, 68, 0.18);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.35);
    }
    .lg-score-col {
      text-align: right;
    }
    .lg-score-digits {
      font-size: 15px;
      font-weight: 800;
      color: #ffffff;
    }
    .lg-score-caption {
      font-size: 9px;
      color: #94a3b8;
      text-transform: uppercase;
    }

    .lg-reasons-wrap {
      margin-bottom: 14px;
    }
    .lg-reasons-header {
      font-size: 11px;
      font-weight: 600;
      color: #94a3b8;
      text-transform: uppercase;
      margin-bottom: 6px;
      letter-spacing: 0.5px;
    }
    .lg-reasons {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .lg-reason-li {
      font-size: 11.5px;
      line-height: 1.4;
      color: #cbd5e1;
      background: rgba(255, 255, 255, 0.04);
      padding: 6px 10px;
      border-radius: 6px;
      display: flex;
      align-items: flex-start;
      gap: 6px;
    }
    .lg-bullet {
      color: #38bdf8;
      font-weight: 700;
    }

    .lg-actions {
      display: flex;
      gap: 8px;
    }
    .lg-btn {
      flex: 1;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      border: none;
      transition: all 0.15s ease;
      text-align: center;
    }
    .lg-btn-dismiss {
      background: #334155;
      color: #cbd5e1;
    }
    .lg-btn-dismiss:hover {
      background: #475569;
      color: #ffffff;
    }
    .lg-btn-details {
      background: #0284c7;
      color: #ffffff;
    }
    .lg-btn-details:hover {
      background: #0369a1;
    }
  `;

  window.LoginGuardOverlay = {
    render(data) {
      // Prevent duplicate overlays
      if (document.getElementById('loginguard-overlay-root')) {
        return;
      }

      const host = document.createElement('div');
      host.id = 'loginguard-overlay-root';
      const shadow = host.attachShadow({ mode: 'open' });

      // Build style element
      const styleEl = document.createElement('style');
      styleEl.textContent = OVERLAY_STYLES;
      shadow.appendChild(styleEl);

      const verdict = data.verdict || 'SAFE';
      const score = typeof data.score === 'number' ? data.score : 0;
      const hostname = data.hostname || window.location.hostname;
      const reasons = Array.isArray(data.reasons) && data.reasons.length > 0
        ? data.reasons.slice(0, 3)
        : ['Website security heuristics verified.'];

      const reasonsHtml = reasons.map(r => `
        <li class="lg-reason-li">
          <span class="lg-bullet">•</span>
          <span>${escapeHtml(r)}</span>
        </li>
      `).join('');

      const card = document.createElement('div');
      card.className = `loginguard-card verdict-${verdict}`;
      card.innerHTML = `
        <div class="lg-header">
          <div class="lg-brand">
            <div class="lg-icon">${SHIELD_SVG}</div>
            <div class="lg-titles">
              <span class="lg-app-name">LoginGuard</span>
              <span class="lg-app-sub">Website Security Check</span>
            </div>
          </div>
          <button class="lg-close" id="lg-close-btn" title="Dismiss">${CLOSE_SVG}</button>
        </div>
        <div class="lg-body">
          <div class="lg-domain-row">
            <span class="lg-label">Website</span>
            <span class="lg-val" title="${escapeHtml(hostname)}">${escapeHtml(hostname)}</span>
          </div>

          <div class="lg-verdict-box">
            <div class="lg-badge badge-${verdict}">
              ${verdict}
            </div>
            <div class="lg-score-col">
              <div class="lg-score-digits">${score}/100</div>
              <div class="lg-score-caption">Risk Score</div>
            </div>
          </div>

          <div class="lg-reasons-wrap">
            <div class="lg-reasons-header">Security Analysis:</div>
            <ul class="lg-reasons">
              ${reasonsHtml}
            </ul>
          </div>

          <div class="lg-actions">
            <button class="lg-btn lg-btn-dismiss" id="lg-dismiss-btn">Dismiss</button>
            <button class="lg-btn lg-btn-details" id="lg-details-btn">View Details</button>
          </div>
        </div>
      `;

      shadow.appendChild(card);
      document.body.appendChild(host);

      // Event listeners
      const removeOverlay = () => {
        if (host && host.parentNode) {
          host.parentNode.removeChild(host);
        }
      };

      const closeBtn = shadow.getElementById('lg-close-btn');
      const dismissBtn = shadow.getElementById('lg-dismiss-btn');
      const detailsBtn = shadow.getElementById('lg-details-btn');

      if (closeBtn) closeBtn.addEventListener('click', removeOverlay);
      if (dismissBtn) dismissBtn.addEventListener('click', removeOverlay);

      if (detailsBtn) {
        detailsBtn.addEventListener('click', () => {
          chrome.runtime.sendMessage({
            type: 'OPEN_REPORT',
            domain: hostname
          });
        });
      }

      // If Safe, optionally auto-dismiss after 12 seconds so it doesn't stay indefinitely
      if (verdict === 'SAFE') {
        setTimeout(() => {
          removeOverlay();
        }, 12000);
      }
    }
  };

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
})();
