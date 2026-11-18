/**
 * LoginGuard - Automatic Login Page Detector
 * Inspects DOM for password input elements without ever accessing field values.
 * 
 * STRICT PRIVACY GUARANTEE:
 * 1. Never reads password or username values (.value).
 * 2. Never attaches event listeners to keystrokes (keydown, keyup, input).
 * 3. Never intercepts form submissions (submit event).
 * 4. Only analyzes the current page URL and hostname.
 */

(function () {
  // Prevent double-initialization
  if (window.__loginguard_detector_installed) return;
  window.__loginguard_detector_installed = true;

  let hasScannedCurrentPage = false;
  let lastScannedUrl = '';
  let debounceTimeout = null;

  /**
   * Checks if the DOM contains any password input elements.
   * Only checks element existence/attributes; NEVER reads .value!
   */
  function hasPasswordField() {
    try {
      const passwordInputs = document.querySelectorAll('input[type="password"]');
      return passwordInputs.length > 0;
    } catch (e) {
      return false;
    }
  }

  /**
   * Triggers security scan for the current page.
   */
  function triggerScan(reason = 'password_field_detected') {
    const currentUrl = window.location.href;

    // Avoid redundant scans of the same URL in the same session
    if (hasScannedCurrentPage && lastScannedUrl === currentUrl) {
      return;
    }

    hasScannedCurrentPage = true;
    lastScannedUrl = currentUrl;

    // Notify background service worker with ONLY the URL
    chrome.runtime.sendMessage(
      {
        type: 'LOGIN_PAGE_DETECTED',
        url: currentUrl,
        triggerReason: reason
      },
      (response) => {
        if (chrome.runtime.lastError) {
          // Extension reloaded or inactive
          return;
        }

        if (response && response.success && response.showOverlay) {
          if (window.LoginGuardOverlay && typeof window.LoginGuardOverlay.render === 'function') {
            window.LoginGuardOverlay.render(response);
          }
        }
      }
    );
  }

  /**
   * Debounced check function to prevent excessive DOM inspections.
   */
  function evaluatePage(reason = 'mutation') {
    if (debounceTimeout) clearTimeout(debounceTimeout);
    debounceTimeout = setTimeout(() => {
      if (hasPasswordField()) {
        triggerScan(reason);
      }
    }, 400);
  }

  // 1. Initial check when page loads
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => evaluatePage('initial_dom_ready'));
  } else {
    evaluatePage('initial_immediate');
  }

  // 2. Observe dynamic changes (modals, login overlays, React/Vue/Angular dynamic renders)
  const observer = new MutationObserver((mutations) => {
    let shouldCheck = false;
    for (const mutation of mutations) {
      if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            if (node.tagName === 'INPUT' && node.getAttribute('type') === 'password') {
              shouldCheck = true;
              break;
            }
            if (node.querySelector && node.querySelector('input[type="password"]')) {
              shouldCheck = true;
              break;
            }
          }
        }
      } else if (mutation.type === 'attributes' && mutation.attributeName === 'type') {
        if (mutation.target.getAttribute('type') === 'password') {
          shouldCheck = true;
          break;
        }
      }
      if (shouldCheck) break;
    }

    if (shouldCheck) {
      evaluatePage('dynamic_dom_mutation');
    }
  });

  observer.observe(document.documentElement || document.body, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['type']
  });

  // 3. SPA Navigation Handling (History API & hashchange)
  function handleUrlChange() {
    if (window.location.href !== lastScannedUrl) {
      hasScannedCurrentPage = false;
      // Remove any existing overlay from prior page view
      const existing = document.getElementById('loginguard-overlay-root');
      if (existing) existing.remove();
      evaluatePage('spa_navigation');
    }
  }

  window.addEventListener('popstate', handleUrlChange);
  window.addEventListener('hashchange', handleUrlChange);

  // Monkey-patch history.pushState and replaceState to catch client-side routing
  const originalPushState = history.pushState;
  if (originalPushState) {
    history.pushState = function (...args) {
      originalPushState.apply(this, args);
      handleUrlChange();
    };
  }

  const originalReplaceState = history.replaceState;
  if (originalReplaceState) {
    history.replaceState = function (...args) {
      originalReplaceState.apply(this, args);
      handleUrlChange();
    };
  }
})();
