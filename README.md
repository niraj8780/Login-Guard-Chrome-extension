# LoginGuard – Smart Website & Phishing Detection Chrome Extension

LoginGuard is an open-source, privacy-preserving cybersecurity extension built on **Chrome Manifest V3**. It automatically detects when you visit a webpage containing a login or password field, analyzes the domain's authenticity and infrastructure risk, and presents an interactive security verdict banner.

---

## Key Features

1. **Automatic Password-Field Detection**:
   - Uses DOM element inspection and `MutationObserver` to detect password inputs across static websites, login modals, and Single Page Applications (SPAs).
   - **Zero-Credential Privacy**: Never reads `input.value`, never records keystrokes, and never intercepts login submissions.

2. **In-Page Security Verdict Overlay**:
   - Renders a floating banner in the top-right corner isolated via **Shadow DOM** so it never clashes with host website styling.
   - Highlights the domain risk score, verdict badge (**Safe**, **Suspicious**, or **Dangerous**), and direct audit findings.

3. **Multi-Vector Heuristic Engine**:
   - **Protocol Security**: Flags plain HTTP connections where credentials can be intercepted.
   - **Lookalike & Typosquatting Analysis**: Uses Levenshtein edit distance and leetspeak character normalization (e.g. `g00gle.com`, `goog1e-login.com`, `paypa1.com`, `micros0ft.com`) against high-profile brands.
   - **Structural Anomaly Detection**: Identifies Punycode (IDN) homoglyphs, raw IP address hosts, excessive subdomain nesting, and suspicious keyword combinations.
   - **Domain Age & RDAP**: Queries registration creation dates to flag freshly created phishing domains (<30 days old).
   - **Threat Intelligence**: Cross-references against Google Safe Browsing API v4 and local phishing signature blocklists.

4. **Transparent 0–100 Risk Scoring**:
   - **0–24 (Safe)**: No known risks or lookalike patterns detected.
   - **25–59 (Suspicious)**: Heuristic anomalies detected; proceed with caution.
   - **60–100 (Dangerous)**: Critical risks detected (HTTP login, confirmed phishing blocklist, or brand impersonation).

5. **Toolbar Popup, Audit Report, History & Settings**:
   - **Popup**: Instant risk meter, verdict pill, and quick scan actions.
   - **Audit Report**: Detailed breakdown of transport encryption, registration age, lookalike scores, and safety guidance.
   - **History**: Local scan log with search, filtering, JSON export, and single-click record deletion.
   - **Settings**: Whitelist management, auto-scan toggles, and optional backend proxy configuration.

---

## Installation (100% Free – No Developer Account Needed)

You do **not** need a paid Google Web Store developer account to run and test LoginGuard in your browser:

1. Open Google Chrome.
2. Navigate to `chrome://extensions/` in the address bar.
3. In the top-right corner, toggle **Developer mode** to **ON**.
4. Click the **Load unpacked** button in the top-left corner.
5. Select the project directory:
   ```
   C:\Users\NIRAJ PATIL\.gemini\antigravity\scratch\LoginGuard
   ```
6. Click the extension puzzle icon in the Chrome toolbar and pin **LoginGuard**.
7. Open `tests/demo-login.html` in Chrome or visit any login page to see LoginGuard trigger in real time.

---

## Project Structure

```
LoginGuard/
├── manifest.json              # Chrome Manifest V3 configuration
├── README.md                  # Documentation and architecture guide
├── LICENSE                    # MIT License
├── .gitignore                 # Version control exclusions
│
├── background/
│   └── service-worker.js      # Background service worker (pipeline orchestrator)
│
├── content/
│   ├── detector.js            # MutationObserver & password field detector
│   ├── overlay.js             # Shadow DOM floating security notification
│   └── content.css            # Overlay styles
│
├── popup/
│   ├── popup.html             # Toolbar popup dashboard
│   ├── popup.css              # Popup styling
│   └── popup.js               # Popup controller
│
├── report/
│   ├── report.html            # In-depth security audit page
│   ├── report.css             # Audit report styling
│   └── report.js              # Report controller
│
├── history/
│   ├── history.html           # Scan log with search and filters
│   ├── history.css            # History styling
│   └── history.js             # History management controller
│
├── settings/
│   ├── settings.html          # Configuration and whitelist page
│   ├── settings.css           # Settings styling
│   └── settings.js            # Settings controller
│
├── utils/
│   ├── domain-check.js        # Public suffix, IP, and structure parsing
│   ├── lookalike-detection.js # Levenshtein & brand impersonation engine
│   ├── scoring.js             # 0-100 risk scoring and verdict generation
│   ├── rdap.js                # Public RDAP client & domain age calculation
│   ├── phishing-check.js      # Safe Browsing & threat intelligence handler
│   └── storage.js             # chrome.storage.local wrapper
│
├── assets/
│   ├── icons/                 # 16px, 32px, 48px, 128px PNG extension icons
│   └── screenshots/           # UI previews (overlay, popup, report, history)
│
├── backend/
│   ├── package.json           # Express backend dependencies
│   ├── server.js              # Optional caching & API proxy server
│   ├── .env.example           # Environment template
│   └── README.md              # Backend documentation
│
└── tests/
    ├── domain.test.js         # Domain parsing and structural unit tests
    ├── lookalike.test.js      # Typosquatting and Levenshtein unit tests
    ├── scoring.test.js        # Risk scoring and whitelist unit tests
    ├── rdap.test.js           # RDAP parsing and threat signature unit tests
    ├── dynamic-spa.test.js    # SPA navigation & API failure tests
    └── demo-login.html        # Interactive test harness for manual verification
```

---

## Running the Automated Test Suite

LoginGuard includes a comprehensive automated test suite testing domain extraction, lookalike detection, risk scoring, RDAP parsing, and API failure handling.

To run the unit tests:
```bash
node --test tests/*.test.js
```

### Test Results
```
✔ Domain Extraction: Normal HTTPS login page
✔ Domain Extraction: Insecure HTTP login page
✔ Domain Extraction: Multi-part TLD parsing (.co.uk, .edu.in)
✔ IP Address Detection: Raw IPv4 and IPv6 hosts
✔ Punycode Detection: Internationalized homoglyphs
✔ Structural Suspicion: Long domains, hyphens, excessive subdomains
✔ API Failure Handling: Safe Browsing API handles unconfigured keys gracefully
✔ API Failure Handling: Backend proxy handles offline/unreachable servers gracefully
✔ API Failure Handling: Full phishing check continues without throwing when services fail
✔ RDAP Handling: Special and local hostnames are skipped without errors
✔ SPA & Dynamic Simulation: Route change tracking logic
✔ Levenshtein Distance: Basic edit calculations
✔ Character Substitution Normalization: Leetspeak & homoglyphs
✔ Lookalike Detection: Legitimate brand domains are passed
✔ Lookalike Detection: Impersonated domains flag with high penalty
✔ Lookalike Detection: Independent unbranded domains pass without false positives
✔ RDAP Parsing: Extracts registration date correctly from RDAP event arrays
✔ RDAP Domain Age: Calculates days from creation date
✔ RDAP Fallback: Missing or malformed events do not crash or produce false penalties
✔ Phishing Threat Signatures: Detects known blocklisted test signatures
✔ Scoring: Completely clean HTTPS domain yields SAFE verdict (Score 0)
✔ Scoring: Insecure HTTP login yields SUSPICIOUS (+30)
✔ Scoring: Confirmed phishing match always yields DANGEROUS (+70)
✔ Scoring: Lookalike + HTTP yields DANGEROUS (+65)
✔ Scoring: Cumulative score is strictly bounded at 100
✔ Scoring: Whitelisted domain suppresses heuristic warnings
✔ Scoring: Whitelist NEVER overrides confirmed phishing matches
ℹ tests 27 | pass 27 | fail 0
```

---

## Optional Backend Server

The extension is 100% functional standalone. If you wish to proxy Google Safe Browsing API calls or cache RDAP results:

```bash
cd backend
npm install
npm start
```
Configure `http://localhost:3000` in the extension's **Settings** page.

---

## Privacy Guarantee

- **No Credential Harvesting**: LoginGuard does not read form inputs or capture keystrokes.
- **Minimum Data Disclosure**: Only domain names and normalized URLs are audited.
- **Local-First**: All history and settings reside solely in your browser storage.
