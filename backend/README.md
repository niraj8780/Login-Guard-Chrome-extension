# LoginGuard Backend Service

A lightweight, optional caching and threat-intelligence proxy server for the LoginGuard Chrome Extension.

## Features

- **Google Safe Browsing Proxy**: Keeps private API keys secure on your server rather than distributing them in extension code.
- **RDAP Caching**: Caches WHOIS/RDAP responses in memory to prevent rate limits and speed up client lookups.
- **Built-in Rate Limiting**: Protects against query flooding (120 req/minute per IP).
- **Anonymized Metrics**: Tracks scan counts and threat detections without recording personal user information.
- **Zero Frontend Dependency**: The LoginGuard Chrome Extension runs 100% independently if this server is offline.

## Setup Instructions

### 1. Install Dependencies
```bash
cd backend
npm install
```

### 2. Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Optionally add your Google Cloud Safe Browsing API key:
```env
SAFE_BROWSING_API_KEY=AIzaSy...
PORT=3000
```

### 3. Start the Server
```bash
npm start
```
The server will start on `http://localhost:3000`.

### 4. Connect to Chrome Extension
1. Open the LoginGuard extension in Chrome.
2. Click the gear icon to open **Settings**.
3. Under **External Threat Intelligence APIs**, set the **Custom Backend Proxy URL** to `http://localhost:3000`.
4. Click **Test Connection** to verify connectivity, then click **Save Changes**.

## API Endpoints

- `GET /api/health` - Service health and uptime.
- `GET /api/stats` - Anonymized scan counters.
- `POST /api/rdap` - Cached RDAP lookup for `{ domain: "example.com" }`.
- `POST /api/safebrowsing` - Proxied Google Safe Browsing v4 lookup for `{ url: "https://..." }`.
- `POST /api/check-domain` - Combined threat intelligence check for `{ url: "...", domain: "..." }`.
