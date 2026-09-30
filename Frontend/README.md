# PhishGuard

PhishGuard is a React/Vite URL-analysis interface backed by a FastAPI enrichment service.

## What `/analysis` now does

The analysis workflow no longer fabricates WHOIS/domain-age/IP/OSINT values in the browser. The page:

- parses the URL into scheme, subdomain, domain, TLD, port, path, query string, query parameters/values, and fragment;
- sends the normalized URL to the FastAPI backend for live DNS/IP/RDAP/OSINT enrichment;
- displays resolved IP addresses and geolocation/ASN data when the provider returns it;
- displays RDAP registration data rather than hard-coded registrar or creation dates;
- performs passive OSINT pivots such as DNS/subdomain, reverse-IP, and public urlscan sightings;
- supports optional PhishTank, URLhaus, VirusTotal, and AbuseIPDB enrichment through backend-only API keys;
- clearly marks unavailable/rate-limited sources instead of replacing them with static values;
- never loads the submitted URL as a webpage.

## Run the project

### Frontend

```powershell
npm install
copy .env.example .env
npm run dev
```

For the local Vite preview, leave `VITE_API_BASE_URL` empty. Vite proxies same-origin `/api/*` requests to FastAPI, which also avoids HTTPS→HTTP mixed-content blocks. When the backend is deployed separately, set `VITE_API_BASE_URL` to its HTTPS origin.

### Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
copy .env.example .env
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Then start the frontend normally. Keep the FastAPI service running on port 8000 so Vite can proxy `/api/analyze` to it.

## Free/public data sources used by the baseline

RDAP.org is used for registration data. ipapi.co is used for IP geolocation. HackerTarget is used for DNS and passive infrastructure pivots. urlscan.io search is used for existing public scan sightings. Optional threat-intelligence providers can be enabled from `backend/.env`.

Provider quotas, terms, attribution requirements, and key requirements are external to PhishGuard and can change; review the provider documentation before a public/commercial deployment.
