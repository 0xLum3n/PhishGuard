# PhishGuard FastAPI enrichment backend

The frontend can parse the URL structure by itself, but WHOIS/RDAP, DNS resolution, IP geolocation and passive OSINT are better performed server-side. This service provides `POST /api/analyze` and never opens the submitted destination URL as a webpage.

## Start

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
copy .env.example .env
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

For the local Vite preview, do not set `VITE_API_BASE_URL`. The frontend calls same-origin `/api/analyze`, and Vite proxies that request to FastAPI on port 8000.

```powershell
npm run dev
```

The backend uses RDAP.org for registration data, ipapi.co for IP geolocation, HackerTarget for basic DNS/passive OSINT, urlscan.io search for public sightings, and optional provider keys for PhishTank, URLhaus, VirusTotal and AbuseIPDB.

## Provider notes

PhishTank's simple API is POST-based and allows an optional application key. URLhaus's community API is free under fair-use rules but requires an Auth-Key. VirusTotal's public API requires an API key and is rate-limited; its public API also has usage restrictions for commercial products. AbuseIPDB requires an API key for the `/check` endpoint. These keys belong only in `.env` on the backend.

## Production

Set `FRONTEND_ORIGINS` to your real frontend origin(s), keep API keys out of source control, add request rate limiting/caching, and persist scan records to Supabase separately from the enrichment calls. For a public deployment, do not allow arbitrary high-frequency scans without quotas.
