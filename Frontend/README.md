# PhishGuard Frontend — API Integration Fixed

This frontend is wired to the current PhishGuard FastAPI backend.

## Backend contract

The URL analysis request is sent to:

`POST /api/analysis` (proxied by Vite to `http://127.0.0.1:8000` in local development)

Request body:

```json
{
  "url": "https://example.com"
}
```

## Run

1. Make sure the FastAPI backend is running on port `8000`.
2. Install frontend dependencies:

```bash
npm install
```

3. (Optional) create `.env` from `.env.example`. Leave `VITE_API_BASE_URL` empty for local Vite development; set it to the backend origin only when the frontend is hosted separately.
4. Start Vite:

```bash
npm run dev
```

The frontend will use:

`$VITE_API_BASE_URL/api/analysis`

with `http://127.0.0.1:8000` as the default base URL.

## What was fixed in this stage

- Corrected the analysis endpoint from `/analysis` to `/api/analysis`.
- Updated the frontend response adapter to the backend's real `AnalysisResponse` shape.
- Wired the final assessment, DNS, IP intelligence, RDAP/WHOIS, OSINT, and security findings into the existing analysis view.
- Removed the dependency on the old `raw.analysis.*` response contract.
- Added environment-based backend URL configuration.
- Kept URL credentials and known sensitive query parameters masked in the displayed URL.
- Preserved the existing visual design and navigation.

The current backend does not return a numeric 0–100 threat score, entropy, typosquatting, or homoglyph result in `AnalysisResponse`, so this frontend no longer invents a threat score. Those parts will be handled against the actual backend contract in the later analysis-page stages.
