# PhishGuard Backend

FastAPI backend for PhishGuard URL analysis.

## Current analysis pipeline

1. URL parsing
2. DNS intelligence
3. IP intelligence and approximate network-level geolocation
4. WHOIS/RDAP
5. OSINT: PhishTank, URLhaus, and urlscan.io
6.1 URL structural security analysis
6.2 DNS security analysis
6.3 IP security analysis
6.4 WHOIS/RDAP security analysis
6.5 OSINT security analysis
6.6 Cross-source correlation
6.7 Final assessment

## Step 6

Step 6 converts the collected evidence into explainable findings. The individual security layers do not make network calls. They preserve provider/source evidence and distinguish direct threat-intelligence listings from historical or contextual observations.

The final assessment is intentionally transparent: absence of a finding is not presented as proof that a URL is universally safe, and provider coverage failures are treated as coverage limitations rather than maliciousness evidence.

## Setup

Create a virtual environment and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill provider keys as needed. `.env` is intentionally not distributed in the release archive.

## Run

```powershell
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health endpoint:

```text
GET http://127.0.0.1:8000/api/health
```

Analysis endpoint:

```text
POST http://127.0.0.1:8000/api/analysis
```

Example body:

```json
{
  "url": "https://example.com/login?token=test"
}
```

## Tests

```powershell
python -m pytest -q
```

The tests cover URL parsing, DNS, IP intelligence, WHOIS/RDAP, OSINT providers/services, urlscan evidence classification, all Step 6 analysis layers, cross-source correlation, final assessment, and the main analysis pipeline.


## Local frontend connection

The API allows loopback browser origins for local development. The bundled Vite frontend also proxies `/api` to `http://127.0.0.1:8000`, so local browser requests do not require cross-origin access.
