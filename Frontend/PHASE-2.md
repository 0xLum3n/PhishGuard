# PhishGuard — Phase 2 Analysis Dossier

The `/analysis` route now renders the real FastAPI analysis response rather than the older frontend-only threat model.

## Implemented

- URL decomposition: scheme, subdomain, domain, TLD, port, path, query separator, query parameters/values, fragment.
- Redaction of credential-bearing URL userinfo and common sensitive query parameter values.
- DNS intelligence: status, resolved IPs, hostname records, registrable-domain records.
- IP intelligence and approximate network geolocation: country, region, city, ASN, organization, timezone, coordinates.
- WHOIS/RDAP: registrar, registration/expiry/update dates, DNSSEC, status values, nameservers and redaction state.
- OSINT: provider-by-provider status, match counts, evidence and references.
- Security findings across URL, DNS, IP, WHOIS/RDAP, OSINT and cross-source correlation layers.
- Final assessment with verdict, confidence, summary, rationale, evidence and coverage.
- Direct PDF report download generated in-browser without an additional PDF dependency.
- Print-friendly report styling.
- Scanning progress labels aligned to actual backend pipeline stages.

## API contract

The frontend uses the current backend contract:

`POST /api/analysis`

with body:

```json
{"url":"https://example.com/"}
```

Local Vite development uses the `/api` proxy to the FastAPI service on port 8000, avoiding browser CORS preflight problems.

## Phase boundary

This phase focuses on the requested core URL analysis workflow. Competitive feature research and further product enhancements are intentionally left for a later phase.
