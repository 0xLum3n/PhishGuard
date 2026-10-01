# PhishGuard — Phase 2.1 Dynamic Analysis Report

This phase replaces the previous static/partial report presentation with a live data-driven `/analysis` report.

## Report structure

1. **URL — All Parts** — renders the complete `url` response object plus URL security findings.
2. **DNS Information** — renders the complete `dns` response object plus DNS security findings.
3. **IP Information & Geolocation** — renders the complete `ip_intelligence` object plus IP security findings.
4. **WHOIS / RDAP Information** — renders the complete `whois` object plus WHOIS security findings.
5. **OSINT — In Depth** — renders the complete `osint` object plus OSINT security findings.

Each panel uses the live JSON returned by `POST /api/analysis`. There are no hard-coded hostname, IP, provider, domain age, match-count, threat-score, or confidence values in the report.

## Risk index

The backend now returns `final_assessment.risk_score`, `risk_score_version`, and `risk_factors`.

`risk_score` is a deterministic evidence-derived visualization index from 0–100. It is **not** a probability. The frontend animates the circular gauge and contribution bars from these returned values.

The backend score implementation is versioned as `evidence-v1` so it can be changed later without silently changing the meaning of historical reports.

## Privacy

The UI recursively redacts URL passwords, authorization-style fields, API keys/secrets, and values belonging to sensitive query parameters before rendering the complete response payload.

## Validation in this environment

- Backend Python compilation: passed.
- Backend final-assessment smoke checks: passed for clean, suspicious, and URLhaus-confirmed evidence cases.
- App.tsx / main.tsx TypeScript transpilation: passed.
- Full dependency-backed Vite production build was not executed because frontend dependencies are not installed in the isolated build environment.
