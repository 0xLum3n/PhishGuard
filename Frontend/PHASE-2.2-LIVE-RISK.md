# Phase 2.2 — Live Risk Visualization

The `/analysis` page now renders the risk gauge and evidence graph exclusively from the live FastAPI response.

## Backend changes
- Added `risk_dimensions` to `final_assessment`.
- Added `risk_events` containing the top weighted live contributors.
- Upgraded the evidence index to `evidence-v2`.
- Risk dimensions are calculated from URL, DNS, IP/geolocation, WHOIS/RDAP, OSINT and cross-source evidence returned by the current scan.
- Direct OSINT matches are scored explicitly and are not double-counted as generic OSINT findings.
- Informational findings do not add risk points.

## Frontend changes
- Circular gauge animates from zero to the backend-returned score whenever a new scan completes.
- Live evidence distribution bars animate from zero to each backend-returned dimension.
- Top risk contributors are rendered from backend `risk_events`.
- Complete risk-engine payload can be expanded from the report.
- No fixture/demo risk numbers are used by the report.
