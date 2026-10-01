# PhishGuard Backend

FastAPI backend for the PhishGuard URL Analysis Engine.

## Current Phase

Step 1 — URL Parsing

The current backend performs:

- URL validation
- Scheme extraction
- Username extraction
- Password extraction
- Subdomain extraction
- Hostname extraction
- Domain extraction
- Registrable domain extraction
- TLD extraction
- Port extraction
- Path extraction
- Query extraction
- Query parameter extraction
- Duplicate query parameter handling
- Fragment extraction
- IP address detection
- IPv4 support
- IPv6 support
- Basic URL normalization

External intelligence is NOT performed yet.

No WHOIS, DNS, IP geolocation, OSINT or threat scoring is performed in Step 1.

---

## Setup

Create a virtual environment:

```bash
python -m venv .venv