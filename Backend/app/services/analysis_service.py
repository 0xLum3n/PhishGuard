from app.schemas.response import AnalysisResponse
from app.services.dns_service import DNSService
from app.services.ip_service import IPService
from app.services.url_parser import parse_url
from app.services.whois_service import WhoisService
from app.services.osint_service import OSINTService


# =========================================================
# Shared services
# =========================================================

dns_service = DNSService()

ip_service = IPService()

whois_service = WhoisService()

osint_service = OSINTService()


# =========================================================
# URL ANALYSIS
# =========================================================

async def analyze_url(
    url: str,
) -> AnalysisResponse:

    # =====================================================
    # STEP 1 — URL parsing
    # =====================================================

    parsed_url = parse_url(
        url
    )

    # =====================================================
    # STEP 2 — DNS
    # =====================================================

    dns_result = await dns_service.lookup(
        hostname=parsed_url.hostname,
        registrable_domain=(
            parsed_url.registrable_domain
        ),
    )

    # =====================================================
    # STEP 3 — IP intelligence
    # =====================================================

    ip_intelligence = (
        await ip_service.lookup_many(
            dns_result.resolved_ips
        )
    )

    # =====================================================
    # STEP 4 — WHOIS / RDAP
    # =====================================================

    whois_result = await whois_service.lookup(
        parsed_url.registrable_domain
    )

    # =====================================================
    # STEP 5 — OSINT
    # =====================================================

    osint_result = await osint_service.lookup(
        url=parsed_url.original,
        domain=parsed_url.registrable_domain,
    )

    # =====================================================
    # FINAL RESPONSE
    # =====================================================

    return AnalysisResponse(
        success=True,

        # Existing Step 1
        url=parsed_url,

        # Existing Step 2
        dns=dns_result,

        # Existing Step 3
        ip_intelligence=ip_intelligence,

        # Existing Step 4
        whois=whois_result,

        # New Step 5
        osint=osint_result,
    )