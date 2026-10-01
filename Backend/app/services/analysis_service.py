from app.schemas.response import AnalysisResponse
from app.services.dns_service import DNSService
from app.services.ip_service import IPService
from app.services.url_parser import parse_url
from app.services.whois_service import WhoisService


# =========================================================
# Shared services
# =========================================================

dns_service = DNSService()

ip_service = IPService()

whois_service = WhoisService()


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
        registrable_domain=parsed_url.registrable_domain,
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
    #
    # IMPORTANT:
    #
    # We use the registrable domain rather than the full
    # hostname.
    #
    # www.example.com
    #        ↓
    # example.com
    #
    # This is the registration object we want.
    # =====================================================

    whois_result = await whois_service.lookup(
        parsed_url.registrable_domain
    )

    # =====================================================
    # FINAL RESPONSE
    # =====================================================

    return AnalysisResponse(
        success=True,

        url=parsed_url,

        dns=dns_result,

        ip_intelligence=ip_intelligence,

        whois=whois_result,
    )