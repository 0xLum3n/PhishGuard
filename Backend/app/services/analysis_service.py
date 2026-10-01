from app.schemas.response import AnalysisResponse
from app.services.dns_service import DNSService
from app.services.ip_service import IPService
from app.services.url_parser import parse_url
from app.services.whois_service import WhoisService
from app.services.osint_service import OSINTService
from app.services.url_security_service import URLSecurityService
from app.services.dns_security_service import DNSSecurityService
from app.services.ip_security_service import IPSecurityService
from app.services.whois_security_service import WhoisSecurityService
from app.services.osint_security_service import OSINTSecurityService
from app.services.correlation_security_service import CorrelationSecurityService
from app.services.final_assessment_service import FinalAssessmentService


# =========================================================
# Shared services
# =========================================================

dns_service = DNSService()

ip_service = IPService()

whois_service = WhoisService()

osint_service = OSINTService()

url_security_service = URLSecurityService()
dns_security_service = DNSSecurityService()
ip_security_service = IPSecurityService()
whois_security_service = WhoisSecurityService()
osint_security_service = OSINTSecurityService()
correlation_security_service = CorrelationSecurityService()
final_assessment_service = FinalAssessmentService()


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
    # STEP 6.1 — URL STRUCTURAL SECURITY ANALYSIS
    # =====================================================

    security_result = url_security_service.analyze(
        parsed_url
    )

    # =====================================================
    # STEP 6.2 — DNS SECURITY ANALYSIS
    # =====================================================

    dns_security_result = dns_security_service.analyze(
        dns_result
    )

    # =====================================================
    # STEP 6.3 — IP SECURITY ANALYSIS
    # =====================================================

    ip_security_result = ip_security_service.analyze(
        ip_intelligence
    )

    # =====================================================
    # STEP 6.4 — WHOIS / RDAP SECURITY ANALYSIS
    # =====================================================

    whois_security_result = whois_security_service.analyze(
        whois_result
    )

    # =====================================================
    # STEP 6.5 — OSINT SECURITY ANALYSIS
    # =====================================================

    osint_security_result = osint_security_service.analyze(
        osint_result
    )

    # =====================================================
    # STEP 6.6 — CROSS-SOURCE CORRELATION
    # =====================================================

    correlation_security_result = correlation_security_service.analyze(
        url_parts=parsed_url,
        dns_result=dns_result,
        ip_result=ip_intelligence,
        whois_result=whois_result,
        osint_result=osint_result,
        url_security_result=security_result,
        dns_security_result=dns_security_result,
        ip_security_result=ip_security_result,
        whois_security_result=whois_security_result,
        osint_security_result=osint_security_result,
    )

    # =====================================================
    # STEP 6.7 — FINAL ASSESSMENT / DECISION
    # =====================================================

    final_assessment_result = final_assessment_service.analyze(
        osint_result=osint_result,
        url_security_result=security_result,
        dns_security_result=dns_security_result,
        ip_security_result=ip_security_result,
        whois_security_result=whois_security_result,
        osint_security_result=osint_security_result,
        correlation_security_result=correlation_security_result,
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

        # Existing Step 5
        osint=osint_result,

        # Step 6.1
        security=security_result,

        # Step 6.2
        dns_security=dns_security_result,

        # Step 6.3
        ip_security=ip_security_result,

        # Step 6.4
        whois_security=whois_security_result,

        # Step 6.5
        osint_security=osint_security_result,

        # Step 6.6
        correlation_security=correlation_security_result,

        # Step 6.7
        final_assessment=final_assessment_result,
    )