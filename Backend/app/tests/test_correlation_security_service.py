from app.schemas.response import (
    DNSResult,
    IPIntelligence,
    IPIntelligenceResponse,
    OSINTMatch,
    OSINTProviderResult,
    OSINTResult,
    URLParts,
    WhoisResult,
)
from app.services.correlation_security_service import CorrelationSecurityService


def _url_parts() -> URLParts:
    return URLParts(
        original="https://example.com/login",
        normalized="https://example.com/login",
        scheme="https",
        hostname="example.com",
        path="/login",
        registrable_domain="example.com",
        domain="example",
        tld="com",
    )


def _dns() -> DNSResult:
    return DNSResult(
        hostname="example.com",
        registrable_domain="example.com",
        status="resolved",
        resolved_ips=["1.2.3.4", "5.6.7.8"],
        hostname_records={},
        domain_records={},
        hostname_txt_records=None,
        records={},
    )


def _ip() -> IPIntelligenceResponse:
    return IPIntelligenceResponse(
        status="completed",
        total_ips=2,
        public_ips=2,
        enriched_ips=2,
        lookup_limit=5,
        limit_reached=False,
        results=[
            IPIntelligence(
                ip="1.2.3.4",
                version=4,
                classification="public",
                status="success",
                country_code="US",
            ),
            IPIntelligence(
                ip="5.6.7.8",
                version=4,
                classification="public",
                status="success",
                country_code="DE",
            ),
        ],
    )


def test_multi_source_exact_url_correlation():
    osint = OSINTResult(
        status="completed",
        providers=[
            OSINTProviderResult(
                source="PhishTank",
                status="success",
                query="https://example.com/login",
                matched=True,
                match_count=1,
                matches=[
                    OSINTMatch(
                        source="PhishTank",
                        match_type="exact_url",
                        indicator="https://example.com/login",
                        reference="https://phishtank.test/1",
                    )
                ],
            ),
            OSINTProviderResult(
                source="URLhaus",
                status="success",
                query="https://example.com/login",
                matched=True,
                match_count=1,
                matches=[
                    OSINTMatch(
                        source="URLhaus",
                        match_type="malware_url",
                        indicator="https://example.com/login",
                        reference="https://urlhaus.test/1",
                    )
                ],
            ),
        ],
    )

    result = CorrelationSecurityService().analyze(
        url_parts=_url_parts(),
        dns_result=_dns(),
        ip_result=_ip(),
        whois_result=None,
        osint_result=osint,
    )

    ids = {finding.rule_id for finding in result.findings}

    assert "CORR-MULTI-SOURCE-EXACT-URL" in ids
    assert "CORR-PHISHTANK-URLHAUS" in ids
    assert "CORR-DNS-MULTI-IP" in ids
    assert "CORR-IP-MULTI-COUNTRY" in ids


def test_urlscan_redirect_is_context_not_exact_mismatch():
    osint = OSINTResult(
        status="completed",
        providers=[
            OSINTProviderResult(
                source="urlscan.io",
                status="success",
                query="example.com",
                matched=True,
                match_count=1,
                matches=[
                    OSINTMatch(
                        source="urlscan.io",
                        match_type="exact_url",
                        indicator="https://example.com/login",
                        reference="https://urlscan.test/1",
                        details={
                            "task_url": "https://example.com/login",
                            "task_domain": "example.com",
                            "page_url": "https://other.example.net/",
                            "page_domain": "other.example.net",
                            "page_redirected": True,
                        },
                    )
                ],
            )
        ],
    )

    result = CorrelationSecurityService().analyze(
        url_parts=_url_parts(),
        dns_result=_dns(),
        ip_result=_ip(),
        whois_result=None,
        osint_result=osint,
    )

    redirect = next(
        finding
        for finding in result.findings
        if finding.rule_id == "CORR-URLSCAN-REDIRECT-CONTEXT"
    )

    assert redirect.severity == "info"
    assert redirect.evidence["observation_count"] == 1


def test_no_unrelated_page_domain_is_treated_as_exact_hostname():
    osint = OSINTResult(
        status="completed",
        providers=[
            OSINTProviderResult(
                source="urlscan.io",
                status="success",
                query="example.com",
                matched=False,
                match_count=0,
                matches=[],
                metadata={
                    "page_domain_observations": [
                        {
                            "task_url": "https://other.example.net/",
                            "task_domain": "other.example.net",
                            "page_domain": "example.com",
                        }
                    ]
                },
            )
        ],
    )

    result = CorrelationSecurityService().analyze(
        url_parts=_url_parts(),
        dns_result=_dns(),
        ip_result=_ip(),
        whois_result=None,
        osint_result=osint,
    )

    assert all(
        finding.rule_id != "CORR-URLSCAN-URL-HOSTNAME"
        for finding in result.findings
    )


def test_recent_registration_plus_osint_correlation():
    osint = OSINTResult(
        status="completed",
        providers=[
            OSINTProviderResult(
                source="URLhaus",
                status="success",
                query="https://example.com/login",
                matched=True,
                match_count=1,
                matches=[
                    OSINTMatch(
                        source="URLhaus",
                        match_type="malware_url",
                        indicator="https://example.com/login",
                        reference="https://urlhaus.test/1",
                    )
                ],
            )
        ],
    )

    whois = WhoisResult(
        domain="example.com",
        status="success",
        registration_date="2026-09-20T00:00:00Z",
    )

    from app.schemas.response import WhoisSecurityResult, SecurityFinding

    whois_security = WhoisSecurityResult(
        status="completed",
        findings=[
            SecurityFinding(
                rule_id="WHOIS-RECENTLY-REGISTERED",
                category="whois-lifecycle",
                title="Domain was registered recently",
                severity="medium",
                confidence="high",
                description="test",
            )
        ],
    )

    result = CorrelationSecurityService().analyze(
        url_parts=_url_parts(),
        dns_result=_dns(),
        ip_result=_ip(),
        whois_result=whois,
        osint_result=osint,
        whois_security_result=whois_security,
    )

    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "CORR-RECENT-DOMAIN-OSINT"
    )

    assert finding.severity == "medium"
    assert finding.evidence["osint_sources"] == ["URLhaus"]
