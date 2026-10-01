import pytest

from app.schemas.response import (
    AnalysisResponse,
    IPIntelligenceResponse,
    OSINTResult,
    URLParts,
)
from app.services import analysis_service


class FakeDNSService:
    async def lookup(self, hostname, registrable_domain):
        from app.schemas.response import DNSResult

        return DNSResult(
            hostname=hostname,
            registrable_domain=registrable_domain,
            status="resolved",
            resolved_ips=[],
            hostname_records={},
            domain_records={},
            hostname_txt_records=None,
            records={},
        )


class FakeIPService:
    async def lookup_many(self, ips):
        return IPIntelligenceResponse(
            status="no_public_ips",
            total_ips=0,
            public_ips=0,
            enriched_ips=0,
            lookup_limit=5,
            limit_reached=False,
            results=[],
        )


class FakeWhoisService:
    async def lookup(self, domain):
        return None


class FakeOSINTService:
    async def lookup(self, url, domain):
        return OSINTResult(status="no_matches")


class FakeSecurityService:
    def analyze(self, value):
        from app.schemas.response import URLSecurityResult

        return URLSecurityResult(status="completed")


class FakeDNSSecurityService:
    def analyze(self, value):
        from app.schemas.response import DNSSecurityResult

        return DNSSecurityResult(status="completed")


class FakeIPSecurityService:
    def analyze(self, value):
        from app.schemas.response import IPSecurityResult

        return IPSecurityResult(status="completed")


class FakeWhoisSecurityService:
    def analyze(self, value):
        from app.schemas.response import WhoisSecurityResult

        return WhoisSecurityResult(status="completed")


class FakeOSINTSecurityService:
    def analyze(self, value):
        from app.schemas.response import OSINTSecurityResult

        return OSINTSecurityResult(
            status="completed",
            total_findings=1,
        )


class FakeCorrelationSecurityService:
    def analyze(self, **kwargs):
        from app.schemas.response import CorrelationSecurityResult

        return CorrelationSecurityResult(
            status="completed",
            total_findings=2,
        )


class FakeFinalAssessmentService:
    def analyze(self, **kwargs):
        from app.schemas.response import FinalAssessmentResult

        return FinalAssessmentResult(
            status="completed",
            verdict="no_significant_evidence",
            confidence="medium",
            summary="test",
        )


@pytest.mark.anyio
async def test_analysis_pipeline_includes_osint_security(monkeypatch):
    parsed = URLParts(
        original="https://example.com",
        normalized="https://example.com",
        scheme="https",
        hostname="example.com",
        path="/",
        registrable_domain="example.com",
        domain="example",
        tld="com",
    )

    monkeypatch.setattr(
        analysis_service,
        "parse_url",
        lambda url: parsed,
    )
    monkeypatch.setattr(
        analysis_service,
        "dns_service",
        FakeDNSService(),
    )
    monkeypatch.setattr(
        analysis_service,
        "ip_service",
        FakeIPService(),
    )
    monkeypatch.setattr(
        analysis_service,
        "whois_service",
        FakeWhoisService(),
    )
    monkeypatch.setattr(
        analysis_service,
        "osint_service",
        FakeOSINTService(),
    )
    monkeypatch.setattr(
        analysis_service,
        "url_security_service",
        FakeSecurityService(),
    )
    monkeypatch.setattr(
        analysis_service,
        "dns_security_service",
        FakeDNSSecurityService(),
    )
    monkeypatch.setattr(
        analysis_service,
        "ip_security_service",
        FakeIPSecurityService(),
    )
    monkeypatch.setattr(
        analysis_service,
        "whois_security_service",
        FakeWhoisSecurityService(),
    )
    monkeypatch.setattr(
        analysis_service,
        "osint_security_service",
        FakeOSINTSecurityService(),
    )
    monkeypatch.setattr(
        analysis_service,
        "correlation_security_service",
        FakeCorrelationSecurityService(),
    )

    monkeypatch.setattr(
        analysis_service,
        "final_assessment_service",
        FakeFinalAssessmentService(),
    )

    result = await analysis_service.analyze_url(
        "https://example.com"
    )

    assert isinstance(result, AnalysisResponse)
    assert result.osint_security is not None
    assert result.osint_security.total_findings == 1
    assert result.correlation_security is not None
    assert result.correlation_security.total_findings == 2
    assert result.final_assessment is not None
    assert result.final_assessment.verdict == "no_significant_evidence"
