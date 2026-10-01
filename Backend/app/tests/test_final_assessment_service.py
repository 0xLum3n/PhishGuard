from app.schemas.response import (
    OSINTMatch,
    OSINTProviderResult,
    OSINTResult,
    SecurityFinding,
    URLSecurityResult,
)
from app.services.final_assessment_service import FinalAssessmentService


service = FinalAssessmentService()


def test_urlhaus_match_produces_confirmed_threat_evidence():
    result = service.analyze(
        osint_result=OSINTResult(
            status="completed",
            providers=[
                OSINTProviderResult(
                    source="URLhaus",
                    status="success",
                    query="https://example.com/payload",
                    matched=True,
                    match_count=1,
                    matches=[
                        OSINTMatch(
                            source="URLhaus",
                            match_type="malware_url",
                            indicator="https://example.com/payload",
                            reference="https://urlhaus.abuse.ch/url/1/",
                            details={
                                "url_status": "online",
                            },
                        )
                    ],
                )
            ],
        )
    )

    assert result.verdict == "confirmed_threat_evidence"
    assert result.risk_score >= 50
    assert result.risk_score_version == "evidence-v1"
    assert result.confidence == "medium"
    assert "URLhaus" in result.evidence_summary["direct_threat_intel"]["sources"]


def test_verified_valid_phishtank_match_produces_confirmed_threat_evidence():
    result = service.analyze(
        osint_result=OSINTResult(
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
                            reference="https://phishtank.org/phish_detail.php?phish_id=1",
                            details={
                                "verified": True,
                                "valid": True,
                            },
                        )
                    ],
                )
            ],
        )
    )

    assert result.verdict == "confirmed_threat_evidence"
    assert result.confidence == "high"


def test_phishtank_unverified_listing_alone_does_not_confirm_threat():
    result = service.analyze(
        osint_result=OSINTResult(
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
                            details={
                                "verified": False,
                                "valid": False,
                            },
                        )
                    ],
                ),
                OSINTProviderResult(
                    source="URLhaus",
                    status="no_match",
                    query="https://example.com/login",
                ),
            ],
        )
    )

    assert result.verdict == "no_significant_evidence"


def test_actionable_findings_produce_suspicious_indicators():
    finding = SecurityFinding(
        rule_id="TEST-HIGH",
        category="url-structure",
        title="Test high finding",
        severity="high",
        confidence="high",
        description="test",
    )

    result = service.analyze(
        osint_result=OSINTResult(
            status="completed",
            providers=[
                OSINTProviderResult(
                    source="URLhaus",
                    status="no_match",
                    query="https://example.com",
                )
            ],
        ),
        url_security_result=URLSecurityResult(
            status="completed",
            total_findings=1,
            findings=[finding],
        ),
    )

    assert result.verdict == "suspicious_indicators"
    assert result.risk_score >= 15
    assert result.confidence == "high"


def test_no_findings_with_provider_coverage_produces_no_significant_evidence():
    result = service.analyze(
        osint_result=OSINTResult(
            status="completed",
            providers=[
                OSINTProviderResult(
                    source="URLhaus",
                    status="no_match",
                    query="https://example.com",
                ),
                OSINTProviderResult(
                    source="PhishTank",
                    status="success",
                    query="https://example.com",
                    matched=False,
                ),
            ],
        )
    )

    assert result.verdict == "no_significant_evidence"
    assert result.confidence == "medium"


def test_no_provider_coverage_produces_inconclusive():
    result = service.analyze(
        osint_result=OSINTResult(
            status="not_configured",
            providers=[
                OSINTProviderResult(
                    source="URLhaus",
                    status="not_configured",
                    query="https://example.com",
                    error="not configured",
                ),
                OSINTProviderResult(
                    source="PhishTank",
                    status="not_configured",
                    query="https://example.com",
                    error="not configured",
                ),
            ],
        )
    )

    assert result.verdict == "inconclusive"
    assert result.confidence == "low"
