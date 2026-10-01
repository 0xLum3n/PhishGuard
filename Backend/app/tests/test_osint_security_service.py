from app.schemas.response import (
    OSINTMatch,
    OSINTProviderResult,
    OSINTResult,
)
from app.services.osint_security_service import OSINTSecurityService


service = OSINTSecurityService()


def _ids(result):
    return {finding.rule_id for finding in result.findings}


def test_phishtank_exact_match_creates_high_confidence_finding():
    result = service.analyze(
        OSINTResult(
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
                                "phish_id": "1",
                                "verified": True,
                                "valid": True,
                            },
                        )
                    ],
                )
            ],
        )
    )

    finding = next(
        item
        for item in result.findings
        if item.rule_id == "OSINT-PHISHTANK-MATCH"
    )

    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert finding.evidence["match_count"] == 1


def test_urlhaus_match_is_distinguished_from_phishtank():
    result = service.analyze(
        OSINTResult(
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
                                "threat": "malware_download",
                                "tags": ["test"],
                            },
                        )
                    ],
                )
            ],
        )
    )

    assert "OSINT-URLHAUS-MATCH" in _ids(result)
    assert "OSINT-PHISHTANK-MATCH" not in _ids(result)


def test_urlscan_exact_and_hostname_are_contextual_findings():
    result = service.analyze(
        OSINTResult(
            status="completed",
            providers=[
                OSINTProviderResult(
                    source="urlscan.io",
                    status="success",
                    query="example.com",
                    matched=True,
                    match_count=2,
                    matches=[
                        OSINTMatch(
                            source="urlscan.io",
                            match_type="exact_url",
                            indicator="https://example.com",
                            reference="https://urlscan.io/result/exact/",
                            details={
                                "task_url": "https://example.com",
                                "page_domain": "example.net",
                            },
                        ),
                        OSINTMatch(
                            source="urlscan.io",
                            match_type="exact_hostname",
                            indicator="https://example.com/account",
                            reference="https://urlscan.io/result/host/",
                            details={
                                "task_url": "https://example.com/account",
                                "task_domain": "example.com",
                            },
                        ),
                    ],
                    metadata={
                        "page_domain_observations": [
                            {
                                "task_url": "https://attacker.example/",
                                "page_domain": "example.com",
                            }
                        ]
                    },
                )
            ],
        )
    )

    ids = _ids(result)

    assert "OSINT-URLSCAN-EXACT-URL" in ids
    assert "OSINT-URLSCAN-EXACT-HOSTNAME" in ids
    assert "OSINT-URLSCAN-PAGE-DOMAIN" not in ids

    exact_url = next(
        item
        for item in result.findings
        if item.rule_id == "OSINT-URLSCAN-EXACT-URL"
    )
    assert exact_url.severity == "info"


def test_page_domain_observation_does_not_create_match_finding():
    result = service.analyze(
        OSINTResult(
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
                                "task_url": "https://attacker.example/",
                                "page_domain": "example.com",
                            }
                        ]
                    },
                )
            ],
        )
    )

    assert result.total_findings == 0
    assert result.findings == []
    assert any(
        "resulting-page domain observations" in observation
        for observation in result.observations
    )


def test_provider_failure_is_coverage_context_only():
    result = service.analyze(
        OSINTResult(
            status="partial",
            providers=[
                OSINTProviderResult(
                    source="URLhaus",
                    status="rate_limited",
                    query="https://example.com",
                    error="rate limited",
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

    ids = _ids(result)

    assert "OSINT-RATE-LIMITED" in ids
    assert "OSINT-PARTIAL-COVERAGE" in ids
    assert "OSINT-URLHAUS-MATCH" not in ids
