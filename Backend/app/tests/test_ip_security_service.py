from app.schemas.response import (
    IPIntelligence,
    IPIntelligenceResponse,
)
from app.services.ip_security_service import IPSecurityService


service = IPSecurityService()


def _result_ids(response: IPIntelligenceResponse) -> set[str]:
    analyzed = service.analyze(response)
    return {finding.rule_id for finding in analyzed.findings}


def _ip(
    address: str,
    *,
    version: int = 4,
    classification: str = "public",
    status: str = "success",
    country_code: str | None = None,
) -> IPIntelligence:
    return IPIntelligence(
        ip=address,
        version=version,
        classification=classification,
        status=status,
        source="ipapi.co",
        country_code=country_code,
    )


def test_special_use_ip_is_detected():
    response = IPIntelligenceResponse(
        status="completed",
        total_ips=1,
        public_ips=0,
        enriched_ips=0,
        lookup_limit=5,
        results=[
            _ip(
                "10.0.0.1",
                classification="private",
                status="private",
            )
        ],
    )

    assert "IP-SPECIAL-USE" in _result_ids(response)


def test_multiple_public_ips_are_detected_as_context():
    response = IPIntelligenceResponse(
        status="completed",
        total_ips=2,
        public_ips=2,
        enriched_ips=2,
        lookup_limit=5,
        results=[
            _ip("203.0.113.10"),
            _ip("203.0.113.11"),
        ],
    )

    assert "IP-MULTIPLE-PUBLIC" in _result_ids(response)


def test_dual_stack_is_detected():
    response = IPIntelligenceResponse(
        status="completed",
        total_ips=2,
        public_ips=2,
        enriched_ips=2,
        lookup_limit=5,
        results=[
            _ip("203.0.113.10", version=4),
            _ip("2001:db8::10", version=6),
        ],
    )

    assert "IP-DUAL-STACK" in _result_ids(response)


def test_public_lookup_failure_is_detected():
    response = IPIntelligenceResponse(
        status="partial",
        total_ips=1,
        public_ips=1,
        enriched_ips=0,
        lookup_limit=5,
        results=[
            _ip(
                "203.0.113.10",
                status="timeout",
            )
        ],
    )

    assert "IP-LOOKUP-FAILURE" in _result_ids(response)


def test_rate_limit_is_separated_from_generic_lookup_failure():
    response = IPIntelligenceResponse(
        status="partial",
        total_ips=1,
        public_ips=1,
        enriched_ips=0,
        lookup_limit=5,
        results=[
            _ip(
                "203.0.113.10",
                status="rate_limited",
            )
        ],
    )

    ids = _result_ids(response)

    assert "IP-LOOKUP-FAILURE" in ids
    assert "IP-RATE-LIMITED" in ids


def test_multiple_countries_are_detected_as_context():
    response = IPIntelligenceResponse(
        status="completed",
        total_ips=2,
        public_ips=2,
        enriched_ips=2,
        lookup_limit=5,
        results=[
            _ip("203.0.113.10", country_code="US"),
            _ip("203.0.113.11", country_code="IN"),
        ],
    )

    assert "IP-MULTI-COUNTRY-CONTEXT" in _result_ids(response)


def test_empty_ip_result_is_observation_only():
    analyzed = service.analyze(
        IPIntelligenceResponse(
            status="no_public_ips",
            total_ips=0,
            public_ips=0,
            enriched_ips=0,
            lookup_limit=5,
            results=[],
        )
    )

    assert analyzed.status == "completed"
    assert analyzed.total_findings == 0
    assert analyzed.observations
