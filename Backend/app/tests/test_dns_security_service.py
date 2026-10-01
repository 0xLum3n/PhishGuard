from app.schemas.response import (
    DNSRecordResult,
    DNSResult,
)
from app.services.dns_security_service import DNSSecurityService


service = DNSSecurityService()


def _result_ids(result: DNSResult) -> set[str]:
    analyzed = service.analyze(result)
    return {finding.rule_id for finding in analyzed.findings}


def _record(
    record_type: str,
    status: str,
    name: str,
    records: list[str] | None = None,
    error: str | None = None,
) -> DNSRecordResult:
    return DNSRecordResult(
        record_type=record_type,
        queried_name=name,
        status=status,
        records=records or [],
        error=error,
    )


def test_nxdomain_is_detected():
    result = DNSResult(
        hostname="missing.example",
        registrable_domain="example",
        status="nxdomain",
        hostname_records={
            "A": _record("A", "nxdomain", "missing.example"),
            "AAAA": _record("AAAA", "nxdomain", "missing.example"),
            "CNAME": _record("CNAME", "nxdomain", "missing.example"),
        },
        domain_records={},
        records={},
    )

    assert "DNS-NXDOMAIN" in _result_ids(result)


def test_no_data_is_detected():
    result = DNSResult(
        hostname="empty.example",
        registrable_domain="example",
        status="no_data",
        hostname_records={
            "A": _record("A", "no_answer", "empty.example"),
            "AAAA": _record("AAAA", "no_answer", "empty.example"),
            "CNAME": _record("CNAME", "no_answer", "empty.example"),
        },
        domain_records={},
        records={},
    )

    assert "DNS-NO-DATA" in _result_ids(result)


def test_partial_dns_failure_is_detected():
    result = DNSResult(
        hostname="partial.example",
        registrable_domain="example",
        status="partial",
        resolved_ips=["192.0.2.10"],
        hostname_records={
            "A": _record("A", "success", "partial.example", ["192.0.2.10"]),
            "AAAA": _record(
                "AAAA",
                "timeout",
                "partial.example",
                error="timeout",
            ),
        },
        domain_records={},
        records={},
    )

    assert "DNS-PARTIAL" in _result_ids(result)


def test_multiple_a_records_are_detected_as_context():
    result = DNSResult(
        hostname="multi.example",
        registrable_domain="example",
        status="resolved",
        resolved_ips=["192.0.2.10", "192.0.2.11"],
        hostname_records={
            "A": _record(
                "A",
                "success",
                "multi.example",
                ["192.0.2.10", "192.0.2.11"],
            ),
        },
        domain_records={},
        records={},
    )

    analyzed = service.analyze(result)
    finding = next(
        finding
        for finding in analyzed.findings
        if finding.rule_id == "DNS-MULTIPLE-A"
    )

    assert finding.severity == "info"
    assert finding.evidence["address_count"] == 2


def test_cross_domain_cname_is_detected_as_context():
    result = DNSResult(
        hostname="www.example.com",
        registrable_domain="example.com",
        status="resolved",
        hostname_records={
            "CNAME": _record(
                "CNAME",
                "success",
                "www.example.com",
                ["target.cloud.example.net."],
            ),
        },
        domain_records={},
        records={},
    )

    analyzed = service.analyze(result)
    ids = {finding.rule_id for finding in analyzed.findings}

    assert "DNS-CNAME-CROSS-DOMAIN" in ids


def test_same_domain_cname_is_not_flagged():
    result = DNSResult(
        hostname="www.example.com",
        registrable_domain="example.com",
        status="resolved",
        hostname_records={
            "CNAME": _record(
                "CNAME",
                "success",
                "www.example.com",
                ["origin.example.com."],
            ),
        },
        domain_records={},
        records={},
    )

    ids = _result_ids(result)

    assert "DNS-CNAME-CROSS-DOMAIN" not in ids
