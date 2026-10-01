from datetime import datetime, timedelta, timezone

from app.schemas.response import (
    RDAPNameserver,
    WhoisResult,
)
from app.services.whois_security_service import WhoisSecurityService


service = WhoisSecurityService()


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _base(**overrides):
    now = datetime.now(timezone.utc)

    data = dict(
        domain="example.com",
        status="success",
        source="RDAP",
        rdap_server="https://rdap.example.test",
        registration_date=_iso(now - timedelta(days=365)),
        expiration_date=_iso(now + timedelta(days=365)),
        last_updated_date=None,
        events=[],
        registrar_name="Example Registrar",
        registrar_id="123",
        registry_name=None,
        registry_id=None,
        domain_status=[],
        nameservers=[
            RDAPNameserver(
                hostname="ns1.example.com",
                ipv4=[],
                ipv6=[],
            )
        ],
        dnssec="signed",
        redacted=False,
        error=None,
    )
    data.update(overrides)
    return WhoisResult(**data)


def _ids(result):
    return {finding.rule_id for finding in result.findings}


def test_successful_normal_record_has_no_unexpected_findings():
    result = service.analyze(_base())
    assert result.status == "completed"
    assert "WHOIS-LOOKUP-UNAVAILABLE" not in _ids(result)
    assert "WHOIS-REGISTRATION-MISSING" not in _ids(result)
    assert "WHOIS-EXPIRATION-MISSING" not in _ids(result)


def test_recent_registration_is_detected():
    now = datetime.now(timezone.utc)
    result = service.analyze(
        _base(
            registration_date=_iso(now - timedelta(days=5))
        )
    )
    assert "WHOIS-RECENTLY-REGISTERED" in _ids(result)


def test_expiring_soon_is_detected():
    now = datetime.now(timezone.utc)
    result = service.analyze(
        _base(
            expiration_date=_iso(now + timedelta(days=5))
        )
    )
    assert "WHOIS-EXPIRING-SOON" in _ids(result)


def test_expired_is_detected():
    now = datetime.now(timezone.utc)
    result = service.analyze(
        _base(
            expiration_date=_iso(now - timedelta(days=5))
        )
    )
    assert "WHOIS-EXPIRED" in _ids(result)


def test_inconsistent_lifecycle_is_detected():
    now = datetime.now(timezone.utc)
    result = service.analyze(
        _base(
            registration_date=_iso(now),
            expiration_date=_iso(now - timedelta(days=1)),
        )
    )
    assert "WHOIS-LIFECYCLE-INCONSISTENT" in _ids(result)


def test_missing_registrar_nameservers_and_unsigned_dnssec_are_detected():
    result = service.analyze(
        _base(
            registrar_name=None,
            registrar_id=None,
            nameservers=[],
            dnssec="unsigned",
        )
    )
    ids = _ids(result)
    assert "WHOIS-NO-REGISTRAR" in ids
    assert "WHOIS-NO-NAMESERVERS" in ids
    assert "WHOIS-DNSSEC-UNSIGNED" in ids


def test_redaction_is_detected():
    result = service.analyze(
        _base(redacted=True)
    )
    assert "WHOIS-REDACTED" in _ids(result)


def test_failed_lookup_returns_context_finding():
    result = service.analyze(
        _base(
            status="not_found",
            registration_date=None,
            expiration_date=None,
            registrar_name=None,
            registrar_id=None,
            nameservers=[],
            dnssec=None,
            error="Domain not found.",
        )
    )
    ids = _ids(result)
    assert "WHOIS-LOOKUP-UNAVAILABLE" in ids
    assert result.status == "completed"


def test_none_result_is_handled():
    result = service.analyze(None)
    assert result.status == "completed"
    assert result.total_findings == 0
    assert result.findings == []
