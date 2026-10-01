from app.services.url_parser import parse_url
from app.services.url_security_service import URLSecurityService


service = URLSecurityService()


def _rule_ids(url: str) -> set[str]:
    result = service.analyze(parse_url(url))
    return {finding.rule_id for finding in result.findings}


def test_clean_url_has_no_structural_findings():
    result = service.analyze(
        parse_url("https://example.com/login")
    )

    assert result.status == "completed"
    assert result.total_findings == 0
    assert result.findings == []


def test_ip_hostname_is_detected():
    assert "URL-IP-HOST" in _rule_ids(
        "https://192.0.2.10/login"
    )


def test_credentials_are_detected():
    assert "URL-CREDENTIALS" in _rule_ids(
        "https://user:password@example.com/login"
    )


def test_nonstandard_port_is_detected():
    assert "URL-NONSTANDARD-PORT" in _rule_ids(
        "https://example.com:8080/login"
    )


def test_punycode_is_detected():
    assert "URL-PUNYCODE" in _rule_ids(
        "https://xn--pple-43d.example/login"
    )


def test_deep_subdomain_is_detected():
    assert "URL-DEEP-SUBDOMAIN" in _rule_ids(
        "https://a.b.c.d.example.com/login"
    )


def test_sensitive_and_duplicate_parameters_are_detected():
    rules = _rule_ids(
        "https://example.com/login?token=abc&token=def"
    )

    assert "URL-SENSITIVE-PARAMS" in rules
    assert "URL-DUPLICATE-PARAMS" in rules


def test_many_query_parameters_are_detected():
    query = "&".join(
        f"p{i}=x"
        for i in range(9)
    )

    assert "URL-MANY-QUERY-PARAMS" in _rule_ids(
        f"https://example.com/login?{query}"
    )


def test_double_encoding_is_detected():
    assert "URL-DOUBLE-ENCODING" in _rule_ids(
        "https://example.com/?next=%252Fadmin"
    )


def test_high_encoding_is_detected():
    query = "&".join(
        f"p{i}=%41"
        for i in range(10)
    )

    assert "URL-HIGH-ENCODING" in _rule_ids(
        f"https://example.com/?{query}"
    )


def test_long_url_is_detected():
    long_value = "a" * 2100

    assert "URL-LONG" in _rule_ids(
        f"https://example.com/?q={long_value}"
    )
