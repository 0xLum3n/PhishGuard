import pytest

from app.services.url_parser import parse_url


def test_basic_https_url():

    result = parse_url("https://example.com")

    assert result.scheme == "https"
    assert result.hostname == "example.com"
    assert result.domain == "example.com"
    assert result.tld == "com"
    assert result.subdomain is None
    assert result.port is None
    assert result.path == "/"
    assert result.query is None
    assert result.fragment is None


def test_full_url():

    result = parse_url(
        "https://www.example.com:8443/"
        "login/user"
        "?id=123&lang=en"
        "#section"
    )

    assert result.scheme == "https"
    assert result.subdomain == "www"
    assert result.domain == "example.com"

    assert result.tld == "com"

    assert result.port == 8443

    assert result.path == "/login/user"

    assert result.query == "id=123&lang=en"

    assert result.fragment == "section"

    assert result.has_query is True

    assert result.has_fragment is True

    assert len(result.query_parameters) == 2


def test_query_parameter_values():

    result = parse_url(
        "https://example.com"
        "?id=123&id=456&lang=en"
    )

    assert len(result.query_parameters) == 2

    id_parameter = next(
        parameter
        for parameter in result.query_parameters
        if parameter.name == "id"
    )

    assert id_parameter.value == "123"

    assert id_parameter.values == [
        "123",
        "456",
    ]


def test_blank_query_parameter():

    result = parse_url(
        "https://example.com?token="
    )

    parameter = result.query_parameters[0]

    assert parameter.name == "token"

    assert parameter.value == ""

    assert parameter.values == [""]


def test_subdomain():

    result = parse_url(
        "https://login.account.example.com"
    )

    assert result.subdomain == "login.account"

    assert result.domain == "example.com"

    assert result.tld == "com"


def test_multi_label_tld():

    result = parse_url(
        "https://login.example.co.uk"
    )

    assert result.subdomain == "login"

    assert result.domain == "example.co.uk"

    assert result.tld == "co.uk"


def test_ip_address():

    result = parse_url(
        "https://192.168.1.10:8080/login"
    )

    assert result.is_ip_address is True

    assert result.hostname == "192.168.1.10"

    assert result.domain == "192.168.1.10"

    assert result.tld is None

    assert result.port == 8080


def test_ipv6_address():

    result = parse_url(
        "https://[2001:db8::1]:8443/test"
    )

    assert result.is_ip_address is True

    assert result.hostname == "2001:db8::1"

    assert result.port == 8443


def test_url_without_scheme():

    result = parse_url(
        "example.com/login"
    )

    assert result.scheme == "https"

    assert result.hostname == "example.com"

    assert result.path == "/login"


def test_credentials_detection():

    result = parse_url(
        "https://user:password@example.com/login"
    )

    assert result.has_credentials is True

    assert result.username == "user"

    assert result.password == "password"


def test_fragment():

    result = parse_url(
        "https://example.com/page#section"
    )

    assert result.fragment == "section"

    assert result.has_fragment is True


def test_empty_url():

    with pytest.raises(ValueError):

        parse_url("")


def test_whitespace_url():

    result = parse_url(
        "   https://example.com   "
    )

    assert result.hostname == "example.com"


def test_unsupported_scheme():

    with pytest.raises(ValueError):

        parse_url(
            "ftp://example.com/file.txt"
        )


def test_protocol_relative_url():

    with pytest.raises(ValueError):

        parse_url(
            "//example.com/path"
        )


def test_missing_hostname():

    with pytest.raises(ValueError):

        parse_url(
            "https:///login"
        )


def test_invalid_port():

    with pytest.raises(ValueError):

        parse_url(
            "https://example.com:99999/"
        )


def test_query_encoding():

    result = parse_url(
        "https://example.com"
        "?search=hello%20world"
    )

    parameter = result.query_parameters[0]

    assert parameter.name == "search"

    assert parameter.value == "hello world"


def test_unicode_domain():

    result = parse_url(
        "https://xn--pple-43d.com/login"
    )

    assert result.hostname == "xn--pple-43d.com"

    assert result.domain == "xn--pple-43d.com"