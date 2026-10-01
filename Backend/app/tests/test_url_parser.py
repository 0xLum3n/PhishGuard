from app.services.url_parser import parse_url
def test_psl_co_uk():

    result = parse_url(
        "https://login.example.co.uk/account"
    )

    assert result.subdomain == "login"

    assert result.domain == "example"

    assert result.registrable_domain == "example.co.uk"

    assert result.tld == "co.uk"


def test_psl_com_au():

    result = parse_url(
        "https://login.example.com.au/account"
    )

    assert result.subdomain == "login"

    assert result.domain == "example"

    assert result.registrable_domain == "example.com.au"

    assert result.tld == "com.au"


def test_deep_subdomain():

    result = parse_url(
        "https://a.b.c.example.com/login"
    )

    assert result.subdomain == "a.b.c"

    assert result.domain == "example"

    assert result.registrable_domain == "example.com"

    assert result.tld == "com"


def test_ip_does_not_have_tld():

    result = parse_url(
        "https://192.168.1.100:8080/admin"
    )

    assert result.is_ip_address is True

    assert result.domain == "192.168.1.100"

    assert result.registrable_domain == "192.168.1.100"

    assert result.tld is None


def test_unknown_suffix():

    result = parse_url(
        "https://server.internal/login"
    )

    assert result.tld is None

    assert result.registrable_domain is None