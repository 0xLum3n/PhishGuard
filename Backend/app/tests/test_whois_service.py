import pytest

from app.services.whois_service import WhoisService


# =========================================================
# Fake RDAP provider
# =========================================================

class FakeRDAPProvider:

    async def lookup(
        self,
        domain: str,
    ):

        return {
            "success": True,
            "status": "success",
            "rdap_server": "https://rdap.example.test",
            "data": {
                "objectClassName": "domain",

                "ldhName": domain,

                "status": [
                    "client transfer prohibited"
                ],

                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": (
                            "2020-01-02T03:04:05Z"
                        ),
                    },
                    {
                        "eventAction": "last changed",
                        "eventDate": (
                            "2025-01-02T03:04:05Z"
                        ),
                    },
                    {
                        "eventAction": "expiration",
                        "eventDate": (
                            "2027-01-02T03:04:05Z"
                        ),
                    },
                ],

                "entities": [
                    {
                        "handle": "12345",
                        "roles": [
                            "registrar"
                        ],
                        "vcardArray": [
                            "vcard",
                            [
                                [
                                    "fn",
                                    {},
                                    "text",
                                    "Example Registrar",
                                ]
                            ],
                        ],
                    }
                ],

                "nameservers": [
                    {
                        "ldhName": "ns1.example.com",
                        "ipAddresses": {
                            "v4": [
                                "192.0.2.1"
                            ],
                            "v6": [
                                "2001:db8::1"
                            ],
                        },
                    },
                    {
                        "ldhName": "ns2.example.com",
                    },
                ],

                "secureDNS": {
                    "delegationSigned": True
                },

                "remarks": [],
            },
        }


class NotFoundProvider:

    async def lookup(
        self,
        domain: str,
    ):

        return {
            "success": False,
            "status": "not_found",
            "rdap_server": (
                "https://rdap.example.test"
            ),
            "error": "Domain not found.",
        }


# =========================================================
# Success
# =========================================================

@pytest.mark.anyio
async def test_whois_success():

    service = WhoisService(
        provider=FakeRDAPProvider()
    )

    result = await service.lookup(
        "example.com"
    )

    assert result.status == "success"

    assert result.domain == "example.com"

    assert result.source == "RDAP"

    assert (
        result.rdap_server
        == "https://rdap.example.test"
    )

    assert (
        result.registration_date
        == "2020-01-02T03:04:05Z"
    )

    assert (
        result.last_updated_date
        == "2025-01-02T03:04:05Z"
    )

    assert (
        result.expiration_date
        == "2027-01-02T03:04:05Z"
    )

    assert (
        result.registrar_name
        == "Example Registrar"
    )

    assert (
        result.registrar_id
        == "12345"
    )

    assert result.domain_status == [
        "client transfer prohibited"
    ]

    assert len(result.nameservers) == 2

    assert (
        result.nameservers[0].hostname
        == "ns1.example.com"
    )

    assert (
        result.nameservers[0].ipv4
        == ["192.0.2.1"]
    )

    assert (
        result.nameservers[0].ipv6
        == ["2001:db8::1"]
    )

    assert result.dnssec == "signed"


# =========================================================
# Not found
# =========================================================

@pytest.mark.anyio
async def test_whois_not_found():

    service = WhoisService(
        provider=NotFoundProvider()
    )

    result = await service.lookup(
        "does-not-exist.example"
    )

    assert result.status == "not_found"

    assert (
        result.error
        == "Domain not found."
    )


# =========================================================
# Missing domain
# =========================================================

@pytest.mark.anyio
async def test_whois_missing_domain():

    service = WhoisService(
        provider=FakeRDAPProvider()
    )

    result = await service.lookup(
        None
    )

    assert result.status == "not_applicable"

    assert result.domain == ""


# =========================================================
# Empty domain
# =========================================================

@pytest.mark.anyio
async def test_whois_empty_domain():

    service = WhoisService(
        provider=FakeRDAPProvider()
    )

    result = await service.lookup(
        ""
    )

    assert result.status == "not_applicable"

@pytest.fixture
def anyio_backend():
    return "asyncio"