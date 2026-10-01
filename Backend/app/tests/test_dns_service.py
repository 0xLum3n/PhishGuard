import dns.resolver
import pytest

from app.services.dns_service import DNSService


# =========================================================
# Fake DNS record
# =========================================================

class FakeRecord:
    def __init__(self, value: str):
        self.value = value

    def to_text(self) -> str:
        return self.value


# =========================================================
# Fake resolver
# =========================================================

class FakeResolver:
    """
    Minimal async resolver used for deterministic tests.
    """

    def __init__(self, responses):
        self.responses = responses
        self.timeout = 2.0
        self.lifetime = 5.0

    async def resolve(
        self,
        hostname,
        record_type,
        **kwargs,
    ):
        response = self.responses.get(
            record_type
        )

        if isinstance(
            response,
            Exception,
        ):
            raise response

        return [
            FakeRecord(value)
            for value in response
        ]


# =========================================================
# Tests
# =========================================================

@pytest.mark.anyio
async def test_dns_success():

    resolver = FakeResolver(
        {
            "A": [
                "93.184.216.34",
            ],
            "AAAA": [
                "2606:2800:220:1:248:1893:25c8:1946",
            ],
            "CNAME": [],
            "MX": [
                "10 mail.example.com.",
            ],
            "NS": [
                "ns1.example.com.",
                "ns2.example.com.",
            ],
            "TXT": [
                '"v=spf1 -all"',
            ],
        }
    )

    service = DNSService(
        resolver=resolver
    )

    result = await service.lookup(
        "example.com"
    )

    assert result.status == "resolved"

    assert result.hostname == "example.com"

    assert result.resolved_ips == [
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
    ]

    assert result.records["A"].records == [
        "93.184.216.34"
    ]

    assert result.records["AAAA"].records == [
        "2606:2800:220:1:248:1893:25c8:1946"
    ]

    assert result.records["MX"].records == [
        "10 mail.example.com."
    ]

    assert result.records["NS"].records == [
        "ns1.example.com.",
        "ns2.example.com.",
    ]


@pytest.mark.anyio
async def test_dns_no_answer_is_not_fatal():

    resolver = FakeResolver(
        {
            "A": dns.resolver.NoAnswer(),
            "AAAA": dns.resolver.NoAnswer(),
            "CNAME": dns.resolver.NoAnswer(),
            "MX": [
                "10 mail.example.com."
            ],
            "NS": dns.resolver.NoAnswer(),
            "TXT": dns.resolver.NoAnswer(),
        }
    )

    service = DNSService(
        resolver=resolver
    )

    result = await service.lookup(
        "example.com"
    )

    assert result.status == "resolved"

    assert result.records["A"].status == "no_answer"

    assert result.records["MX"].status == "success"


@pytest.mark.anyio
async def test_dns_nxdomain():

    resolver = FakeResolver(
        {
            "A": dns.resolver.NXDOMAIN(),
            "AAAA": dns.resolver.NXDOMAIN(),
            "CNAME": dns.resolver.NXDOMAIN(),
            "MX": dns.resolver.NXDOMAIN(),
            "NS": dns.resolver.NXDOMAIN(),
            "TXT": dns.resolver.NXDOMAIN(),
        }
    )

    service = DNSService(
        resolver=resolver
    )

    result = await service.lookup(
        "does-not-exist.example.invalid"
    )

    assert result.status == "nxdomain"

    assert result.resolved_ips == []


@pytest.mark.anyio
async def test_dns_timeout_does_not_crash():

    resolver = FakeResolver(
        {
            "A": [
                "93.184.216.34"
            ],
            "AAAA": dns.resolver.NoAnswer(),
            "CNAME": dns.resolver.NoAnswer(),
            "MX": dns.resolver.LifetimeTimeout(),
            "NS": [
                "ns1.example.com."
            ],
            "TXT": dns.resolver.NoAnswer(),
        }
    )

    service = DNSService(
        resolver=resolver
    )

    result = await service.lookup(
        "example.com"
    )

    assert result.status == "partial"

    assert result.resolved_ips == [
        "93.184.216.34"
    ]

    assert result.records["MX"].status == "timeout"


@pytest.mark.anyio
async def test_ip_address_does_not_use_dns():

    resolver = FakeResolver({})

    service = DNSService(
        resolver=resolver
    )

    result = await service.lookup(
        "192.168.1.100"
    )

    assert result.status == "not_applicable"

    assert result.resolved_ips == [
        "192.168.1.100"
    ]

    assert result.records == {}


@pytest.mark.anyio
async def test_ipv6_address_does_not_use_dns():

    resolver = FakeResolver({})

    service = DNSService(
        resolver=resolver
    )

    result = await service.lookup(
        "2001:db8::1"
    )

    assert result.status == "not_applicable"

    assert result.resolved_ips == [
        "2001:db8::1"
    ]

@pytest.fixture
def anyio_backend():
    return "asyncio"