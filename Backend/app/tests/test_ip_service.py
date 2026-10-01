import pytest

from app.services.ip_service import IPService


# =========================================================
# Fake provider
# =========================================================

class FakeProvider:
    """
    Fake provider used to test the service without
    contacting ipapi.co.
    """

    def __init__(
        self,
        client=None,
    ):
        self.client = client

    async def lookup(
        self,
        ip: str,
    ):
        return {
            "success": True,
            "status": "success",
            "data": {
                "ip": ip,
                "city": "Mountain View",
                "region": "California",
                "region_code": "CA",
                "country_code": "US",
                "country_name": "United States",
                "postal": "94043",
                "latitude": 37.386,
                "longitude": -122.0838,
                "timezone": "America/Los_Angeles",
                "asn": "AS15169",
                "org": "Google LLC",
            },
        }


class FailingProvider:

    def __init__(
        self,
        client=None,
    ):
        self.client = client

    async def lookup(
        self,
        ip: str,
    ):
        return {
            "success": False,
            "status": "rate_limited",
            "error": "Test rate limit.",
        }


# =========================================================
# Public IP
# =========================================================

@pytest.mark.anyio
async def test_public_ip_lookup():

    service = IPService(
        provider_factory=FakeProvider,
    )

    result = await service.lookup_many(
        [
            "8.8.8.8"
        ]
    )

    assert result.status == "completed"

    assert result.total_ips == 1

    assert result.public_ips == 1

    assert result.enriched_ips == 1

    assert len(result.results) == 1

    ip = result.results[0]

    assert ip.ip == "8.8.8.8"

    assert ip.version == 4

    assert ip.classification == "public"

    assert ip.status == "success"

    assert ip.country_code == "US"

    assert ip.country_name == "United States"

    assert ip.city == "Mountain View"

    assert ip.asn == "AS15169"

    assert ip.organization == "Google LLC"


# =========================================================
# Private IP
# =========================================================

@pytest.mark.anyio
async def test_private_ip_is_not_sent_to_provider():

    service = IPService(
        provider_factory=FakeProvider,
    )

    result = await service.lookup_many(
        [
            "192.168.1.1"
        ]
    )

    assert result.status == "no_public_ips"

    assert result.total_ips == 1

    assert result.public_ips == 0

    assert result.enriched_ips == 0

    assert len(result.results) == 1

    ip = result.results[0]

    assert ip.ip == "192.168.1.1"

    assert ip.classification == "private"

    assert ip.status == "private"


# =========================================================
# Loopback
# =========================================================

@pytest.mark.anyio
async def test_loopback_ip():

    service = IPService(
        provider_factory=FakeProvider,
    )

    result = await service.lookup_many(
        [
            "127.0.0.1"
        ]
    )

    assert result.status == "no_public_ips"

    assert result.results[0].classification == "loopback"

    assert result.results[0].status == "loopback"


# =========================================================
# IPv6 public address
# =========================================================

@pytest.mark.anyio
async def test_public_ipv6():

    service = IPService(
        provider_factory=FakeProvider,
    )

    result = await service.lookup_many(
        [
            "2001:4860:4860::8888"
        ]
    )

    assert result.status == "completed"

    assert result.results[0].version == 6

    assert result.results[0].classification == "public"

    assert result.results[0].status == "success"


# =========================================================
# Duplicate IPs
# =========================================================

@pytest.mark.anyio
async def test_duplicate_ips_are_removed():

    service = IPService(
        provider_factory=FakeProvider,
    )

    result = await service.lookup_many(
        [
            "8.8.8.8",
            "8.8.8.8",
            "1.1.1.1",
        ]
    )

    assert result.total_ips == 2

    assert result.public_ips == 2

    assert result.enriched_ips == 2

    assert len(result.results) == 2


# =========================================================
# Lookup limit
# =========================================================

@pytest.mark.anyio
async def test_lookup_limit():

    service = IPService(
        provider_factory=FakeProvider,
        max_lookups=2,
    )

    result = await service.lookup_many(
        [
            "8.8.8.8",
            "1.1.1.1",
            "9.9.9.9",
        ]
    )

    assert result.total_ips == 3

    assert result.public_ips == 3

    assert result.enriched_ips == 2

    assert result.lookup_limit == 2

    assert result.limit_reached is True

    assert result.status == "partial"


# =========================================================
# Provider failure
# =========================================================

@pytest.mark.anyio
async def test_provider_failure_does_not_crash():

    service = IPService(
        provider_factory=FailingProvider,
    )

    result = await service.lookup_many(
        [
            "8.8.8.8"
        ]
    )

    assert result.status == "error"

    assert result.enriched_ips == 0

    assert result.results[0].status == "rate_limited"

    assert result.results[0].classification == "public"


@pytest.fixture
def anyio_backend():
    return "asyncio"