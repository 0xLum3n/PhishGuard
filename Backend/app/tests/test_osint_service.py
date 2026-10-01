import pytest

from app.schemas.response import (
    OSINTMatch,
    OSINTProviderResult,
)
from app.services.osint_service import OSINTService


# =========================================================
# Fake providers
# =========================================================

class FakePhishTank:

    async def lookup(
        self,
        url,
        domain,
    ):

        return OSINTProviderResult(
            source="FakePhishTank",

            status="success",

            query=url,

            matched=True,

            match_count=1,

            matches=[
                OSINTMatch(
                    source="FakePhishTank",
                    match_type="phishing_url",
                    indicator=url,
                    reference=(
                        "https://example.test/phish/1"
                    ),
                    details={
                        "verified": True,
                    },
                )
            ],
        )


class FakeURLhaus:

    async def lookup(
        self,
        url,
        domain,
    ):

        return OSINTProviderResult(
            source="FakeURLhaus",

            status="no_match",

            query=url,

            matched=False,

            match_count=0,

            matches=[],
        )


class FakeURLScan:

    async def lookup(
        self,
        url,
        domain,
    ):

        return OSINTProviderResult(
            source="FakeURLScan",

            status="success",

            query=domain,

            matched=True,

            match_count=2,

            matches=[
                OSINTMatch(
                    source="FakeURLScan",
                    match_type="historical_scan",
                    indicator=domain,
                    reference=(
                        "https://urlscan.io/result/abc/"
                    ),
                ),
                OSINTMatch(
                    source="FakeURLScan",
                    match_type="historical_scan",
                    indicator=domain,
                    reference=(
                        "https://urlscan.io/result/def/"
                    ),
                ),
            ],
        )


class FakeUnavailable:

    async def lookup(
        self,
        url,
        domain,
    ):

        return OSINTProviderResult(
            source="UnavailableProvider",

            status="rate_limited",

            query=url,

            error="Test rate limit.",
        )


# =========================================================
# Successful aggregate
# =========================================================

@pytest.mark.anyio
async def test_osint_aggregate():

    service = OSINTService(
        providers=[
            FakePhishTank(),
            FakeURLhaus(),
            FakeURLScan(),
        ]
    )

    result = await service.lookup(
        url="https://example.com/login",
        domain="example.com",
    )

    assert result.status == "completed"

    assert len(result.providers) == 3

    assert result.total_matches == 3

    assert len(result.matches) == 3


# =========================================================
# No matches
# =========================================================

class FakeCleanProvider:

    async def lookup(
        self,
        url,
        domain,
    ):

        return OSINTProviderResult(
            source="CleanProvider",

            status="no_match",

            query=url,

            matched=False,

            match_count=0,

            matches=[],
        )


@pytest.mark.anyio
async def test_osint_no_matches():

    service = OSINTService(
        providers=[
            FakeCleanProvider(),
            FakeCleanProvider(),
        ]
    )

    result = await service.lookup(
        url="https://example.com",
        domain="example.com",
    )

    assert result.status == "no_matches"

    assert result.total_matches == 0

    assert result.matches == []


# =========================================================
# Partial result
# =========================================================

@pytest.mark.anyio
async def test_osint_partial_failure():

    service = OSINTService(
        providers=[
            FakePhishTank(),
            FakeUnavailable(),
        ]
    )

    result = await service.lookup(
        url="https://example.com",
        domain="example.com",
    )

    assert result.status == "partial"

    assert result.total_matches == 1

    assert len(result.matches) == 1


# =========================================================
# All providers unavailable
# =========================================================

class FakeNotConfigured:

    async def lookup(
        self,
        url,
        domain,
    ):

        return OSINTProviderResult(
            source="NotConfigured",

            status="not_configured",

            query=url,
        )


@pytest.mark.anyio
async def test_all_providers_not_configured():

    service = OSINTService(
        providers=[
            FakeNotConfigured(),
            FakeNotConfigured(),
        ]
    )

    result = await service.lookup(
        url="https://example.com",
        domain="example.com",
    )

    assert result.status == "not_configured"

    assert result.total_matches == 0


# =========================================================
# Empty provider list
# =========================================================

@pytest.mark.anyio
async def test_empty_provider_list():

    service = OSINTService(
        providers=[]
    )

    result = await service.lookup(
        url="https://example.com",
        domain="example.com",
    )

    assert result.status == "not_configured"

    assert result.total_matches == 0


# =========================================================
# asyncio test backend
# =========================================================

@pytest.fixture
def anyio_backend():
    return "asyncio"