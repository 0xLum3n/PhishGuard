import pytest

from app.providers.urlscan import (
    URLScanProvider,
    _domain_matches,
    _hostname_from_url,
    _normalize_exact_url,
    _url_matches,
)


# =========================================================
# URL normalization helpers
# =========================================================

def test_normalize_root_url_equivalence():
    assert (
        _normalize_exact_url("https://example.com")
        == _normalize_exact_url("https://example.com/")
    )


def test_normalize_default_port():
    assert (
        _normalize_exact_url("https://example.com:443/")
        == _normalize_exact_url("https://example.com")
    )


def test_url_matching_is_exact():
    assert _url_matches(
        "https://example.com/login",
        "https://example.com/login",
    )

    assert not _url_matches(
        "https://example.com/login",
        "https://example.com/logout",
    )


def test_hostname_from_url():
    assert (
        _hostname_from_url(
            "https://WWW.Example.COM./login"
        )
        == "www.example.com"
    )


def test_hostname_comparison_is_not_parent_domain_matching():
    assert _domain_matches(
        "example.com",
        "example.com",
    )

    assert not _domain_matches(
        "www.example.com",
        "example.com",
    )


# =========================================================
# Provider evidence separation
# =========================================================

class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


class FakeSearchClient:
    def __init__(self):
        self.calls = []

    async def get(self, endpoint, *, params, headers, follow_redirects):
        self.calls.append(params["q"])
        query = params["q"]

        if query.startswith("task.url.keyword"):
            return FakeResponse({
                "results": [
                    {
                        "_id": "exact-1",
                        "task": {
                            "uuid": "exact-1",
                            "url": "https://example.com",
                            "domain": "example.com",
                            "time": "2026-01-01T00:00:00Z",
                        },
                        "page": {
                            "url": "https://redirected.example.net/",
                            "domain": "redirected.example.net",
                            "redirected": True,
                        },
                    }
                ],
                "total": 1,
                "has_more": False,
            })

        if query.startswith("canonical.task.url"):
            return FakeResponse({"results": []})

        if query.startswith("task.domain.keyword"):
            return FakeResponse({
                "results": [
                    {
                        # Wrong original task hostname. Its page happens
                        # to be example.com, so it must be filtered out.
                        "_id": "wrong-original-host",
                        "task": {
                            "uuid": "wrong-original-host",
                            "url": "https://attacker.example/",
                            "domain": "attacker.example",
                        },
                        "page": {
                            "url": "https://example.com/",
                            "domain": "example.com",
                        },
                    },
                    {
                        # Valid exact original hostname.
                        "_id": "host-1",
                        "task": {
                            "uuid": "host-1",
                            "url": "https://example.com/account",
                            "domain": "example.com",
                        },
                        "page": {
                            "url": "https://example.com/account",
                            "domain": "example.com",
                        },
                    },
                ],
            })

        if query.startswith("page.domain.keyword"):
            return FakeResponse({
                "results": [
                    {
                        "_id": "page-only",
                        "task": {
                            "uuid": "page-only",
                            "url": "https://attacker.example/",
                            "domain": "attacker.example",
                        },
                        "page": {
                            "url": "https://example.com/",
                            "domain": "example.com",
                            "redirected": True,
                        },
                    }
                ],
            })

        if query.startswith("page.domain:"):
            return FakeResponse({
                "results": [
                    {
                        "_id": "history-1",
                        "task": {
                            "uuid": "history-1",
                            "url": "https://another.example/",
                        },
                        "page": {
                            "url": "https://example.com/",
                            "domain": "example.com",
                        },
                    }
                ],
                "total": 1,
                "has_more": False,
            })

        raise AssertionError(f"Unexpected query: {query}")


@pytest.mark.anyio
async def test_urlscan_separates_exact_and_page_domain_evidence():
    client = FakeSearchClient()
    provider = URLScanProvider(
        api_key="test-key",
        max_results=10,
        client=client,
    )

    result = await provider.lookup(
        "https://example.com",
        hostname="example.com",
        registrable_domain="example.com",
    )

    assert result.status == "success"
    assert result.matched is True
    assert result.match_count == 2

    assert result.metadata["exact_url_count"] == 1
    assert result.metadata["exact_hostname_count"] == 1
    assert result.metadata["page_domain_observation_count"] == 1
    assert result.metadata["domain_history_count"] == 1

    match_types = {
        match.match_type
        for match in result.matches
    }
    assert match_types == {
        "exact_url",
        "exact_hostname",
    }

    exact_hostname_match = next(
        match
        for match in result.matches
        if match.match_type == "exact_hostname"
    )

    assert (
        _hostname_from_url(
            exact_hostname_match.details["task_url"]
        )
        == "example.com"
    )
    assert (
        exact_hostname_match.details["task_domain"]
        == "example.com"
    )
    assert (
        exact_hostname_match.details["page_domain"]
        == "example.com"
    )

    assert result.metadata["page_domain_observations"] == [
        {
            "scan_id": "page-only",
            "task_url": "https://attacker.example/",
            "task_domain": "attacker.example",
            "page_url": "https://example.com/",
            "page_domain": "example.com",
            "redirected": True,
            "scan_time": None,
            "reference": "https://urlscan.io/result/page-only/",
        }
    ]


@pytest.fixture
def anyio_backend():
    return "asyncio"
