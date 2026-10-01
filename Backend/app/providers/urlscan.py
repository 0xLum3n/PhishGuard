from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx
import tldextract

from app.schemas.response import (
    OSINTMatch,
    OSINTProviderResult,
)


URLSCAN_ENDPOINT = (
    "https://urlscan.io/api/v1/search"
)


# =========================================================
# Helpers
# =========================================================

def _clean(value: str | None) -> str | None:
    """Remove surrounding whitespace and optional quotes."""

    if value is None:
        return None

    value = value.strip()

    if (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in {"'", '"'}
    ):
        value = value[1:-1].strip()

    return value or None


def _escape_query_value(value: str) -> str:
    """Escape Elasticsearch query-string reserved characters."""

    reserved = r'\+-=&|><!(){}[]^"~*?:/'

    escaped: list[str] = []

    for char in value:
        if char in reserved:
            escaped.append("\\")
        escaped.append(char)

    return "".join(escaped)


def _quote_query_value(value: str) -> str:
    """Quote an Elasticsearch query-string value."""

    return f'"{_escape_query_value(value)}"'


def _result_scan_id(item: dict[str, Any]) -> str | None:
    """Extract the urlscan result/scan UUID."""

    task = item.get("task")

    if isinstance(task, dict) and task.get("uuid"):
        return str(task["uuid"])

    if item.get("_id"):
        return str(item["_id"])

    return None


def _result_url(item: dict[str, Any]) -> str | None:
    """Return the original task URL, falling back to page URL."""

    task = item.get("task")

    if isinstance(task, dict) and task.get("url"):
        return str(task["url"])

    page = item.get("page")

    if isinstance(page, dict) and page.get("url"):
        return str(page["url"])

    return None


def _domain_from_item(item: dict[str, Any]) -> str | None:
    """Return a contextual page domain, falling back to task domain."""

    page = item.get("page")

    if isinstance(page, dict) and page.get("domain"):
        return str(page["domain"])

    task = item.get("task")

    if isinstance(task, dict) and task.get("domain"):
        return str(task["domain"])

    return None


def _canonical_task_url(item: dict[str, Any]) -> str | None:
    """Extract urlscan's canonical task URL."""

    canonical = item.get("canonical")

    if not isinstance(canonical, dict):
        return None

    task = canonical.get("task")

    if not isinstance(task, dict):
        return None

    value = task.get("url")
    return str(value) if value else None


def _hostname_from_url(value: str | None) -> str | None:
    """Safely derive a normalized hostname from a URL."""

    if not value:
        return None

    try:
        hostname = urlsplit(value).hostname
    except ValueError:
        return None

    if not hostname:
        return None

    return hostname.rstrip(".").lower()


def _normalize_exact_url(value: str | None) -> str | None:
    """Normalize URLs for exact historical comparison."""

    if not value:
        return None

    raw = value.strip()

    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw.lower()

    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()

    if not scheme or not hostname:
        return raw.lower()

    host = hostname

    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    try:
        port = parsed.port
    except ValueError:
        port = None

    netloc = host

    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo += f":{parsed.password}"
        netloc = f"{userinfo}@{netloc}"

    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        netloc = f"{netloc}:{port}"

    path = parsed.path or "/"
    normalized = f"{scheme}://{netloc}{path}"

    if parsed.query:
        normalized += f"?{parsed.query}"

    if parsed.fragment:
        normalized += f"#{parsed.fragment}"

    if path == "/":
        return normalized[:-1]

    return normalized


def _url_matches(candidate: str, observed: str | None) -> bool:
    """Compare two URLs using normalized exact semantics."""

    return _normalize_exact_url(candidate) == _normalize_exact_url(observed)


def _domain_matches(expected: str, observed: str | None) -> bool:
    """Compare hostnames exactly; do not broaden to parent domains."""

    if not observed:
        return False

    return (
        observed.strip().rstrip(".").lower()
        == expected.strip().rstrip(".").lower()
    )


def _items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Safely extract search results."""

    results = payload.get("results")

    if not isinstance(results, list):
        return []

    return [item for item in results if isinstance(item, dict)]


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate urlscan records, preferably by scan UUID."""

    seen: set[str] = set()
    output: list[dict[str, Any]] = []

    for item in items:
        scan_id = _result_scan_id(item)
        key = scan_id if scan_id else repr(item)

        if key in seen:
            continue

        seen.add(key)
        output.append(item)

    return output


def _to_match(item: dict[str, Any], match_type: str) -> OSINTMatch:
    """
    Convert a urlscan record into evidence.

    task_* fields describe the original URL submitted to urlscan.
    page_* fields describe the resulting page after navigation.
    """

    task = item.get("task") if isinstance(item.get("task"), dict) else {}
    page = item.get("page") if isinstance(item.get("page"), dict) else {}
    stats = item.get("stats") if isinstance(item.get("stats"), dict) else {}

    scan_id = _result_scan_id(item)
    reference = f"https://urlscan.io/result/{scan_id}/" if scan_id else None

    return OSINTMatch(
        source="urlscan.io",
        match_type=match_type,
        indicator=(
            task.get("url")
            or task.get("domain")
            or page.get("domain")
            or ""
        ),
        reference=reference,
        details={
            "scan_id": scan_id,
            "task_url": task.get("url"),
            "canonical_task_url": _canonical_task_url(item),
            "task_domain": task.get("domain"),
            "page_domain": page.get("domain"),
            "page_url": page.get("url"),
            "page_redirected": page.get("redirected"),
            "ip": page.get("ip"),
            "country": page.get("country"),
            "asn": page.get("asn"),
            "scan_time": task.get("time"),
            "stats": stats,
        },
    )


class URLScanProvider:
    """
    Historical urlscan intelligence with explicit evidence scopes.

    exact_url:
        The original tasked URL matches the submitted URL.

    exact_hostname:
        The ORIGINAL task URL hostname matches the submitted hostname.

    page_domain_observation:
        The resulting page domain matches the target. Context only.

    domain_history:
        Broad historical activity under the registrable domain. Context only.

    Only exact_url and exact_hostname are promoted to OSINT matches.
    None of these observations alone is a malicious verdict.
    """

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 8.0,
        max_results: int = 10,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = _clean(api_key)
        self.timeout = timeout
        self.max_results = max(1, min(int(max_results), 100))
        self._client = client

    @staticmethod
    def _derive_registrable_domain(hostname: str) -> str:
        extracted = tldextract.extract(hostname)
        return extracted.registered_domain or hostname

    @staticmethod
    def _root_url_candidates(normalized_url: str) -> list[str]:
        """Search both root URL spellings when the target is a root URL."""

        parsed = urlsplit(normalized_url)

        if (
            parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        ):
            host = (parsed.hostname or "").lower()

            # urlsplit() removes IPv6 brackets from hostname.
            # Put them back when constructing the root URL.
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"

            root = f"{parsed.scheme.lower()}://{host}"

            if parsed.port:
                root += f":{parsed.port}"

            return list(dict.fromkeys([root, root + "/"]))

        return [normalized_url]

    async def _search(
        self,
        client: httpx.AsyncClient,
        query: str,
    ) -> dict[str, Any]:
        response = await client.get(
            URLSCAN_ENDPOINT,
            params={
                "q": query,
                "size": self.max_results,
                "datasource": "scans",
            },
            headers={
                "api-key": self.api_key or "",
                "Accept": "application/json",
            },
            follow_redirects=True,
        )

        if response.status_code in {401, 403}:
            raise PermissionError(
                f"urlscan authentication failed (HTTP {response.status_code})."
            )

        if response.status_code == 429:
            raise RuntimeError("urlscan rate limit reached.")

        response.raise_for_status()

        payload = response.json()
        return payload if isinstance(payload, dict) else {}

    async def lookup(
        self,
        url: str,
        hostname: str | None = None,
        registrable_domain: str | None = None,
    ) -> OSINTProviderResult:
        if not self.api_key:
            return OSINTProviderResult(
                source="urlscan.io",
                status="not_configured",
                query=(registrable_domain or hostname or url),
                matched=False,
                match_count=0,
                matches=[],
                metadata={"authenticated": False},
                error="urlscan API key is not configured.",
            )

        normalized_url = url.strip()

        try:
            parsed = urlsplit(normalized_url)
        except ValueError as exc:
            return OSINTProviderResult(
                source="urlscan.io",
                status="invalid_request",
                query=url,
                matched=False,
                match_count=0,
                matches=[],
                metadata={"authenticated": True},
                error=f"Invalid URL: {exc}",
            )

        effective_hostname = (
            hostname or parsed.hostname or ""
        ).strip().lower()

        if not effective_hostname:
            return OSINTProviderResult(
                source="urlscan.io",
                status="invalid_request",
                query=url,
                matched=False,
                match_count=0,
                matches=[],
                metadata={"authenticated": True},
                error="Unable to derive hostname from URL.",
            )

        effective_domain = (
            registrable_domain
            or self._derive_registrable_domain(effective_hostname)
        ).strip().lower()

        try:
            close_client = self._client is None
            client = self._client or httpx.AsyncClient(timeout=self.timeout)

            try:
                # =====================================================
                # 1. EXACT URL
                # =====================================================
                exact_items: list[dict[str, Any]] = []
                url_candidates = self._root_url_candidates(normalized_url)

                for candidate in url_candidates:
                    payload = await self._search(
                        client,
                        "task.url.keyword:"
                        f"{_quote_query_value(candidate)}",
                    )

                    for item in _items(payload):
                        task = item.get("task")
                        observed = (
                            task.get("url")
                            if isinstance(task, dict)
                            else None
                        )

                        if _url_matches(candidate, observed):
                            exact_items.append(item)

                    payload = await self._search(
                        client,
                        "canonical.task.url:"
                        f"{_quote_query_value(candidate)}",
                    )

                    for item in _items(payload):
                        canonical_url = _canonical_task_url(item)

                        if _url_matches(candidate, canonical_url):
                            exact_items.append(item)

                exact_items = _dedupe(exact_items)

                # =====================================================
                # 2. EXACT ORIGINAL TASK HOSTNAME
                # =====================================================
                hostname_items: list[dict[str, Any]] = []

                hostname_payload = await self._search(
                    client,
                    "task.domain.keyword:"
                    f"{_quote_query_value(effective_hostname)}",
                )

                for item in _items(hostname_payload):
                    task = item.get("task")

                    if not isinstance(task, dict):
                        continue

                    task_url = task.get("url")
                    task_url_hostname = _hostname_from_url(task_url)

                    # Strongest protection: validate from task.url itself.
                    if task_url_hostname != effective_hostname:
                        continue

                    observed_domain = task.get("domain")

                    # Secondary consistency check when task.domain exists.
                    if (
                        observed_domain
                        and not _domain_matches(
                            effective_hostname,
                            observed_domain,
                        )
                    ):
                        continue

                    hostname_items.append(item)

                hostname_items = _dedupe(hostname_items)

                # =====================================================
                # 3. PAGE DOMAIN OBSERVATIONS (CONTEXT ONLY)
                # =====================================================
                page_domain_payload = await self._search(
                    client,
                    "page.domain.keyword:"
                    f"{_quote_query_value(effective_hostname)}",
                )

                page_domain_items = _dedupe(
                    _items(page_domain_payload)
                )

                page_domain_observations: list[dict[str, Any]] = []

                for item in page_domain_items[: self.max_results]:
                    task = (
                        item.get("task")
                        if isinstance(item.get("task"), dict)
                        else {}
                    )
                    page = (
                        item.get("page")
                        if isinstance(item.get("page"), dict)
                        else {}
                    )
                    scan_id = _result_scan_id(item)

                    page_domain_observations.append(
                        {
                            "scan_id": scan_id,
                            "task_url": task.get("url"),
                            "task_domain": task.get("domain"),
                            "page_url": page.get("url"),
                            "page_domain": page.get("domain"),
                            "redirected": page.get("redirected"),
                            "scan_time": task.get("time"),
                            "reference": (
                                f"https://urlscan.io/result/{scan_id}/"
                                if scan_id
                                else None
                            ),
                        }
                    )

                # =====================================================
                # 4. BROAD DOMAIN HISTORY (CONTEXT ONLY)
                # =====================================================
                history_payload = await self._search(
                    client,
                    f"page.domain:{effective_domain}",
                )

                history_items = _dedupe(_items(history_payload))

            finally:
                if close_client:
                    await client.aclose()

            # =========================================================
            # Promote ONLY exact evidence
            # =========================================================
            promoted_matches: list[OSINTMatch] = []
            exact_ids: set[str] = set()

            for item in exact_items:
                scan_id = _result_scan_id(item)

                if scan_id:
                    exact_ids.add(scan_id)

                promoted_matches.append(
                    _to_match(item, "exact_url")
                )

            for item in hostname_items:
                scan_id = _result_scan_id(item)

                # Avoid double-counting a scan already found by exact URL.
                if scan_id and scan_id in exact_ids:
                    continue

                promoted_matches.append(
                    _to_match(item, "exact_hostname")
                )

            # =========================================================
            # Domain history observations
            # =========================================================
            history_observations: list[dict[str, Any]] = []

            for item in history_items[: self.max_results]:
                task = (
                    item.get("task")
                    if isinstance(item.get("task"), dict)
                    else {}
                )
                page = (
                    item.get("page")
                    if isinstance(item.get("page"), dict)
                    else {}
                )
                scan_id = _result_scan_id(item)

                history_observations.append(
                    {
                        "scan_id": scan_id,
                        "task_url": task.get("url"),
                        "page_url": page.get("url"),
                        "domain": (
                            page.get("domain")
                            or task.get("domain")
                        ),
                        "scan_time": task.get("time"),
                        "reference": (
                            f"https://urlscan.io/result/{scan_id}/"
                            if scan_id
                            else None
                        ),
                    }
                )

            return OSINTProviderResult(
                source="urlscan.io",
                status="success",
                query=effective_domain,
                # Only exact URL/hostname evidence affects matched.
                matched=bool(promoted_matches),
                match_count=len(promoted_matches),
                matches=promoted_matches,
                metadata={
                    "authenticated": True,
                    "target_url": normalized_url,
                    "target_hostname": effective_hostname,
                    "target_registrable_domain": effective_domain,
                    "exact_url_count": len(exact_items),
                    "exact_hostname_count": len(hostname_items),
                    "page_domain_observation_count": len(
                        page_domain_items
                    ),
                    "domain_history_count": len(history_items),
                    "domain_history_total": history_payload.get("total"),
                    "domain_history_has_more": history_payload.get(
                        "has_more"
                    ),
                    "page_domain_observations": page_domain_observations,
                    "domain_history_observations": history_observations,
                    "queries": {
                        "exact_url": (
                            [
                                "task.url.keyword:"
                                f"{_quote_query_value(candidate)}"
                                for candidate in url_candidates
                            ]
                            + [
                                "canonical.task.url:"
                                f"{_quote_query_value(candidate)}"
                                for candidate in url_candidates
                            ]
                        ),
                        "exact_hostname": (
                            "task.domain.keyword:"
                            f"{_quote_query_value(effective_hostname)}"
                        ),
                        "page_domain_observation": (
                            "page.domain.keyword:"
                            f"{_quote_query_value(effective_hostname)}"
                        ),
                        "domain_history": (
                            f"page.domain:{effective_domain}"
                        ),
                    },
                    "semantic_note": (
                        "urlscan historical observations are contextual. "
                        "Only exact URL and exact original-task-hostname "
                        "evidence are promoted to matches. A resulting "
                        "page/domain does not by itself constitute an exact "
                        "match or malicious verdict."
                    ),
                },
                error=None,
            )

        except PermissionError as exc:
            return OSINTProviderResult(
                source="urlscan.io",
                status="unauthorized",
                query=effective_domain,
                matched=False,
                match_count=0,
                matches=[],
                metadata={"authenticated": False},
                error=str(exc),
            )

        except RuntimeError as exc:
            return OSINTProviderResult(
                source="urlscan.io",
                status="rate_limited",
                query=effective_domain,
                matched=False,
                match_count=0,
                matches=[],
                metadata={"authenticated": True},
                error=str(exc),
            )

        except httpx.TimeoutException:
            return OSINTProviderResult(
                source="urlscan.io",
                status="timeout",
                query=effective_domain,
                matched=False,
                match_count=0,
                matches=[],
                metadata={"authenticated": True},
                error="urlscan request timed out.",
            )

        except httpx.HTTPError as exc:
            return OSINTProviderResult(
                source="urlscan.io",
                status="upstream_error",
                query=effective_domain,
                matched=False,
                match_count=0,
                matches=[],
                metadata={"authenticated": True},
                error=str(exc),
            )

        except Exception as exc:
            return OSINTProviderResult(
                source="urlscan.io",
                status="error",
                query=effective_domain,
                matched=False,
                match_count=0,
                matches=[],
                metadata={"authenticated": True},
                error=str(exc),
            )
