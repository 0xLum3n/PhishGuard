from __future__ import annotations

from typing import Any

import httpx

from app.schemas.response import OSINTMatch, OSINTProviderResult


PHISHTANK_ENDPOINT = (
    "http://checkurl.phishtank.com/checkurl/"
)


def _clean(value: str | None) -> str | None:
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


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
    }


class PhishTankProvider:
    """
    Exact PhishTank URL lookup.

    The app key is OPTIONAL for the simple API.

    Behaviour:
        2xx  -> success
        401  -> unauthorized
        403  -> forbidden
        509  -> rate_limited

    We do NOT convert every 403 into "bad API key".
    """

    def __init__(
        self,
        app_key: str | None = None,
        timeout: float = 8.0,
        user_agent: str = "PhishGuard/0.1",
        client: httpx.AsyncClient | None = None,
    ) -> None:

        self.app_key = _clean(app_key)
        self.timeout = timeout
        self.user_agent = (
            user_agent.strip()
            or "PhishGuard/0.1"
        )
        self._client = client

    async def _post(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> httpx.Response:

        data = {
            "url": url,
            "format": "json",
        }

        # Optional credential.
        if self.app_key:
            data["app_key"] = self.app_key

        return await client.post(
            PHISHTANK_ENDPOINT,
            data=data,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "application/json",
            },
            follow_redirects=True,
        )

    async def lookup(
        self,
        url: str,
    ) -> OSINTProviderResult:

        if not url or not url.strip():
            return OSINTProviderResult(
                source="PhishTank",
                status="invalid_request",
                query=url,
                matched=False,
                match_count=0,
                matches=[],
                metadata={},
                error="URL is empty.",
            )

        try:
            close_client = self._client is None

            client = (
                self._client
                or httpx.AsyncClient(
                    timeout=self.timeout,
                )
            )

            try:
                response = await self._post(
                    client,
                    url,
                )

                if response.status_code == 509:
                    return OSINTProviderResult(
                        source="PhishTank",
                        status="rate_limited",
                        query=url,
                        matched=False,
                        match_count=0,
                        matches=[],
                        metadata={
                            "authenticated": bool(self.app_key),
                            "http_status": 509,
                        },
                        error=(
                            "PhishTank rate limit reached."
                        ),
                    )

                if response.status_code == 401:
                    return OSINTProviderResult(
                        source="PhishTank",
                        status="unauthorized",
                        query=url,
                        matched=False,
                        match_count=0,
                        matches=[],
                        metadata={
                            "authenticated": bool(
                                self.app_key
                            ),
                            "http_status": 401,
                        },
                        error=(
                            "PhishTank returned HTTP 401."
                        ),
                    )

                if response.status_code == 403:
                    return OSINTProviderResult(
                        source="PhishTank",
                        status="forbidden",
                        query=url,
                        matched=False,
                        match_count=0,
                        matches=[],
                        metadata={
                            "authenticated": bool(
                                self.app_key
                            ),
                            "http_status": 403,
                        },
                        error=(
                            "PhishTank returned HTTP 403. "
                            "This may be an access or "
                            "security check rather than "
                            "an API-key failure."
                        ),
                    )

                response.raise_for_status()

                payload = response.json()

            finally:
                if close_client:
                    await client.aclose()

            if not isinstance(payload, dict):
                payload = {}

            result = payload.get(
                "results",
                {},
            )

            if not isinstance(result, dict):
                result = {}

            in_database = _as_bool(
                result.get("in_database")
            )

            verified = _as_bool(
                result.get("verified")
            )

            valid = _as_bool(
                result.get("valid")
            )

            matches: list[OSINTMatch] = []

            if in_database:
                detail_url = result.get(
                    "phish_detail_page"
                )

                matches.append(
                    OSINTMatch(
                        source="PhishTank",
                        match_type="exact_url",
                        indicator=str(
                            result.get("url")
                            or url
                        ),
                        reference=(
                            str(detail_url)
                            if detail_url
                            else None
                        ),
                        details={
                            "phish_id": result.get(
                                "phish_id"
                            ),
                            "verified": verified,
                            "valid": valid,
                            "verified_at": result.get(
                                "verified_at"
                            ),
                            "submitted_at": result.get(
                                "submitted_at"
                            ),
                        },
                    )
                )

            return OSINTProviderResult(
                source="PhishTank",
                status="success",
                query=url,
                matched=bool(matches),
                match_count=len(matches),
                matches=matches,
                metadata={
                    "authenticated": bool(
                        self.app_key
                    ),
                    "in_database": in_database,
                    "verified": verified,
                    "valid": valid,
                    "http_status": response.status_code,
                },
                error=None,
            )

        except httpx.TimeoutException:
            return OSINTProviderResult(
                source="PhishTank",
                status="timeout",
                query=url,
                matched=False,
                match_count=0,
                matches=[],
                metadata={
                    "authenticated": bool(
                        self.app_key
                    )
                },
                error=(
                    "PhishTank request timed out."
                ),
            )

        except httpx.HTTPError as exc:
            return OSINTProviderResult(
                source="PhishTank",
                status="upstream_error",
                query=url,
                matched=False,
                match_count=0,
                matches=[],
                metadata={
                    "authenticated": bool(
                        self.app_key
                    )
                },
                error=str(exc),
            )

        except Exception as exc:
            return OSINTProviderResult(
                source="PhishTank",
                status="error",
                query=url,
                matched=False,
                match_count=0,
                matches=[],
                metadata={
                    "authenticated": bool(
                        self.app_key
                    )
                },
                error=str(exc),
            )