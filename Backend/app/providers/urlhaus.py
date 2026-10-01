from __future__ import annotations

import httpx

from app.schemas.response import (
    OSINTMatch,
    OSINTProviderResult,
)


class URLhausProvider:
    """
    URLhaus exact-URL lookup.

    Only queries the existing URLhaus database.
    """

    SOURCE = "URLhaus"

    ENDPOINT = (
        "https://urlhaus-api.abuse.ch/v1/url/"
    )

    def __init__(
        self,
        client: httpx.AsyncClient,
        auth_key: str | None = None,
    ) -> None:

        self.client = client

        self.auth_key = auth_key

    # =====================================================
    # Lookup
    # =====================================================

    async def lookup(
        self,
        url: str,
        domain: str | None = None,
    ) -> OSINTProviderResult:

        if not self.auth_key:

            return OSINTProviderResult(
                source=self.SOURCE,

                status="not_configured",

                query=url,

                error=(
                    "URLhaus Auth-Key is not configured."
                ),
            )

        try:

            response = await self.client.post(
                self.ENDPOINT,

                data={
                    "url": url,
                },

                headers={
                    "Auth-Key": self.auth_key,
                    "Accept": "application/json",
                    "User-Agent": "PhishGuard/0.1",
                },
            )

        except httpx.TimeoutException:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="timeout",
                query=url,
                error=(
                    "URLhaus lookup timed out."
                ),
            )

        except httpx.RequestError as exc:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="error",
                query=url,
                error=(
                    "URLhaus network error: "
                    f"{type(exc).__name__}"
                ),
            )

        if response.status_code == 429:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="rate_limited",
                query=url,
                error=(
                    "URLhaus rate limit reached."
                ),
            )

        if response.status_code in {
            401,
            403,
        }:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="unauthorized",
                query=url,
                error=(
                    "URLhaus rejected the supplied Auth-Key."
                ),
            )

        if response.status_code >= 400:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="error",
                query=url,
                error=(
                    "URLhaus returned HTTP "
                    f"{response.status_code}."
                ),
            )

        try:

            payload = response.json()

        except ValueError:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="error",
                query=url,
                error=(
                    "URLhaus returned invalid JSON."
                ),
            )

        query_status = payload.get(
            "query_status"
        )

        # -------------------------------------------------
        # No result
        # -------------------------------------------------

        if query_status == "no_results":

            return OSINTProviderResult(
                source=self.SOURCE,
                status="no_match",
                query=url,
                matched=False,
                match_count=0,
                matches=[],
            )

        # -------------------------------------------------
        # API-level errors
        # -------------------------------------------------

        if query_status != "ok":

            return OSINTProviderResult(
                source=self.SOURCE,
                status="error",
                query=url,
                error=(
                    "URLhaus query failed with status: "
                    f"{query_status}"
                ),
            )

        # -------------------------------------------------
        # Match
        # -------------------------------------------------

        reference = payload.get(
            "urlhaus_reference"
        )

        indicator = payload.get(
            "url",
            url,
        )

        tags = payload.get(
            "tags",
            [],
        )

        if not isinstance(
            tags,
            list,
        ):

            tags = []

        blacklists = payload.get(
            "blacklists",
            {},
        )

        if not isinstance(
            blacklists,
            dict,
        ):

            blacklists = {}

        match = OSINTMatch(
            source=self.SOURCE,

            match_type="malware_url",

            indicator=str(
                indicator
            ),

            reference=(
                str(reference)
                if reference
                else None
            ),

            details={
                "id": payload.get(
                    "id"
                ),

                "url_status": payload.get(
                    "url_status"
                ),

                "host": payload.get(
                    "host"
                ),

                "date_added": payload.get(
                    "date_added"
                ),

                "last_online": payload.get(
                    "last_online"
                ),

                "threat": payload.get(
                    "threat"
                ),

                "tags": tags,

                "blacklists": blacklists,

                "payload_count": len(
                    payload.get(
                        "payloads",
                        []
                    )
                    if isinstance(
                        payload.get(
                            "payloads",
                            []
                        ),
                        list,
                    )
                    else []
                ),
            },
        )

        return OSINTProviderResult(
            source=self.SOURCE,

            status="success",

            query=url,

            matched=True,

            match_count=1,

            matches=[
                match
            ],
        )