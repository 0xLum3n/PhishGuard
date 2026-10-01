from __future__ import annotations

from typing import Any

import httpx

from app.schemas.response import (
    OSINTMatch,
    OSINTProviderResult,
)


class PhishTankProvider:
    """
    PhishTank exact-URL lookup.

    This provider only checks PhishTank's existing database.

    It does NOT submit or report the URL.
    """

    SOURCE = "PhishTank"

    ENDPOINT = (
        "http://checkurl.phishtank.com/checkurl/"
    )

    def __init__(
        self,
        client: httpx.AsyncClient,
        app_key: str | None = None,
        user_agent: str = "PhishGuard/0.1",
    ) -> None:

        self.client = client

        self.app_key = app_key

        self.user_agent = user_agent

    # =====================================================
    # Helpers
    # =====================================================

    @staticmethod
    def _as_bool(
        value: Any,
    ) -> bool:

        if isinstance(
            value,
            bool,
        ):
            return value

        if isinstance(
            value,
            str,
        ):

            return value.lower() in {
                "true",
                "1",
                "yes",
                "y",
            }

        return bool(value)

    # =====================================================
    # Lookup
    # =====================================================

    async def lookup(
        self,
        url: str,
        domain: str | None = None,
    ) -> OSINTProviderResult:

        data = {
            "url": url,
            "format": "json",
        }

        if self.app_key:

            data["app_key"] = self.app_key

        try:

            response = await self.client.post(
                self.ENDPOINT,
                data=data,
                headers={
                    "User-Agent": self.user_agent,
                    "Accept": "application/json",
                },
            )

        except httpx.TimeoutException:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="timeout",
                query=url,
                error=(
                    "PhishTank lookup timed out."
                ),
            )

        except httpx.RequestError as exc:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="error",
                query=url,
                error=(
                    "PhishTank network error: "
                    f"{type(exc).__name__}"
                ),
            )

        # -------------------------------------------------
        # Rate limiting
        # -------------------------------------------------

        if response.status_code in {
            429,
            509,
        }:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="rate_limited",
                query=url,
                error=(
                    "PhishTank rate limit reached."
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
                    "PhishTank refused the request."
                ),
            )

        if response.status_code >= 400:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="error",
                query=url,
                error=(
                    "PhishTank returned HTTP "
                    f"{response.status_code}."
                ),
            )

        # -------------------------------------------------
        # JSON
        # -------------------------------------------------

        try:

            payload = response.json()

        except ValueError:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="error",
                query=url,
                error=(
                    "PhishTank returned invalid JSON."
                ),
            )

        results = payload.get(
            "results"
        )

        # Depending on response representation, results
        # can appear as a dictionary or collection.

        if isinstance(
            results,
            dict,
        ):

            result = results

        elif isinstance(
            results,
            list,
        ) and results:

            result = results[0]

        else:

            result = {}

        if not isinstance(
            result,
            dict,
        ):

            result = {}

        in_database = self._as_bool(
            result.get(
                "in_database",
                False,
            )
        )

        if not in_database:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="no_match",
                query=url,
                matched=False,
                match_count=0,
                matches=[],
            )

        # -------------------------------------------------
        # Match
        # -------------------------------------------------

        phish_id = result.get(
            "phish_id"
        )

        detail_page = result.get(
            "phish_detail_page"
        )

        match = OSINTMatch(
            source=self.SOURCE,

            match_type="phishing_url",

            indicator=str(
                result.get(
                    "url",
                    url,
                )
            ),

            reference=(
                str(detail_page)
                if detail_page
                else None
            ),

            details={
                "phish_id": phish_id,

                "verified": self._as_bool(
                    result.get(
                        "verified",
                        False,
                    )
                ),

                "valid": self._as_bool(
                    result.get(
                        "valid",
                        False,
                    )
                ),

                "verified_at": result.get(
                    "verified_at"
                ),

                "submitted_at": result.get(
                    "submitted_at"
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

            metadata={
                "app_key_used": bool(
                    self.app_key
                ),
            },
        )