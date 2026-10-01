from __future__ import annotations

from typing import Any

import httpx

from app.schemas.response import (
    OSINTMatch,
    OSINTProviderResult,
)


class URLScanProvider:
    """
    urlscan.io historical-search provider.

    IMPORTANT:
        This implementation searches existing scans.

        It does NOT submit the user's URL for scanning.
    """

    SOURCE = "urlscan.io"

    ENDPOINT = (
        "https://urlscan.io/api/v1/search/"
    )

    def __init__(
        self,
        client: httpx.AsyncClient,
        api_key: str | None = None,
        max_results: int = 10,
    ) -> None:

        self.client = client

        self.api_key = api_key

        self.max_results = max(
            1,
            min(
                max_results,
                100,
            ),
        )

    # =====================================================
    # Safe nested getter
    # =====================================================

    @staticmethod
    def _get(
        data: dict[str, Any],
        *keys: str,
    ) -> Any:

        current: Any = data

        for key in keys:

            if not isinstance(
                current,
                dict,
            ):

                return None

            current = current.get(
                key
            )

        return current

    # =====================================================
    # Lookup
    # =====================================================

    async def lookup(
        self,
        url: str,
        domain: str | None = None,
    ) -> OSINTProviderResult:

        if not domain:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="error",
                query=url,
                error=(
                    "No registrable domain was available "
                    "for urlscan historical search."
                ),
            )

        # -------------------------------------------------
        # Domain search
        # -------------------------------------------------
        #
        # We deliberately search historical scans rather
        # than submitting the user's URL.
        # -------------------------------------------------

        params = {
            "q": f"page.domain:{domain}",
            "size": self.max_results,
        }

        headers = {
            "Accept": "application/json",
            "User-Agent": "PhishGuard/0.1",
        }

        if self.api_key:

            headers["api-key"] = self.api_key

        try:

            response = await self.client.get(
                self.ENDPOINT,
                params=params,
                headers=headers,
            )

        except httpx.TimeoutException:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="timeout",
                query=domain,
                error=(
                    "urlscan historical search timed out."
                ),
            )

        except httpx.RequestError as exc:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="error",
                query=domain,
                error=(
                    "urlscan network error: "
                    f"{type(exc).__name__}"
                ),
            )

        if response.status_code == 429:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="rate_limited",
                query=domain,
                error=(
                    "urlscan rate limit reached."
                ),
            )

        if response.status_code in {
            401,
            403,
        }:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="unauthorized",
                query=domain,
                error=(
                    "urlscan rejected the request or API key."
                ),
            )

        if response.status_code >= 400:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="error",
                query=domain,
                error=(
                    "urlscan returned HTTP "
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
                query=domain,
                error=(
                    "urlscan returned invalid JSON."
                ),
            )

        results = payload.get(
            "results",
            [],
        )

        if not isinstance(
            results,
            list,
        ):

            results = []

        total = payload.get(
            "total",
            len(results),
        )

        try:

            total = int(total)

        except (
            TypeError,
            ValueError,
        ):

            total = len(results)

        # -------------------------------------------------
        # No historical results
        # -------------------------------------------------

        if not results:

            return OSINTProviderResult(
                source=self.SOURCE,
                status="no_match",
                query=domain,
                matched=False,
                match_count=0,
                matches=[],
                metadata={
                    "total": total,
                    "authenticated": bool(
                        self.api_key
                    ),
                },
            )

        # -------------------------------------------------
        # Normalize results
        # -------------------------------------------------

        matches: list[
            OSINTMatch
        ] = []

        for item in results:

            if not isinstance(
                item,
                dict,
            ):

                continue

            scan_id = item.get(
                "_id"
            )

            page_url = (
                self._get(
                    item,
                    "page",
                    "url",
                )
            )

            page_domain = (
                self._get(
                    item,
                    "page",
                    "domain",
                )
            )

            page_ip = (
                self._get(
                    item,
                    "page",
                    "ip",
                )
            )

            scan_date = item.get(
                "task",
                {},
            )

            if isinstance(
                scan_date,
                dict,
            ):

                scan_date = scan_date.get(
                    "time"
                )

            else:

                scan_date = None

            stats = item.get(
                "stats",
                {},
            )

            if not isinstance(
                stats,
                dict,
            ):

                stats = {}

            country = self._get(
                item,
                "page",
                "country",
            )

            asn = self._get(
                item,
                "page",
                "asn",
            )

            reference = None

            if scan_id:

                reference = (
                    "https://urlscan.io/result/"
                    f"{scan_id}/"
                )

            matches.append(
                OSINTMatch(
                    source=self.SOURCE,

                    match_type="historical_scan",

                    indicator=(
                        str(page_url)
                        if page_url
                        else domain
                    ),

                    reference=reference,

                    details={
                        "scan_id": scan_id,

                        "domain": page_domain,

                        "ip": page_ip,

                        "country": country,

                        "asn": asn,

                        "scan_time": scan_date,

                        "stats": stats,
                    },
                )
            )

        return OSINTProviderResult(
            source=self.SOURCE,

            status="success",

            query=domain,

            matched=bool(matches),

            match_count=len(matches),

            matches=matches,

            metadata={
                "reported_total": total,

                "returned_count": len(
                    matches
                ),

                "authenticated": bool(
                    self.api_key
                ),
            },
        )