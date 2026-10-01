from __future__ import annotations

from typing import Any

import httpx


class IPAPIProvider:
    """
    ipapi.co integration.

    This class knows how to communicate with ipapi.co.
    It does not perform security scoring or threat analysis.
    """

    BASE_URL = "https://ipapi.co"

    PROVIDER_NAME = "ipapi.co"

    def __init__(
        self,
        client: httpx.AsyncClient,
    ) -> None:

        self.client = client

    async def lookup(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """
        Query ipapi.co for one IP address.
        """

        url = (
            f"{self.BASE_URL}/"
            f"{ip}/json/"
        )

        response = await self.client.get(
            url
        )

        # -------------------------------------------------
        # Rate limit
        # -------------------------------------------------

        if response.status_code == 429:

            return {
                "success": False,
                "status": "rate_limited",
                "error": "Provider rate limit reached.",
            }

        # -------------------------------------------------
        # Not found
        # -------------------------------------------------

        if response.status_code == 404:

            return {
                "success": False,
                "status": "not_found",
                "error": "IP address was not found.",
            }

        # -------------------------------------------------
        # Other HTTP errors
        # -------------------------------------------------

        if response.status_code >= 400:

            return {
                "success": False,
                "status": "error",
                "error": (
                    "Provider returned HTTP "
                    f"{response.status_code}."
                ),
            }

        # -------------------------------------------------
        # JSON decoding
        # -------------------------------------------------

        try:

            data = response.json()

        except ValueError:

            return {
                "success": False,
                "status": "error",
                "error": (
                    "Provider returned an invalid "
                    "JSON response."
                ),
            }

        # -------------------------------------------------
        # ipapi may return a JSON-level error even when
        # the HTTP request succeeded.
        # -------------------------------------------------

        if data.get("error") is True:

            reason = data.get(
                "reason",
                "Provider reported an error.",
            )

            return {
                "success": False,
                "status": "not_found",
                "error": str(reason),
            }

        # -------------------------------------------------
        # Success
        # -------------------------------------------------

        return {
            "success": True,
            "status": "success",
            "data": data,
        }