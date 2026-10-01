from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx


class RDAPProvider:
    """
    Low-level RDAP provider.

    Responsibilities:

    - Retrieve IANA RDAP bootstrap information
    - Select the correct RDAP server for a TLD
    - Query the domain RDAP endpoint
    - Return raw JSON to the service layer

    It does NOT normalize WHOIS data or perform security scoring.
    """

    IANA_BOOTSTRAP_URL = (
        "https://data.iana.org/rdap/dns.json"
    )

    DOMAIN_PATH = "/domain/"

    SOURCE_NAME = "IANA RDAP Bootstrap"

    def __init__(
        self,
        client: httpx.AsyncClient,
    ) -> None:

        self.client = client

        self._bootstrap_cache: dict[str, list[str]] | None = None

        self._bootstrap_lock = asyncio.Lock()

    # =====================================================
    # Bootstrap registry
    # =====================================================

    async def _load_bootstrap(
        self,
    ) -> dict[str, list[str]]:

        if self._bootstrap_cache is not None:
            return self._bootstrap_cache

        async with self._bootstrap_lock:

            if self._bootstrap_cache is not None:
                return self._bootstrap_cache

            response = await self.client.get(
                self.IANA_BOOTSTRAP_URL,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "PhishGuard/0.1",
                },
            )

            response.raise_for_status()

            try:

                payload = response.json()

            except ValueError as exc:

                raise ValueError(
                    "IANA RDAP bootstrap returned invalid JSON."
                ) from exc

            services = payload.get(
                "services"
            )

            if not isinstance(
                services,
                list,
            ):

                raise ValueError(
                    "IANA RDAP bootstrap response is missing "
                    "a valid services array."
                )

            registry: dict[str, list[str]] = {}

            for service in services:

                if not isinstance(
                    service,
                    list,
                ):

                    continue

                if len(service) != 2:
                    continue

                prefixes, urls = service

                if not isinstance(
                    prefixes,
                    list,
                ):
                    continue

                if not isinstance(
                    urls,
                    list,
                ):
                    continue

                clean_urls = [
                    str(url).rstrip("/")
                    for url in urls
                    if isinstance(url, str)
                    and url.strip()
                ]

                if not clean_urls:
                    continue

                for prefix in prefixes:

                    if not isinstance(
                        prefix,
                        str,
                    ):
                        continue

                    registry[
                        prefix.lower().strip(".")
                    ] = clean_urls

            self._bootstrap_cache = registry

            return registry

    # =====================================================
    # Find RDAP server
    # =====================================================

    async def find_server(
        self,
        domain: str,
    ) -> str | None:

        bootstrap = await self._load_bootstrap()

        labels = domain.lower().strip(
            "."
        ).split(".")

        # -------------------------------------------------
        # Try longest suffix first.
        #
        # example.co.uk
        #
        # candidates:
        #
        #     example.co.uk
        #     co.uk
        #     uk
        #
        # Bootstrap may contain a more specific mapping.
        # -------------------------------------------------

        for index in range(
            0,
            len(labels),
        ):

            suffix = ".".join(
                labels[index:]
            )

            urls = bootstrap.get(
                suffix
            )

            if urls:

                return urls[0].rstrip("/")

        return None

    # =====================================================
    # Domain lookup
    # =====================================================

    async def lookup(
        self,
        domain: str,
    ) -> dict[str, Any]:

        server = await self.find_server(
            domain
        )

        if server is None:

            return {
                "success": False,
                "status": "unsupported",
                "error": (
                    "No RDAP server was found in the "
                    "IANA bootstrap registry for this domain."
                ),
            }

        url = (
            f"{server}"
            f"{self.DOMAIN_PATH}"
            f"{domain}"
        )

        try:

            response = await self.client.get(
                url,
                headers={
                    "Accept": (
                        "application/rdap+json, "
                        "application/json"
                    ),
                    "User-Agent": "PhishGuard/0.1",
                },
            )

        except httpx.TimeoutException:

            return {
                "success": False,
                "status": "timeout",
                "rdap_server": server,
                "error": (
                    "RDAP request timed out."
                ),
            }

        except httpx.RequestError as exc:

            return {
                "success": False,
                "status": "error",
                "rdap_server": server,
                "error": (
                    "RDAP network error: "
                    f"{type(exc).__name__}"
                ),
            }

        # -------------------------------------------------
        # HTTP status handling
        # -------------------------------------------------

        if response.status_code == 404:

            return {
                "success": False,
                "status": "not_found",
                "rdap_server": server,
                "error": (
                    "Domain was not found in the RDAP registry."
                ),
            }

        if response.status_code == 429:

            return {
                "success": False,
                "status": "rate_limited",
                "rdap_server": server,
                "error": (
                    "RDAP server rate limit was reached."
                ),
            }

        if response.status_code in {
            401,
            403,
        }:

            return {
                "success": False,
                "status": "forbidden",
                "rdap_server": server,
                "error": (
                    "RDAP server refused the request."
                ),
            }

        if response.status_code >= 500:

            return {
                "success": False,
                "status": "server_error",
                "rdap_server": server,
                "error": (
                    "RDAP server returned HTTP "
                    f"{response.status_code}."
                ),
            }

        if response.status_code >= 400:

            return {
                "success": False,
                "status": "error",
                "rdap_server": server,
                "error": (
                    "RDAP server returned HTTP "
                    f"{response.status_code}."
                ),
            }

        # -------------------------------------------------
        # JSON parsing
        # -------------------------------------------------

        try:

            payload = response.json()

        except (
            ValueError,
            json.JSONDecodeError,
        ):

            return {
                "success": False,
                "status": "invalid_response",
                "rdap_server": server,
                "error": (
                    "RDAP server returned invalid JSON."
                ),
            }

        if not isinstance(
            payload,
            dict,
        ):

            return {
                "success": False,
                "status": "invalid_response",
                "rdap_server": server,
                "error": (
                    "RDAP response is not a JSON object."
                ),
            }

        return {
            "success": True,
            "status": "success",
            "rdap_server": server,
            "data": payload,
        }