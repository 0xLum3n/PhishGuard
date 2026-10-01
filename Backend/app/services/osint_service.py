from __future__ import annotations

import asyncio

import httpx

from app.core.config import settings
from app.providers.phishtank import PhishTankProvider
from app.providers.urlhaus import URLhausProvider
from app.providers.urlscan import URLScanProvider
from app.schemas.response import (
    OSINTOverallStatus,
    OSINTProviderResult,
    OSINTResult,
)


class OSINTService:
    """
    Coordinates all OSINT providers.

    The service:

    - executes providers concurrently
    - keeps provider failures isolated
    - aggregates matches
    - never generates a threat score
    """

    def __init__(
        self,
        providers=None,
    ) -> None:

        self.providers = providers


    # =====================================================
    # Default providers
    # =====================================================

    @staticmethod
    def _build_default_providers(
        client: httpx.AsyncClient,
    ):

        return [
            PhishTankProvider(
                client=client,
                app_key=settings.PHISHTANK_APP_KEY,
                user_agent=settings.USER_AGENT,
            ),

            URLhausProvider(
                client=client,
                auth_key=settings.URLHAUS_AUTH_KEY,
            ),

            URLScanProvider(
                client=client,
                api_key=settings.URLSCAN_API_KEY,
                max_results=(
                    settings.URLSCAN_MAX_RESULTS
                ),
            ),
        ]


    # =====================================================
    # Aggregate status
    # =====================================================

    @staticmethod
    def _calculate_status(
        providers: list[OSINTProviderResult],
    ) -> OSINTOverallStatus:

        if not providers:

            return "not_configured"

        configured = [
            provider
            for provider in providers
            if provider.status
            != "not_configured"
        ]

        if not configured:

            return "not_configured"

        successful = [
            provider
            for provider in configured
            if provider.status
            in {
                "success",
                "no_match",
            }
        ]

        has_matches = any(
            provider.matched
            for provider in configured
        )

        has_failures = any(
            provider.status
            not in {
                "success",
                "no_match",
                "not_configured",
            }
            for provider in configured
        )

        if has_failures and successful:

            return "partial"

        if has_failures and not successful:

            return "error"

        if has_matches:

            return "completed"

        return "no_matches"


    # =====================================================
    # Lookup
    # =====================================================

    async def lookup(
        self,
        url: str,
        domain: str | None,
    ) -> OSINTResult:

        timeout = httpx.Timeout(
            timeout=settings.OSINT_TIMEOUT
        )

        # -------------------------------------------------
        # Tests can inject fake providers.
        # -------------------------------------------------

        if self.providers is not None:

            try:

                provider_results = await asyncio.gather(
                    *[
                        provider.lookup(
                            url,
                            domain,
                        )
                        for provider in self.providers
                    ],
                    return_exceptions=True,
                )

            except Exception as exc:

                return OSINTResult(
                    status="error",
                    providers=[],
                    matches=[],
                    total_matches=0,
                )

        else:

            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
            ) as client:

                providers = (
                    self._build_default_providers(
                        client
                    )
                )

                provider_results = await asyncio.gather(
                    *[
                        provider.lookup(
                            url,
                            domain,
                        )
                        for provider in providers
                    ],
                    return_exceptions=True,
                )

        # -------------------------------------------------
        # Normalize unexpected provider exceptions.
        # -------------------------------------------------

        normalized_results: list[
            OSINTProviderResult
        ] = []

        for index, result in enumerate(
            provider_results
        ):

            if isinstance(
                result,
                OSINTProviderResult,
            ):

                normalized_results.append(
                    result
                )

            else:

                provider_name = (
                    type(
                        self.providers[index]
                    ).__name__
                    if self.providers is not None
                    and index < len(
                        self.providers
                    )
                    else "OSINT Provider"
                )

                normalized_results.append(
                    OSINTProviderResult(
                        source=provider_name,
                        status="error",
                        query=domain or url,
                        error=(
                            "Unexpected provider exception: "
                            f"{type(result).__name__}"
                        ),
                    )
                )

        # -------------------------------------------------
        # Aggregate matches
        # -------------------------------------------------

        matches = []

        for provider in normalized_results:

            matches.extend(
                provider.matches
            )

        status = self._calculate_status(
            normalized_results
        )

        return OSINTResult(
            status=status,

            providers=normalized_results,

            matches=matches,

            total_matches=len(matches),
        )