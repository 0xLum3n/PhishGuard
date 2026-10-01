from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

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

    Providers run concurrently, failures stay isolated, and
    provider matches are aggregated without generating a
    threat score.
    """

    def __init__(self, providers=None) -> None:
        self.providers = providers

    @staticmethod
    def _build_default_providers(client: httpx.AsyncClient):
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
                max_results=settings.URLSCAN_MAX_RESULTS,
            ),
        ]

    @staticmethod
    def _calculate_status(
        providers: list[OSINTProviderResult],
    ) -> OSINTOverallStatus:
        if not providers:
            return "not_configured"

        configured = [
            provider
            for provider in providers
            if provider.status != "not_configured"
        ]

        if not configured:
            return "not_configured"

        successful = [
            provider
            for provider in configured
            if provider.status in {"success", "no_match"}
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

    @staticmethod
    async def _lookup_provider(
        provider,
        url: str,
        domain: str | None,
    ):
        """
        Preserve provider-specific lookup contracts.

        PhishTank:
            lookup(url)

        urlscan:
            lookup(url, hostname=..., registrable_domain=...)

        Existing two-argument providers:
            lookup(url, domain)
        """

        if isinstance(provider, PhishTankProvider):
            return await provider.lookup(url)

        if isinstance(provider, URLScanProvider):
            parsed = urlsplit(url)

            hostname = (
                parsed.hostname or ""
            ).strip().lower()

            registrable_domain = (
                domain or ""
            ).strip().lower()

            return await provider.lookup(
                url,
                hostname=hostname,
                registrable_domain=(
                    registrable_domain or None
                ),
            )

        return await provider.lookup(url, domain)

    async def lookup(
        self,
        url: str,
        domain: str | None,
    ) -> OSINTResult:
        timeout = httpx.Timeout(
            timeout=settings.OSINT_TIMEOUT
        )

        if self.providers is not None:
            provider_list = list(self.providers)

            provider_results = await asyncio.gather(
                *[
                    self._lookup_provider(
                        provider,
                        url,
                        domain,
                    )
                    for provider in provider_list
                ],
                return_exceptions=True,
            )

        else:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
            ) as client:
                provider_list = self._build_default_providers(client)

                provider_results = await asyncio.gather(
                    *[
                        self._lookup_provider(
                            provider,
                            url,
                            domain,
                        )
                        for provider in provider_list
                    ],
                    return_exceptions=True,
                )

        normalized_results: list[OSINTProviderResult] = []

        for index, result in enumerate(provider_results):
            if isinstance(result, OSINTProviderResult):
                normalized_results.append(result)
                continue

            provider_name = (
                type(provider_list[index]).__name__
                if index < len(provider_list)
                else "OSINTProvider"
            )

            normalized_results.append(
                OSINTProviderResult(
                    source=provider_name,
                    status="error",
                    query=domain or url,
                    matched=False,
                    match_count=0,
                    matches=[],
                    metadata={},
                    error=(
                        "Unexpected provider exception: "
                        f"{type(result).__name__}: {result}"
                    ),
                )
            )

        matches = [
            match
            for provider in normalized_results
            for match in provider.matches
        ]

        status = self._calculate_status(
            normalized_results
        )

        return OSINTResult(
            status=status,
            providers=normalized_results,
            matches=matches,
            total_matches=len(matches),
        )
