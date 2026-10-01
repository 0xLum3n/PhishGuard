from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import httpx

from app.providers.ip_geolocation import IPAPIProvider
from app.schemas.response import (
    IPClassification,
    IPIntelligence,
    IPIntelligenceResponse,
)


# =========================================================
# Configuration
# =========================================================

IP_LOOKUP_TIMEOUT = 5.0

MAX_IP_LOOKUPS_PER_ANALYSIS = 5


# =========================================================
# Helpers
# =========================================================

def _parse_ip(
    value: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """
    Parse and validate an IP address.
    """

    try:

        return ipaddress.ip_address(
            value
        )

    except ValueError as exc:

        raise ValueError(
            f"Invalid IP address: {value}"
        ) from exc


def _classify_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> IPClassification:
    """
    Classify special-use/non-public addresses.
    """

    if ip.is_unspecified:
        return "unspecified"

    if ip.is_loopback:
        return "loopback"

    if ip.is_link_local:
        return "link_local"

    if ip.is_multicast:
        return "multicast"

    if ip.is_reserved:
        return "reserved"

    if ip.is_private:
        return "private"

    return "public"


def _provider_status_to_model_status(
    status: str,
):
    """
    Convert provider status to our API status values.
    """

    if status == "rate_limited":
        return "rate_limited"

    if status == "timeout":
        return "timeout"

    if status == "not_found":
        return "not_found"

    return "error"


def _safe_string(
    value: Any,
) -> str | None:
    """
    Convert provider values safely to strings.
    """

    if value is None:
        return None

    text = str(value).strip()

    return text or None


def _safe_float(
    value: Any,
) -> float | None:
    """
    Convert provider values safely to float.
    """

    if value is None:
        return None

    try:

        return float(value)

    except (
        TypeError,
        ValueError,
    ):

        return None


# =========================================================
# IP SERVICE
# =========================================================

class IPService:
    """
    IP intelligence service.

    Responsibilities:

    - Validate IP addresses
    - Classify special/private addresses
    - Avoid external lookups for non-public IPs
    - Query geolocation provider for public IPs
    - Normalize provider responses
    - Handle provider failures
    """

    def __init__(
        self,
        provider_factory=IPAPIProvider,
        max_lookups: int = MAX_IP_LOOKUPS_PER_ANALYSIS,
    ) -> None:

        if max_lookups <= 0:

            raise ValueError(
                "max_lookups must be greater than zero."
            )

        self.provider_factory = provider_factory

        self.max_lookups = max_lookups


    # =====================================================
    # Public single-IP normalization
    # =====================================================

    @staticmethod
    def _build_special_ip_result(
        ip: str,
        parsed_ip: ipaddress.IPv4Address
        | ipaddress.IPv6Address,
        classification: IPClassification,
    ) -> IPIntelligence:

        status = classification

        return IPIntelligence(
            ip=ip,
            version=(
                4
                if parsed_ip.version == 4
                else 6
            ),
            classification=classification,
            status=status,
            source=None,
            error=(
                "External geolocation lookup was skipped "
                "because this is not a public IP address."
            ),
        )


    # =====================================================
    # Provider response normalization
    # =====================================================

    @staticmethod
    def _normalize_provider_result(
        ip: str,
        provider_result: dict[str, Any],
    ) -> IPIntelligence:

        # -------------------------------------------------
        # Parse IP again for guaranteed version information.
        # -------------------------------------------------

        parsed_ip = _parse_ip(
            ip
        )

        version = (
            4
            if parsed_ip.version == 4
            else 6
        )

        # -------------------------------------------------
        # Provider failure
        # -------------------------------------------------

        if not provider_result.get(
            "success",
            False,
        ):

            provider_status = provider_result.get(
                "status",
                "error",
            )

            error = provider_result.get(
                "error",
                "IP intelligence provider failed.",
            )

            return IPIntelligence(
                ip=ip,
                version=version,
                classification="public",
                status=_provider_status_to_model_status(
                    provider_status
                ),
                source=IPAPIProvider.PROVIDER_NAME,
                error=str(error),
            )

        # -------------------------------------------------
        # Successful response
        # -------------------------------------------------

        data = provider_result.get(
            "data",
            {},
        )

        return IPIntelligence(
            ip=ip,
            version=version,
            classification="public",
            status="success",
            source=IPAPIProvider.PROVIDER_NAME,

            country_code=_safe_string(
                data.get("country_code")
            ),

            country_name=_safe_string(
                data.get("country_name")
            ),

            region=_safe_string(
                data.get("region")
            ),

            region_code=_safe_string(
                data.get("region_code")
            ),

            city=_safe_string(
                data.get("city")
            ),

            postal=_safe_string(
                data.get("postal")
            ),

            latitude=_safe_float(
                data.get("latitude")
            ),

            longitude=_safe_float(
                data.get("longitude")
            ),

            timezone=_safe_string(
                data.get("timezone")
            ),

            asn=_safe_string(
                data.get("asn")
            ),

            organization=_safe_string(
                data.get("org")
            ),

            hostname=_safe_string(
                data.get("hostname")
            ),

            error=None,
        )


    # =====================================================
    # Single public lookup
    # =====================================================

    async def _lookup_public_ip(
        self,
        provider: IPAPIProvider,
        ip: str,
    ) -> IPIntelligence:

        try:

            provider_result = (
                await provider.lookup(
                    ip
                )
            )

            return self._normalize_provider_result(
                ip,
                provider_result,
            )

        except (
            httpx.TimeoutException,
            TimeoutError,
        ):

            parsed_ip = _parse_ip(
                ip
            )

            return IPIntelligence(
                ip=ip,
                version=(
                    4
                    if parsed_ip.version == 4
                    else 6
                ),
                classification="public",
                status="timeout",
                source=IPAPIProvider.PROVIDER_NAME,
                error=(
                    "IP intelligence lookup timed out."
                ),
            )

        except httpx.RequestError as exc:

            parsed_ip = _parse_ip(
                ip
            )

            return IPIntelligence(
                ip=ip,
                version=(
                    4
                    if parsed_ip.version == 4
                    else 6
                ),
                classification="public",
                status="error",
                source=IPAPIProvider.PROVIDER_NAME,
                error=(
                    "Network error while contacting "
                    "IP intelligence provider: "
                    f"{type(exc).__name__}"
                ),
            )

        except Exception as exc:

            parsed_ip = _parse_ip(
                ip
            )

            return IPIntelligence(
                ip=ip,
                version=(
                    4
                    if parsed_ip.version == 4
                    else 6
                ),
                classification="public",
                status="error",
                source=IPAPIProvider.PROVIDER_NAME,
                error=(
                    "Unexpected IP intelligence error: "
                    f"{type(exc).__name__}"
                ),
            )


    # =====================================================
    # Many IPs
    # =====================================================

    async def lookup_many(
        self,
        ips: list[str],
    ) -> IPIntelligenceResponse:

        # -------------------------------------------------
        # Deduplicate while preserving order.
        # -------------------------------------------------

        unique_ips: list[str] = []

        seen: set[str] = set()

        for value in ips:

            value = value.strip()

            if not value:
                continue

            if value in seen:
                continue

            seen.add(value)

            unique_ips.append(value)

        total_ips = len(
            unique_ips
        )

        # -------------------------------------------------
        # No IPs at all.
        # -------------------------------------------------

        if not unique_ips:

            return IPIntelligenceResponse(
                status="no_public_ips",
                total_ips=0,
                public_ips=0,
                enriched_ips=0,
                lookup_limit=self.max_lookups,
                limit_reached=False,
                results=[],
            )

        # -------------------------------------------------
        # Parse/classify every IP.
        # -------------------------------------------------

        parsed_items: list[
            tuple[
                str,
                ipaddress.IPv4Address
                | ipaddress.IPv6Address,
                IPClassification,
            ]
        ] = []

        immediate_results: list[
            IPIntelligence
        ] = []

        public_ip_strings: list[str] = []

        for value in unique_ips:

            try:

                parsed_ip = _parse_ip(
                    value
                )

            except ValueError:

                # This should not normally happen because IPs
                # originate from DNS, but keep the service
                # defensive.

                immediate_results.append(
                    IPIntelligence(
                        ip=value,
                        version=4,
                        classification="reserved",
                        status="error",
                        source=None,
                        error=(
                            "Invalid IP address returned "
                            "to IP intelligence service."
                        ),
                    )
                )

                continue

            classification = _classify_ip(
                parsed_ip
            )

            parsed_items.append(
                (
                    value,
                    parsed_ip,
                    classification,
                )
            )

            if classification == "public":

                public_ip_strings.append(
                    value
                )

            else:

                immediate_results.append(
                    self._build_special_ip_result(
                        value,
                        parsed_ip,
                        classification,
                    )
                )

        public_ip_count = len(
            public_ip_strings
        )

        # -------------------------------------------------
        # Apply lookup limit.
        # -------------------------------------------------

        selected_public_ips = (
            public_ip_strings[
                : self.max_lookups
            ]
        )

        limit_reached = (
            public_ip_count
            > self.max_lookups
        )

        # -------------------------------------------------
        # No public IPs.
        # -------------------------------------------------

        if not selected_public_ips:

            return IPIntelligenceResponse(
                status="no_public_ips",
                total_ips=total_ips,
                public_ips=public_ip_count,
                enriched_ips=0,
                lookup_limit=self.max_lookups,
                limit_reached=limit_reached,
                results=immediate_results,
            )

        # -------------------------------------------------
        # External provider.
        # -------------------------------------------------

        timeout = httpx.Timeout(
            timeout=IP_LOOKUP_TIMEOUT
        )

        async with httpx.AsyncClient(
            timeout=timeout,
            headers={
                "Accept": "application/json",
                "User-Agent": "PhishGuard/0.1",
            },
        ) as client:

            provider = self.provider_factory(
                client
            )

            tasks = [
                self._lookup_public_ip(
                    provider,
                    ip,
                )
                for ip in selected_public_ips
            ]

            public_results = await asyncio.gather(
                *tasks
            )

        # -------------------------------------------------
        # Combine.
        # -------------------------------------------------

        all_results = (
            immediate_results
            + public_results
        )

        successful_public = sum(
            1
            for result in public_results
            if result.status == "success"
        )

        failed_public = (
            len(public_results)
            - successful_public
        )

        # -------------------------------------------------
        # Overall status.
        # -------------------------------------------------

        if successful_public == 0:

            overall_status = "error"

        elif failed_public > 0 or limit_reached:

            overall_status = "partial"

        else:

            overall_status = "completed"

        return IPIntelligenceResponse(
            status=overall_status,

            total_ips=total_ips,

            public_ips=public_ip_count,

            enriched_ips=successful_public,

            lookup_limit=self.max_lookups,

            limit_reached=limit_reached,

            results=all_results,
        )