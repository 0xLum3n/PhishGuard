from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import tldextract

from app.schemas.response import (
    DNSOverallStatus,
    DNSQueryStatus,
    DNSRecordResult,
    DNSResult,
)


# =========================================================
# Configuration
# =========================================================

HOSTNAME_RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
)

DOMAIN_RECORD_TYPES = (
    "MX",
    "NS",
    "TXT",
)

DEFAULT_DNS_LIFETIME = 5.0

DEFAULT_DNS_TIMEOUT = 2.0


# =========================================================
# DNS Service
# =========================================================

class DNSService:
    """
    DNS intelligence service.

    Exact hostname:
        A
        AAAA
        CNAME
        TXT

    Registrable domain:
        MX
        NS
        TXT

    Backward compatibility:
        `records` is also populated so older callers/tests
        continue to work.
    """

    def __init__(
        self,
        resolver: dns.asyncresolver.Resolver | None = None,
        lifetime: float = DEFAULT_DNS_LIFETIME,
        timeout: float = DEFAULT_DNS_TIMEOUT,
    ) -> None:

        if lifetime <= 0:
            raise ValueError(
                "DNS lifetime must be greater than zero."
            )

        if timeout <= 0:
            raise ValueError(
                "DNS timeout must be greater than zero."
            )

        self.resolver = (
            resolver
            if resolver is not None
            else dns.asyncresolver.Resolver()
        )

        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime

        self.lifetime = lifetime

    # =====================================================
    # Hostname normalization
    # =====================================================

    @staticmethod
    def _normalize_hostname(
        hostname: str,
    ) -> str:
        """
        Normalize a hostname without changing its meaning.
        """

        if not isinstance(hostname, str):
            raise ValueError(
                "Hostname must be a string."
            )

        normalized = (
            hostname
            .strip()
            .rstrip(".")
            .lower()
        )

        if not normalized:
            raise ValueError(
                "Hostname cannot be empty."
            )

        return normalized

    # =====================================================
    # Registrable-domain inference
    # =====================================================

    @staticmethod
    def _infer_registrable_domain(
        hostname: str,
    ) -> str | None:
        """
        Infer the registrable domain using the Public Suffix List.

        Example:

            www.example.co.uk

        becomes:

            example.co.uk
        """

        try:

            extracted = tldextract.extract(
                hostname
            )

            if extracted.top_domain_under_public_suffix:
                return (
                    extracted.top_domain_under_public_suffix
                )

        except Exception:
            # Domain inference must never crash DNS analysis.
            pass

        return None

    # =====================================================
    # Record formatter
    # =====================================================

    @staticmethod
    def _format_record(
        record: Any,
    ) -> str:
        """
        Convert dnspython RDATA to a stable string.
        """

        try:
            return record.to_text().strip()

        except AttributeError:
            return str(record).strip()

    # =====================================================
    # Single DNS query
    # =====================================================

    async def _resolve_record(
        self,
        name: str,
        record_type: str,
    ) -> DNSRecordResult:
        """
        Resolve one DNS record type.
        """

        try:

            answer = await self.resolver.resolve(
                name,
                record_type,
                search=False,
                raise_on_no_answer=True,
                lifetime=self.lifetime,
            )

            records = [
                self._format_record(record)
                for record in answer
            ]

            return DNSRecordResult(
                record_type=record_type,
                queried_name=name,
                status="success",
                records=records,
                error=None,
            )

        except dns.resolver.NXDOMAIN:

            return DNSRecordResult(
                record_type=record_type,
                queried_name=name,
                status="nxdomain",
                records=[],
                error=(
                    "The queried DNS name does not exist."
                ),
            )

        except dns.resolver.NoAnswer:

            return DNSRecordResult(
                record_type=record_type,
                queried_name=name,
                status="no_answer",
                records=[],
                error=(
                    f"No {record_type} record was returned "
                    f"for {name}."
                ),
            )

        except dns.resolver.LifetimeTimeout:

            return DNSRecordResult(
                record_type=record_type,
                queried_name=name,
                status="timeout",
                records=[],
                error=(
                    "DNS query exceeded the configured "
                    f"{self.lifetime:.1f}s lifetime."
                ),
            )

        except dns.resolver.NoNameservers:

            return DNSRecordResult(
                record_type=record_type,
                queried_name=name,
                status="no_nameservers",
                records=[],
                error=(
                    "No usable DNS nameserver was available."
                ),
            )

        except dns.resolver.YXDOMAIN:

            return DNSRecordResult(
                record_type=record_type,
                queried_name=name,
                status="error",
                records=[],
                error=(
                    "DNS query resulted in an invalid "
                    "or excessively long DNS name."
                ),
            )

        except dns.exception.DNSException as exc:

            return DNSRecordResult(
                record_type=record_type,
                queried_name=name,
                status="error",
                records=[],
                error=(
                    f"DNS error: {type(exc).__name__}"
                ),
            )

        except Exception as exc:

            return DNSRecordResult(
                record_type=record_type,
                queried_name=name,
                status="error",
                records=[],
                error=(
                    "Unexpected DNS error: "
                    f"{type(exc).__name__}"
                ),
            )

    # =====================================================
    # Overall status
    # =====================================================

    @staticmethod
    def _calculate_overall_status(
        results: list[DNSRecordResult],
    ) -> DNSOverallStatus:
        """
        Determine the overall DNS state.

        Existing records + one failure:
            partial

        At least one successful record:
            resolved

        Everything missing:
            no_data

        All queries indicate NXDOMAIN:
            nxdomain
        """

        if not results:
            return "no_data"

        has_records = any(
            bool(result.records)
            for result in results
        )

        has_hard_error = any(
            result.status in {
                "timeout",
                "no_nameservers",
                "error",
            }
            for result in results
        )

        all_nxdomain = all(
            result.status == "nxdomain"
            for result in results
        )

        if has_records and has_hard_error:
            return "partial"

        if has_records:
            return "resolved"

        if all_nxdomain:
            return "nxdomain"

        if has_hard_error:
            return "error"

        return "no_data"

    # =====================================================
    # Legacy record map
    # =====================================================

    @staticmethod
    def _build_legacy_records(
        hostname_records: dict[str, DNSRecordResult],
        domain_records: dict[str, DNSRecordResult],
        hostname_txt_records: DNSRecordResult,
    ) -> dict[str, DNSRecordResult]:
        """
        Construct the old flat `records` dictionary.

        Old callers:

            result.records["A"]
            result.records["AAAA"]
            result.records["CNAME"]
            result.records["MX"]
            result.records["NS"]
            result.records["TXT"]

        New callers should prefer:

            hostname_records
            domain_records
            hostname_txt_records
        """

        # Start with ALL hostname records.

        # This guarantees that A/AAAA/CNAME remain available
        # to older code even when their result contains no data.
        legacy_records = dict(
            hostname_records
        )

        # TXT:
        #
        # Prefer the exact-hostname TXT result if it exists
        # as a successful/non-empty result.
        #
        # Otherwise expose the domain-level TXT result.

        if hostname_txt_records.records:

            legacy_records["TXT"] = (
                hostname_txt_records
            )

        elif "TXT" in domain_records:

            legacy_records["TXT"] = (
                domain_records["TXT"]
            )

        # Add domain-level records only if their record type
        # isn't already represented.

        for (
            record_type,
            record_result,
        ) in domain_records.items():

            if record_type not in legacy_records:

                legacy_records[
                    record_type
                ] = record_result

        return legacy_records

    # =====================================================
    # Main lookup
    # =====================================================

    async def lookup(
        self,
        hostname: str,
        registrable_domain: str | None = None,
    ) -> DNSResult:
        """
        Perform DNS intelligence for a hostname.

        Backward-compatible usage:

            await service.lookup(
                "example.com"
            )

        Preferred usage:

            await service.lookup(
                hostname="www.example.com",
                registrable_domain="example.com",
            )
        """

        hostname = self._normalize_hostname(
            hostname
        )

        # =================================================
        # IMPORTANT:
        # Detect IP FIRST.
        #
        # An IP address is not a domain, so we must NOT
        # infer a registrable domain such as:
        #
        #     192.168.1.100
        #
        # before checking whether it is an IP.
        # =================================================

        try:

            ipaddress.ip_address(
                hostname
            )

            return DNSResult(
                hostname=hostname,

                registrable_domain=None,

                status="not_applicable",

                resolved_ips=[
                    hostname
                ],

                hostname_records={},

                domain_records={},

                hostname_txt_records=None,

                # Backward compatibility
                records={},
            )

        except ValueError:
            pass

        # =================================================
        # Determine registrable domain
        # =================================================

        if registrable_domain:

            registrable_domain = (
                self._normalize_hostname(
                    registrable_domain
                )
            )

        else:

            registrable_domain = (
                self._infer_registrable_domain(
                    hostname
                )
            )

        # =================================================
        # HOSTNAME QUERIES
        # =================================================

        hostname_tasks = [
            self._resolve_record(
                hostname,
                record_type,
            )
            for record_type in HOSTNAME_RECORD_TYPES
        ]

        hostname_txt_task = (
            self._resolve_record(
                hostname,
                "TXT",
            )
        )

        # =================================================
        # DOMAIN QUERIES
        # =================================================

        domain_tasks: list[Any] = []

        if registrable_domain:

            domain_tasks = [
                self._resolve_record(
                    registrable_domain,
                    record_type,
                )
                for record_type in DOMAIN_RECORD_TYPES
            ]

        # =================================================
        # Execute hostname queries concurrently
        # =================================================

        hostname_results = await asyncio.gather(
            *hostname_tasks
        )

        hostname_txt_result = (
            await hostname_txt_task
        )

        # =================================================
        # Execute domain queries concurrently
        # =================================================

        if domain_tasks:

            domain_results = await asyncio.gather(
                *domain_tasks
            )

        else:

            domain_results = []

        # =================================================
        # Convert results to dictionaries
        # =================================================

        hostname_records = {
            result.record_type: result
            for result in hostname_results
        }

        domain_records = {
            result.record_type: result
            for result in domain_results
        }

        # =================================================
        # Collect resolved IPs
        # =================================================

        resolved_ips: list[str] = []

        for record_type in (
            "A",
            "AAAA",
        ):

            result = hostname_records.get(
                record_type
            )

            if result is None:
                continue

            for value in result.records:

                if value not in resolved_ips:

                    resolved_ips.append(value)

        # =================================================
        # Construct backward-compatible record map
        # =================================================

        legacy_records = (
            self._build_legacy_records(
                hostname_records=hostname_records,
                domain_records=domain_records,
                hostname_txt_records=hostname_txt_result,
            )
        )

        # =================================================
        # Overall status
        # =================================================

        all_results = (
            hostname_results
            + [hostname_txt_result]
            + domain_results
        )

        overall_status = (
            self._calculate_overall_status(
                all_results
            )
        )

        # =================================================
        # Final response
        # =================================================

        return DNSResult(
            hostname=hostname,

            registrable_domain=(
                registrable_domain
            ),

            status=overall_status,

            resolved_ips=resolved_ips,

            # New architecture
            hostname_records=hostname_records,

            domain_records=domain_records,

            hostname_txt_records=(
                hostname_txt_result
            ),

            # Backward compatibility
            records=legacy_records,
        )