from __future__ import annotations

import tldextract

from app.schemas.response import (
    DNSRecordResult,
    DNSResult,
    SecurityFinding,
    DNSSecurityResult,
)


# =========================================================
# Step 6.2 — DNS security/context rules
# =========================================================

# A DNS response containing many addresses is common for CDNs,
# load balancers, and large services. This rule is therefore
# informational rather than an abuse verdict.
MULTIPLE_IP_THRESHOLD = 1


def _finding(
    *,
    rule_id: str,
    category: str,
    title: str,
    severity: str,
    confidence: str,
    description: str,
    evidence: dict,
) -> SecurityFinding:
    return SecurityFinding(
        rule_id=rule_id,
        category=category,
        title=title,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=evidence,
    )


def _record(
    records: dict[str, DNSRecordResult],
    record_type: str,
) -> DNSRecordResult | None:
    value = records.get(record_type)
    return value if isinstance(value, DNSRecordResult) else None


def _record_values(
    records: dict[str, DNSRecordResult],
    record_type: str,
) -> list[str]:
    result = _record(records, record_type)
    if result is None:
        return []
    return [str(value) for value in result.records if value is not None]


def _registrable_domain_from_cname(
    value: str,
) -> str | None:
    """Return the CNAME target's registrable domain using the PSL."""

    cleaned = value.strip().rstrip(".").lower()

    if not cleaned:
        return None

    extracted = tldextract.extract(cleaned)

    return extracted.registered_domain or cleaned


def _successful_records(
    records: dict[str, DNSRecordResult],
) -> list[DNSRecordResult]:
    return [
        record
        for record in records.values()
        if record.status == "success"
    ]


def _failed_queries(
    records: dict[str, DNSRecordResult],
) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []

    for record_type, record in records.items():
        if record.status in {
            "timeout",
            "no_nameservers",
            "error",
        }:
            failures.append(
                {
                    "record_type": record_type,
                    "status": record.status,
                }
            )

    return failures


def _all_query_results(
    dns_result: DNSResult,
) -> list[DNSRecordResult]:
    """Collect unique structured DNS query results."""

    results: list[DNSRecordResult] = []
    seen: set[tuple[str, str, str]] = set()

    sources = [
        dns_result.hostname_records,
        dns_result.domain_records,
    ]

    if dns_result.hostname_txt_records is not None:
        sources.append(
            {"TXT": dns_result.hostname_txt_records}
        )

    for records in sources:
        for record in records.values():
            key = (
                record.record_type,
                record.queried_name,
                record.status,
            )

            if key in seen:
                continue

            seen.add(key)
            results.append(record)

    return results


class DNSSecurityService:
    """
    Step 6.2: DNS security/context analysis.

    This service consumes the already-collected DNS result.
    It performs no additional network requests and does not
    calculate a final safe/suspicious/malicious verdict.

    The findings describe concrete DNS observations such as:

        - NXDOMAIN
        - no DNS data
        - partial DNS failures
        - multiple A/AAAA addresses
        - CNAME delegation to a different parent domain
    """

    def analyze(
        self,
        dns_result: DNSResult,
    ) -> DNSSecurityResult:
        findings: list[SecurityFinding] = []

        all_results = _all_query_results(dns_result)

        # -----------------------------------------------------
        # DNS-NXDOMAIN
        # -----------------------------------------------------
        if dns_result.status == "nxdomain":
            hostname_results = [
                record
                for record in dns_result.hostname_records.values()
            ]

            findings.append(
                _finding(
                    rule_id="DNS-NXDOMAIN",
                    category="dns",
                    title="Hostname returned NXDOMAIN",
                    severity="low",
                    confidence="high",
                    description=(
                        "The DNS resolver reported that the analyzed hostname "
                        "does not exist. This is a factual DNS state and can be "
                        "caused by an invalid, expired, newly-created, or intentionally "
                        "temporary hostname."
                    ),
                    evidence={
                        "hostname": dns_result.hostname,
                        "status": dns_result.status,
                        "hostname_queries": [
                            {
                                "record_type": record.record_type,
                                "status": record.status,
                            }
                            for record in hostname_results
                        ],
                    },
                )
            )

        # -----------------------------------------------------
        # DNS-NO-DATA
        # -----------------------------------------------------
        if dns_result.status == "no_data":
            findings.append(
                _finding(
                    rule_id="DNS-NO-DATA",
                    category="dns",
                    title="No DNS records were returned",
                    severity="low",
                    confidence="high",
                    description=(
                        "The DNS lookups completed without returning usable DNS "
                        "record data. A domain can legitimately have limited or "
                        "temporary DNS visibility, so this is contextual information."
                    ),
                    evidence={
                        "hostname": dns_result.hostname,
                        "registrable_domain": dns_result.registrable_domain,
                        "status": dns_result.status,
                    },
                )
            )

        # -----------------------------------------------------
        # DNS-PARTIAL
        # -----------------------------------------------------
        failed_queries = _failed_queries(
            {
                **dns_result.hostname_records,
                **dns_result.domain_records,
                **(
                    {"TXT": dns_result.hostname_txt_records}
                    if dns_result.hostname_txt_records is not None
                    else {}
                ),
            }
        )

        if dns_result.status == "partial" or failed_queries:
            findings.append(
                _finding(
                    rule_id="DNS-PARTIAL",
                    category="dns",
                    title="One or more DNS queries failed or timed out",
                    severity="info",
                    confidence="high",
                    description=(
                        "At least one DNS query did not complete normally while "
                        "other DNS information may still be available. This indicates "
                        "incomplete DNS visibility rather than a malicious condition."
                    ),
                    evidence={
                        "overall_status": dns_result.status,
                        "failed_queries": failed_queries,
                    },
                )
            )

        # -----------------------------------------------------
        # DNS-MULTIPLE-A
        # -----------------------------------------------------
        a_records = _record_values(
            dns_result.hostname_records,
            "A",
        )

        if len(set(a_records)) > MULTIPLE_IP_THRESHOLD:
            findings.append(
                _finding(
                    rule_id="DNS-MULTIPLE-A",
                    category="dns",
                    title="Hostname resolves to multiple IPv4 addresses",
                    severity="info",
                    confidence="high",
                    description=(
                        "The hostname currently has multiple distinct IPv4 A records. "
                        "Multiple addresses are common for load balancing, CDNs, redundancy, "
                        "and distributed services."
                    ),
                    evidence={
                        "hostname": dns_result.hostname,
                        "ipv4_addresses": list(dict.fromkeys(a_records)),
                        "address_count": len(set(a_records)),
                    },
                )
            )

        # -----------------------------------------------------
        # DNS-MULTIPLE-AAAA
        # -----------------------------------------------------
        aaaa_records = _record_values(
            dns_result.hostname_records,
            "AAAA",
        )

        if len(set(aaaa_records)) > MULTIPLE_IP_THRESHOLD:
            findings.append(
                _finding(
                    rule_id="DNS-MULTIPLE-AAAA",
                    category="dns",
                    title="Hostname resolves to multiple IPv6 addresses",
                    severity="info",
                    confidence="high",
                    description=(
                        "The hostname currently has multiple distinct IPv6 AAAA records. "
                        "This is common for distributed or redundant infrastructure."
                    ),
                    evidence={
                        "hostname": dns_result.hostname,
                        "ipv6_addresses": list(dict.fromkeys(aaaa_records)),
                        "address_count": len(set(aaaa_records)),
                    },
                )
            )

        # -----------------------------------------------------
        # DNS-CNAME-CROSS-DOMAIN
        # -----------------------------------------------------
        cname_records = _record_values(
            dns_result.hostname_records,
            "CNAME",
        )

        cross_domain_cnames: list[str] = []

        target_domain = (
            dns_result.registrable_domain or ""
        ).strip().rstrip(".").lower()

        for cname in cname_records:
            cname_parent = _registrable_domain_from_cname(cname)

            if (
                target_domain
                and cname_parent
                and cname_parent != target_domain
            ):
                cross_domain_cnames.append(
                    cname
                )

        if cross_domain_cnames:
            findings.append(
                _finding(
                    rule_id="DNS-CNAME-CROSS-DOMAIN",
                    category="dns",
                    title="Hostname uses a CNAME target under a different parent domain",
                    severity="low",
                    confidence="medium",
                    description=(
                        "The hostname points through a CNAME to a target whose apparent "
                        "parent domain differs from the submitted domain. Cross-domain CNAMEs "
                        "are common with CDNs, cloud platforms, SaaS, and managed hosting, so "
                        "this finding is contextual rather than inherently suspicious."
                    ),
                    evidence={
                        "hostname": dns_result.hostname,
                        "registrable_domain": target_domain or None,
                        "cname_targets": cross_domain_cnames,
                    },
                )
            )

        # -----------------------------------------------------
        # DNS-HOSTNAME-IP-ABSENCE
        # -----------------------------------------------------
        has_hostname_a = bool(a_records)
        has_hostname_aaaa = bool(aaaa_records)
        has_hostname_cname = bool(cname_records)

        if not (
            has_hostname_a
            or has_hostname_aaaa
            or has_hostname_cname
        ) and dns_result.status not in {
            "nxdomain",
            "no_data",
            "error",
        }:
            findings.append(
                _finding(
                    rule_id="DNS-NO-HOST-IP",
                    category="dns",
                    title="Hostname has no A, AAAA, or CNAME record in the collected result",
                    severity="info",
                    confidence="medium",
                    description=(
                        "The collected DNS result does not contain an A, AAAA, or CNAME "
                        "record for the hostname. The hostname may still be used through "
                        "other DNS mechanisms or the lookup may be incomplete."
                    ),
                    evidence={
                        "hostname": dns_result.hostname,
                        "status": dns_result.status,
                    },
                )
            )

        # -----------------------------------------------------
        # Observations
        # -----------------------------------------------------
        total_successful = len(
            _successful_records(
                {
                    **dns_result.hostname_records,
                    **dns_result.domain_records,
                }
            )
        )

        observations = [
            f"dns_status={dns_result.status}",
            f"hostname={dns_result.hostname}",
            f"resolved_ip_count={len(set(dns_result.resolved_ips))}",
            f"successful_record_results={total_successful}",
            f"cname_count={len(set(cname_records))}",
            f"a_record_count={len(set(a_records))}",
            f"aaaa_record_count={len(set(aaaa_records))}",
            f"total_structured_results={len(all_results)}",
        ]

        return DNSSecurityResult(
            status="completed",
            total_findings=len(findings),
            findings=findings,
            observations=observations,
        )
