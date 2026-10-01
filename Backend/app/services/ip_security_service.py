from __future__ import annotations

from app.schemas.response import (
    IPIntelligence,
    IPIntelligenceResponse,
    SecurityConfidence,
    SecurityFinding,
    SecuritySeverity,
    IPSecurityResult,
)


# =========================================================
# Configuration
# =========================================================

MULTIPLE_PUBLIC_IP_THRESHOLD = 1


# =========================================================
# Helpers
# =========================================================

def _finding(
    *,
    rule_id: str,
    category: str,
    title: str,
    severity: SecuritySeverity,
    confidence: SecurityConfidence,
    description: str,
    evidence: dict,
) -> SecurityFinding:
    """Construct a normalized security finding."""

    return SecurityFinding(
        rule_id=rule_id,
        category=category,
        title=title,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=evidence,
    )


def _unique_results(
    results: list[IPIntelligence],
) -> list[IPIntelligence]:
    """Deduplicate IP results by normalized IP address."""

    seen: set[str] = set()
    output: list[IPIntelligence] = []

    for result in results:
        key = result.ip.strip().lower()

        if key in seen:
            continue

        seen.add(key)
        output.append(result)

    return output


def _special_use_results(
    results: list[IPIntelligence],
) -> list[IPIntelligence]:
    """Return non-public/special-use IP observations."""

    return [
        result
        for result in results
        if result.classification != "public"
    ]


def _failed_public_results(
    results: list[IPIntelligence],
) -> list[IPIntelligence]:
    """Return public IPs for which provider enrichment failed."""

    return [
        result
        for result in results
        if (
            result.classification == "public"
            and result.status != "success"
        )
    ]


def _countries(
    results: list[IPIntelligence],
) -> list[str]:
    """Return unique country codes represented by successful lookups."""

    values: list[str] = []

    for result in results:
        country = (result.country_code or "").strip().upper()

        if country and country not in values:
            values.append(country)

    return values


class IPSecurityService:
    """
    Step 6.3: security/context analysis of collected IP intelligence.

    This service consumes the already-collected Step 3 IP intelligence.
    It performs no network requests and does not generate a final
    safe/suspicious/malicious verdict.
    """

    def analyze(
        self,
        ip_result: IPIntelligenceResponse,
    ) -> IPSecurityResult:
        findings: list[SecurityFinding] = []
        results = _unique_results(ip_result.results)

        # -----------------------------------------------------
        # IP-SPECIAL-USE
        # -----------------------------------------------------
        special_use = _special_use_results(results)

        if special_use:
            findings.append(
                _finding(
                    rule_id="IP-SPECIAL-USE",
                    category="ip",
                    title=(
                        "One or more discovered IPs are non-public "
                        "or special-use addresses"
                    ),
                    severity="medium",
                    confidence="high",
                    description=(
                        "The collected DNS/IP data contains an address classified as "
                        "private, loopback, link-local, multicast, reserved, or unspecified. "
                        "This can be completely legitimate for internal services, but it is "
                        "important security context when the address is unexpected."
                    ),
                    evidence={
                        "ips": [item.ip for item in special_use],
                        "classifications": {
                            item.ip: item.classification
                            for item in special_use
                        },
                    },
                )
            )

        # -----------------------------------------------------
        # Public IP infrastructure context
        # -----------------------------------------------------
        public_results = [
            result
            for result in results
            if result.classification == "public"
        ]

        if len(public_results) > MULTIPLE_PUBLIC_IP_THRESHOLD:
            findings.append(
                _finding(
                    rule_id="IP-MULTIPLE-PUBLIC",
                    category="ip",
                    title="Multiple public IP addresses were observed",
                    severity="info",
                    confidence="high",
                    description=(
                        "More than one public IP address was available in the collected IP "
                        "intelligence. Multiple public addresses are common with CDNs, load "
                        "balancers, redundancy, and geographically distributed infrastructure."
                    ),
                    evidence={
                        "public_ips": [item.ip for item in public_results],
                        "public_ip_count": len(public_results),
                    },
                )
            )

        # -----------------------------------------------------
        # IP-DUAL-STACK
        # -----------------------------------------------------
        versions = sorted(
            {
                item.version
                for item in public_results
            }
        )

        if 4 in versions and 6 in versions:
            findings.append(
                _finding(
                    rule_id="IP-DUAL-STACK",
                    category="ip",
                    title="Both IPv4 and IPv6 addresses were observed",
                    severity="info",
                    confidence="high",
                    description=(
                        "The collected public-IP data contains both IPv4 and IPv6 addresses. "
                        "Dual-stack deployment is normal for modern services."
                    ),
                    evidence={
                        "versions": versions,
                        "ipv4": [
                            item.ip
                            for item in public_results
                            if item.version == 4
                        ],
                        "ipv6": [
                            item.ip
                            for item in public_results
                            if item.version == 6
                        ],
                    },
                )
            )

        # -----------------------------------------------------
        # IP-LOOKUP-FAILURE
        # -----------------------------------------------------
        failed_public = _failed_public_results(results)

        if failed_public:
            findings.append(
                _finding(
                    rule_id="IP-LOOKUP-FAILURE",
                    category="ip-provider",
                    title=(
                        "One or more public IP intelligence lookups "
                        "did not complete successfully"
                    ),
                    severity="info",
                    confidence="high",
                    description=(
                        "The IP intelligence provider did not successfully enrich every public "
                        "IP that was discovered. This indicates incomplete external intelligence "
                        "rather than a malicious condition."
                    ),
                    evidence={
                        "ips": [item.ip for item in failed_public],
                        "statuses": {
                            item.ip: item.status
                            for item in failed_public
                        },
                        "errors": {
                            item.ip: item.error
                            for item in failed_public
                            if item.error
                        },
                    },
                )
            )

        # -----------------------------------------------------
        # IP-RATE-LIMITED
        # -----------------------------------------------------
        rate_limited = [
            item
            for item in failed_public
            if item.status == "rate_limited"
        ]

        if rate_limited:
            findings.append(
                _finding(
                    rule_id="IP-RATE-LIMITED",
                    category="ip-provider",
                    title="IP intelligence provider rate-limited lookups",
                    severity="info",
                    confidence="high",
                    description=(
                        "The external IP intelligence provider reported a rate limit for one "
                        "or more public IPs. Missing enrichment should not be interpreted as a security verdict."
                    ),
                    evidence={
                        "ips": [item.ip for item in rate_limited],
                        "count": len(rate_limited),
                    },
                )
            )

        # -----------------------------------------------------
        # IP-GEOLOCATION-INCOMPLETE
        # -----------------------------------------------------
        successful_public = [
            item
            for item in public_results
            if item.status == "success"
        ]

        incomplete_geo = [
            item
            for item in successful_public
            if (
                not item.country_code
                and not item.country_name
                and item.latitude is None
                and item.longitude is None
            )
        ]

        if incomplete_geo:
            findings.append(
                _finding(
                    rule_id="IP-GEOLOCATION-INCOMPLETE",
                    category="ip-geolocation",
                    title="Successful IP lookups returned no geographic location data",
                    severity="info",
                    confidence="high",
                    description=(
                        "The IP intelligence provider responded successfully but did not return "
                        "usable geographic fields for one or more addresses. IP geolocation is "
                        "approximate network-level information and may be unavailable."
                    ),
                    evidence={
                        "ips": [item.ip for item in incomplete_geo],
                    },
                )
            )

        # -----------------------------------------------------
        # IP-MULTI-COUNTRY-CONTEXT
        # -----------------------------------------------------
        countries = _countries(successful_public)

        if len(countries) > 1:
            findings.append(
                _finding(
                    rule_id="IP-MULTI-COUNTRY-CONTEXT",
                    category="ip-geolocation",
                    title="Public IPs were geolocated to multiple countries",
                    severity="info",
                    confidence="medium",
                    description=(
                        "Different public IPs associated with the analyzed hostname were "
                        "geolocated to more than one country. Distributed hosting, CDNs, and "
                        "anycast services can legitimately produce this pattern. Geolocation does "
                        "not identify the physical location of an organization or user."
                    ),
                    evidence={
                        "country_codes": countries,
                        "country_count": len(countries),
                        "ips": {
                            item.ip: item.country_code
                            for item in successful_public
                            if item.country_code
                        },
                    },
                )
            )

        observations: list[str] = []

        if not results:
            observations.append(
                "No IP intelligence records were available for analysis."
            )
        elif not public_results:
            observations.append(
                "No public IP addresses were available for external IP intelligence enrichment."
            )
        elif ip_result.limit_reached:
            observations.append(
                "The configured per-analysis public-IP lookup limit was reached; remaining public IPs were not enriched."
            )

        if successful_public:
            observations.append(
                f"{len(successful_public)} public IP intelligence lookup(s) completed successfully."
            )

        return IPSecurityResult(
            status="completed",
            total_findings=len(findings),
            findings=findings,
            observations=observations,
        )
