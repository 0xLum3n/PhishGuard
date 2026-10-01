from __future__ import annotations

from typing import Iterable
from urllib.parse import urlsplit

from app.schemas.response import (
    CorrelationSecurityResult,
    DNSResult,
    IPIntelligenceResponse,
    OSINTMatch,
    OSINTResult,
    SecurityConfidence,
    SecurityFinding,
    SecuritySeverity,
    URLParts,
    URLSecurityResult,
    DNSSecurityResult,
    IPSecurityResult,
    OSINTSecurityResult,
    WhoisResult,
    WhoisSecurityResult,
)


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
    return SecurityFinding(
        rule_id=rule_id,
        category=category,
        title=title,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=evidence,
    )


def _provider(
    osint_result: OSINTResult | None,
    source: str,
):
    if osint_result is None:
        return None

    wanted = source.strip().lower()

    for provider in osint_result.providers:
        if provider.source.strip().lower() == wanted:
            return provider

    return None


def _matches_of_type(
    matches: Iterable[OSINTMatch],
    match_type: str,
) -> list[OSINTMatch]:
    return [
        match
        for match in matches
        if match.match_type == match_type
    ]


def _hostname(value: str | None) -> str | None:
    if not value:
        return None

    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        return host.rstrip(".").lower() if host else None
    except ValueError:
        return None


def _task_domain(match: OSINTMatch) -> str | None:
    details = match.details
    value = details.get("task_domain")

    if value:
        return str(value).rstrip(".").lower()

    return _hostname(details.get("task_url"))


def _page_domain(match: OSINTMatch) -> str | None:
    value = match.details.get("page_domain")
    return str(value).rstrip(".").lower() if value else None


def _reference(match: OSINTMatch) -> str | None:
    return match.reference


def _ip_countries(
    ip_result: IPIntelligenceResponse | None,
) -> set[str]:
    if ip_result is None:
        return set()

    countries: set[str] = set()

    for result in ip_result.results:
        if result.country_code:
            countries.add(
                result.country_code.strip().upper()
            )

    return countries


def _public_ip_results(
    ip_result: IPIntelligenceResponse | None,
):
    if ip_result is None:
        return []

    return [
        result
        for result in ip_result.results
        if result.classification == "public"
    ]


# =========================================================
# Step 6.6 — Cross-source correlation
# =========================================================


class CorrelationSecurityService:
    """
    Step 6.6: correlate already-collected evidence across
    URL, DNS, IP, WHOIS/RDAP and OSINT layers.

    This service performs no network requests.

    It does not calculate a score and does not produce a final
    safe/suspicious/malicious verdict.

    Correlations are explainable relationships between existing
    observations. A correlation can be useful context even when
    every individual observation is legitimate.
    """

    def analyze(
        self,
        *,
        url_parts: URLParts,
        dns_result: DNSResult | None,
        ip_result: IPIntelligenceResponse | None,
        whois_result: WhoisResult | None,
        osint_result: OSINTResult | None,
        url_security_result: URLSecurityResult | None = None,
        dns_security_result: DNSSecurityResult | None = None,
        ip_security_result: IPSecurityResult | None = None,
        whois_security_result: WhoisSecurityResult | None = None,
        osint_security_result: OSINTSecurityResult | None = None,
    ) -> CorrelationSecurityResult:
        findings: list[SecurityFinding] = []
        observations: list[str] = []

        # =====================================================
        # 1. Cross-provider exact URL corroboration
        # =====================================================

        phishtank = _provider(
            osint_result,
            "PhishTank",
        )

        urlhaus = _provider(
            osint_result,
            "URLhaus",
        )

        urlscan = _provider(
            osint_result,
            "urlscan.io",
        )

        phishtank_exact = _matches_of_type(
            phishtank.matches if phishtank else [],
            "exact_url",
        )

        urlhaus_exact = _matches_of_type(
            urlhaus.matches if urlhaus else [],
            "malware_url",
        )

        urlscan_exact = _matches_of_type(
            urlscan.matches if urlscan else [],
            "exact_url",
        )

        source_matches = {
            "PhishTank": phishtank_exact,
            "URLhaus": urlhaus_exact,
            "urlscan.io": urlscan_exact,
        }

        exact_sources = [
            source
            for source, matches in source_matches.items()
            if matches
        ]

        if len(exact_sources) >= 2:
            findings.append(
                _finding(
                    rule_id="CORR-MULTI-SOURCE-EXACT-URL",
                    category="cross-source",
                    title="Multiple OSINT sources contain exact URL evidence",
                    severity="medium",
                    confidence="high",
                    description=(
                        "Two or more independent OSINT providers returned exact URL-level evidence "
                        "for the analyzed URL. The individual provider records remain the authoritative evidence."
                    ),
                    evidence={
                        "sources": exact_sources,
                        "match_counts": {
                            source: len(matches)
                            for source, matches in source_matches.items()
                            if matches
                        },
                        "references": [
                            reference
                            for matches in source_matches.values()
                            for match in matches
                            if (reference := _reference(match))
                        ],
                    },
                )
            )

            observations.append(
                "Multiple independent OSINT providers returned exact URL-level evidence."
            )

        # =====================================================
        # 2. PhishTank + URLhaus corroboration
        # =====================================================

        if phishtank_exact and urlhaus_exact:
            findings.append(
                _finding(
                    rule_id="CORR-PHISHTANK-URLHAUS",
                    category="cross-source",
                    title="PhishTank and URLhaus both returned URL evidence",
                    severity="high",
                    confidence="high",
                    description=(
                        "The same analyzed URL has direct URL-level evidence from both PhishTank "
                        "and URLhaus. This correlation links two independent threat-intelligence datasets; "
                        "their individual records should still be shown separately."
                    ),
                    evidence={
                        "phishtank_match_count": len(phishtank_exact),
                        "urlhaus_match_count": len(urlhaus_exact),
                        "phishtank_references": [
                            ref
                            for match in phishtank_exact
                            if (ref := _reference(match))
                        ],
                        "urlhaus_references": [
                            ref
                            for match in urlhaus_exact
                            if (ref := _reference(match))
                        ],
                    },
                )
            )

            observations.append(
                "PhishTank and URLhaus independently returned URL-level evidence for the same target."
            )

        # =====================================================
        # 3. Exact URL + exact hostname historical correlation
        # =====================================================

        if urlscan_exact:
            urlscan_hostname = _matches_of_type(
                urlscan.matches,
                "exact_hostname",
            )

            if urlscan_hostname:
                findings.append(
                    _finding(
                        rule_id="CORR-URLSCAN-URL-HOSTNAME",
                        category="cross-source",
                        title="urlscan has both exact URL and exact hostname history",
                        severity="info",
                        confidence="high",
                        description=(
                            "urlscan returned both exact URL and exact original-task-hostname historical "
                            "observations for the analyzed target. This indicates historical coverage at two scopes."
                        ),
                        evidence={
                            "exact_url_count": len(urlscan_exact),
                            "exact_hostname_count": len(urlscan_hostname),
                            "exact_url_references": [
                                ref
                                for match in urlscan_exact
                                if (ref := _reference(match))
                            ],
                            "exact_hostname_references": [
                                ref
                                for match in urlscan_hostname
                                if (ref := _reference(match))
                            ],
                        },
                    )
                )

                observations.append(
                    "urlscan contains historical observations at both exact-URL and exact-hostname scopes."
                )

        # =====================================================
        # 4. Exact task URL with resulting-page redirect context
        # =====================================================

        redirect_observations: list[dict] = []

        for match in urlscan_exact:
            task_host = _task_domain(match)
            page_host = _page_domain(match)

            if (
                task_host
                and page_host
                and task_host != page_host
            ):
                redirect_observations.append(
                    {
                        "task_url": match.details.get("task_url"),
                        "task_domain": task_host,
                        "page_url": match.details.get("page_url"),
                        "page_domain": page_host,
                        "page_redirected": match.details.get(
                            "page_redirected"
                        ),
                        "reference": match.reference,
                    }
                )

        if redirect_observations:
            findings.append(
                _finding(
                    rule_id="CORR-URLSCAN-REDIRECT-CONTEXT",
                    category="cross-source",
                    title="Historical exact-URL scans include resulting-page domain changes",
                    severity="info",
                    confidence="high",
                    description=(
                        "At least one exact historical urlscan record shows that the original tasked URL "
                        "and the resulting page domain differ. This is redirect/navigation context and does not "
                        "by itself indicate malicious behavior."
                    ),
                    evidence={
                        "observation_count": len(
                            redirect_observations
                        ),
                        "observations": redirect_observations,
                    },
                )
            )

            observations.append(
                "Some historical exact-URL scans show resulting-page domain changes; these are retained as redirect context."
            )

        # =====================================================
        # 5. WHOIS recent registration + direct OSINT evidence
        # =====================================================

        recently_registered = False

        if whois_security_result is not None:
            recently_registered = any(
                finding.rule_id == "WHOIS-RECENTLY-REGISTERED"
                for finding in whois_security_result.findings
            )

        if (
            recently_registered
            and whois_result
            and exact_sources
        ):
            findings.append(
                _finding(
                    rule_id="CORR-RECENT-DOMAIN-OSINT",
                    category="cross-source",
                    title="Recent registration coincides with direct OSINT evidence",
                    severity="medium",
                    confidence="medium",
                    description=(
                        "The WHOIS/RDAP security layer reports a recent registration window and one or more OSINT "
                        "providers contain exact URL evidence. These are separate observations whose combination "
                        "provides additional context for review."
                    ),
                    evidence={
                        "domain": whois_result.domain,
                        "registration_date": whois_result.registration_date,
                        "osint_sources": exact_sources,
                    },
                )
            )

        # =====================================================
        # 6. URL structural findings + direct OSINT evidence
        # =====================================================

        structural_rule_ids: list[str] = []

        if url_security_result is not None:
            structural_rule_ids = [
                finding.rule_id
                for finding in url_security_result.findings
            ]

        if structural_rule_ids and exact_sources:
            findings.append(
                _finding(
                    rule_id="CORR-URL-STRUCTURE-OSINT",
                    category="cross-source",
                    title="URL structural indicators coexist with direct OSINT evidence",
                    severity="medium",
                    confidence="high",
                    description=(
                        "The URL security layer identified one or more structural indicators and at least one OSINT "
                        "provider returned exact URL evidence. This combines separate evidence categories without "
                        "converting them into a single threat score or verdict."
                    ),
                    evidence={
                        "structural_rule_ids": structural_rule_ids,
                        "osint_sources": exact_sources,
                    },
                )
            )

            observations.append(
                "URL structural indicators coexist with direct OSINT evidence for the same analysis."
            )

        # =====================================================
        # 7. DNS -> IP resolution context
        # =====================================================

        public_ips = _public_ip_results(
            ip_result
        )

        resolved_ip_count = len(
            dns_result.resolved_ips
        ) if dns_result else 0

        if (
            dns_result
            and resolved_ip_count > 1
            and public_ips
        ):
            findings.append(
                _finding(
                    rule_id="CORR-DNS-MULTI-IP",
                    category="cross-source",
                    title="Hostname resolves to multiple public IP addresses",
                    severity="info",
                    confidence="high",
                    description=(
                        "DNS returned multiple IP addresses and the IP intelligence layer classified one or more "
                        "of them as public. Multiple public addresses are common with load balancing, CDNs, and distributed hosting."
                    ),
                    evidence={
                        "resolved_ips": dns_result.resolved_ips,
                        "resolved_ip_count": resolved_ip_count,
                        "public_ip_count": len(public_ips),
                    },
                )
            )

            observations.append(
                "The hostname resolves to multiple public IP addresses; this can reflect distributed infrastructure."
            )

        # =====================================================
        # 8. Multiple countries across resolved public IPs
        # =====================================================

        countries = _ip_countries(
            ip_result
        )

        if len(countries) > 1:
            findings.append(
                _finding(
                    rule_id="CORR-IP-MULTI-COUNTRY",
                    category="cross-source",
                    title="Resolved public IPs have differing geolocation country codes",
                    severity="info",
                    confidence="medium",
                    description=(
                        "The available IP intelligence places resolved public IP addresses in more than one country. "
                        "This often occurs with distributed infrastructure, CDNs, cloud networks, or anycast services."
                    ),
                    evidence={
                        "country_codes": sorted(countries),
                        "public_ip_count": len(public_ips),
                    },
                )
            )

            observations.append(
                "Resolved public IP intelligence spans multiple country codes."
            )

        # =====================================================
        # 9. DNS + IP data availability correlation
        # =====================================================

        if dns_result and ip_result:
            if dns_result.resolved_ips and not public_ips:
                findings.append(
                    _finding(
                        rule_id="CORR-DNS-IP-NO-PUBLIC-ENRICHMENT",
                        category="cross-source-availability",
                        title="DNS resolved IPs but no public IP intelligence was enriched",
                        severity="info",
                        confidence="high",
                        description=(
                            "DNS produced IP addresses, but the current IP-intelligence response contains no public "
                            "IP records. This can happen with private/special-use addresses or provider coverage limits."
                        ),
                        evidence={
                            "resolved_ips": dns_result.resolved_ips,
                            "ip_results": [
                                result.model_dump()
                                for result in ip_result.results
                            ],
                        },
                    )
                )

        # =====================================================
        # 10. URL hostname versus resolved DNS context
        # =====================================================

        if dns_result:
            dns_host = dns_result.hostname.rstrip(".").lower()
            url_host = url_parts.hostname.rstrip(".").lower()

            if dns_host != url_host:
                findings.append(
                    _finding(
                        rule_id="CORR-URL-DNS-HOST-MISMATCH",
                        category="cross-source-consistency",
                        title="URL hostname and DNS lookup hostname differ",
                        severity="medium",
                        confidence="high",
                        description=(
                            "The URL parser and DNS layer were given different hostname values for the same analysis. "
                            "This can indicate a pipeline or normalization inconsistency and should be investigated before interpreting the related intelligence."
                        ),
                        evidence={
                            "url_hostname": url_parts.hostname,
                            "dns_hostname": dns_result.hostname,
                        },
                    )
                )

        # =====================================================
        # 11. Security-layer corroboration context
        # =====================================================

        populated_layers: dict[str, int] = {}

        layer_results = {
            "url": url_security_result,
            "dns": dns_security_result,
            "ip": ip_security_result,
            "whois": whois_security_result,
            "osint": osint_security_result,
        }

        for layer_name, result in layer_results.items():
            if result is not None and result.total_findings > 0:
                populated_layers[layer_name] = result.total_findings

        if len(populated_layers) >= 2:
            findings.append(
                _finding(
                    rule_id="CORR-MULTI-LAYER-FINDINGS",
                    category="cross-source",
                    title="Security indicators were observed across multiple analysis layers",
                    severity="info",
                    confidence="high",
                    description=(
                        "More than one independent PhishGuard analysis layer produced findings. "
                        "This records the breadth of observed evidence without combining findings into "
                        "a numeric score or treating their presence alone as proof of maliciousness."
                    ),
                    evidence={
                        "layers": populated_layers,
                        "layer_count": len(populated_layers),
                    },
                )
            )

            observations.append(
                "Security findings were observed across multiple analysis layers."
            )

        # =====================================================
        # Final observations
        # =====================================================

        if not findings:
            observations.append(
                "No cross-source correlations were identified from the available collected evidence."
            )

        return CorrelationSecurityResult(
            status="completed",
            total_findings=len(findings),
            findings=findings,
            observations=observations,
        )
