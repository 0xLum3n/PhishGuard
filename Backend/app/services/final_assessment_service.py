from __future__ import annotations

from typing import Iterable

from app.schemas.response import (
    CorrelationSecurityResult,
    DNSSecurityResult,
    OSINTMatch,
    OSINTProviderResult,
    OSINTResult,
    OSINTSecurityResult,
    SecurityConfidence,
    SecurityFinding,
    SecuritySeverity,
    URLSecurityResult,
    WhoisSecurityResult,
    FinalAssessmentResult,
)


# =========================================================
# Step 6.7 — Final assessment / decision layer
# =========================================================

# Findings generated purely to describe provider coverage or
# data availability must never by themselves move an analysis
# into a threat verdict.
NON_THREAT_CATEGORIES = {
    "osint-availability",
    "cross-source-availability",
}


ACTIONABLE_SEVERITIES = {
    "medium",
    "high",
}


def _provider(
    osint_result: OSINTResult | None,
    source: str,
) -> OSINTProviderResult | None:
    if osint_result is None:
        return None

    wanted = source.strip().lower()

    for provider in osint_result.providers:
        if provider.source.strip().lower() == wanted:
            return provider

    return None


def _exact_matches(
    provider: OSINTProviderResult | None,
    match_type: str,
) -> list[OSINTMatch]:
    if provider is None:
        return []

    return [
        match
        for match in provider.matches
        if match.match_type == match_type
    ]


def _phishtank_verified_valid(
    matches: Iterable[OSINTMatch],
) -> list[OSINTMatch]:
    strong: list[OSINTMatch] = []

    for match in matches:
        verified = match.details.get("verified")
        valid = match.details.get("valid")

        if verified is True and valid is True:
            strong.append(match)

    return strong


def _urlhaus_matches(
    matches: Iterable[OSINTMatch],
) -> list[OSINTMatch]:
    return list(matches)


def _references(
    matches: Iterable[OSINTMatch],
) -> list[str]:
    return [
        match.reference
        for match in matches
        if match.reference
    ]


def _actionable_findings(
    findings: Iterable[SecurityFinding],
) -> list[SecurityFinding]:
    return [
        finding
        for finding in findings
        if finding.category not in NON_THREAT_CATEGORIES
        and finding.severity in ACTIONABLE_SEVERITIES
    ]


def _all_findings(
    *,
    url_security: URLSecurityResult | None,
    dns_security: DNSSecurityResult | None,
    ip_security,
    whois_security: WhoisSecurityResult | None,
    osint_security: OSINTSecurityResult | None,
    correlation_security: CorrelationSecurityResult | None,
) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []

    for result in (
        url_security,
        dns_security,
        ip_security,
        whois_security,
        osint_security,
        correlation_security,
    ):
        if result is not None:
            findings.extend(result.findings)

    return findings


def _finding_weight(severity: str) -> int:
    """Translate a finding severity into visualization points.

    These points are evidence weights, not probabilities. Informational
    findings intentionally contribute zero so provider/data-availability
    observations do not inflate the risk index.
    """
    return {
        "high": 25,
        "medium": 15,
        "low": 5,
        "info": 0,
    }.get(str(severity).lower(), 0)


def _layer_score(findings: Iterable[SecurityFinding], cap: int) -> tuple[int, dict[str, int]]:
    rows = list(findings)
    subtotal = sum(_finding_weight(f.severity) for f in rows)
    return min(cap, subtotal), {
        "high": sum(1 for f in rows if f.severity == "high"),
        "medium": sum(1 for f in rows if f.severity == "medium"),
        "low": sum(1 for f in rows if f.severity == "low"),
        "info": sum(1 for f in rows if f.severity == "info"),
    }


def _risk_score(
    *,
    osint_result: OSINTResult | None,
    url_security: URLSecurityResult | None,
    dns_security: DNSSecurityResult | None,
    ip_security,
    whois_security: WhoisSecurityResult | None,
    osint_security: OSINTSecurityResult | None,
    correlation_security: CorrelationSecurityResult | None,
) -> tuple[int, dict, dict[str, int], list[dict]]:
    """Compute an evidence-derived 0-100 index entirely from the live scan.

    The score is intentionally explainable. It is not a probability and it is
    not intended to prove that a URL is safe or malicious.
    """
    osint_findings = list(osint_security.findings) if osint_security else []
    # Direct OSINT match findings are accounted for explicitly below so a
    # single threat-intel hit cannot be counted once as a provider match and
    # again as a generic severity finding.
    osint_context_findings = [
        finding
        for finding in osint_findings
        if not str(finding.rule_id).startswith((
            "OSINT-PHISHTANK-MATCH",
            "OSINT-URLHAUS-MATCH",
            "OSINT-URLSCAN-EXACT-URL",
            "OSINT-URLSCAN-EXACT-HOSTNAME",
        ))
    ]
    layer_sources = {
        "url_structure": list(url_security.findings) if url_security else [],
        "dns": list(dns_security.findings) if dns_security else [],
        "ip_geolocation": list(ip_security.findings) if ip_security else [],
        "whois_rdap": list(whois_security.findings) if whois_security else [],
        "osint": osint_context_findings,
        "cross_source_correlation": list(correlation_security.findings) if correlation_security else [],
    }
    caps = {
        "url_structure": 35,
        "dns": 20,
        "ip_geolocation": 20,
        "whois_rdap": 25,
        "osint": 35,
        "cross_source_correlation": 25,
    }

    dimensions: dict[str, int] = {}
    severity_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "info": 0}
    layer_details: dict[str, dict[str, int]] = {}
    layer_points: dict[str, int] = {}
    for layer, rows in layer_sources.items():
        score, counts = _layer_score(rows, caps[layer])
        layer_points[layer] = score
        dimensions[layer] = round((score / caps[layer]) * 100) if caps[layer] else 0
        layer_details[layer] = {"points": score, "cap": caps[layer], "percent": dimensions[layer], **counts}
        for severity, count in counts.items():
            severity_counts[severity] += count

    urlhaus = _provider(osint_result, "URLhaus")
    phishtank = _provider(osint_result, "PhishTank")
    urlscan = _provider(osint_result, "urlscan.io")

    urlhaus_exact = len(_exact_matches(urlhaus, "malware_url"))
    phishtank_exact = _exact_matches(phishtank, "exact_url")
    verified_phishtank = len(_phishtank_verified_valid(phishtank_exact))
    unverified_phishtank = max(0, len(phishtank_exact) - verified_phishtank)

    urlhaus_points = min(100, urlhaus_exact * 65)
    phishtank_verified_points = min(100, verified_phishtank * 60)
    phishtank_context_points = min(12, unverified_phishtank * 6)

    urlscan_exact_url = len(_exact_matches(urlscan, "exact_url"))
    urlscan_exact_hostname = len(_exact_matches(urlscan, "exact_hostname"))
    urlscan_context_points = min(
        15,
        urlscan_exact_url * 4 + urlscan_exact_hostname * 2,
    )

    direct_points = min(100, urlhaus_points + phishtank_verified_points)
    contextual_osint_points = min(25, phishtank_context_points + urlscan_context_points)
    dimensions["direct_threat_intel"] = direct_points
    dimensions["osint_context"] = round((contextual_osint_points / 25) * 100) if contextual_osint_points else 0

    # Correlation is derived from the same evidence, so it gets a capped bonus
    # rather than being allowed to double-count an entire source layer.
    correlation_points = layer_points["cross_source_correlation"]

    # Overall score: direct threat intelligence is allowed to dominate, while
    # structural/contextual evidence accumulates gradually from this scan.
    raw_total = min(100, direct_points + sum(
        layer_points[layer] for layer in (
            "url_structure",
            "dns",
            "ip_geolocation",
            "whois_rdap",
            "osint",
        )
    ) + contextual_osint_points + correlation_points)
    score = max(0, min(100, raw_total))

    risk_events: list[dict] = []
    for layer, rows in layer_sources.items():
        for finding in rows:
            points = _finding_weight(finding.severity)
            if points <= 0:
                continue
            risk_events.append({
                "source": layer,
                "type": "security_finding",
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "points": points,
            })

    if urlhaus_exact:
        risk_events.append({
            "source": "URLhaus",
            "type": "direct_threat_intel",
            "signal": "exact malware URL listing",
            "matches": urlhaus_exact,
            "points": urlhaus_points,
        })
    if verified_phishtank:
        risk_events.append({
            "source": "PhishTank",
            "type": "direct_threat_intel",
            "signal": "verified + valid exact URL listing",
            "matches": verified_phishtank,
            "points": phishtank_verified_points,
        })
    if unverified_phishtank:
        risk_events.append({
            "source": "PhishTank",
            "type": "contextual_osint",
            "signal": "unverified exact URL listing",
            "matches": unverified_phishtank,
            "points": phishtank_context_points,
        })
    if urlscan_exact_url or urlscan_exact_hostname:
        risk_events.append({
            "source": "urlscan.io",
            "type": "contextual_osint",
            "signal": "historical exact URL/hostname observations",
            "exact_url_matches": urlscan_exact_url,
            "exact_hostname_matches": urlscan_exact_hostname,
            "points": urlscan_context_points,
        })

    risk_events.sort(key=lambda item: int(item.get("points", 0)), reverse=True)

    factors = {
        "finding_points": sum(_finding_weight(f.severity) for rows in layer_sources.values() for f in rows),
        "direct_threat_intel_points": direct_points,
        "contextual_osint_points": contextual_osint_points,
        "urlhaus_exact_matches": urlhaus_exact,
        "urlhaus_points": urlhaus_points,
        "phishtank_exact_matches": len(phishtank_exact),
        "phishtank_verified_valid_matches": verified_phishtank,
        "phishtank_context_matches": unverified_phishtank,
        "phishtank_verified_points": phishtank_verified_points,
        "urlscan_exact_url_matches": urlscan_exact_url,
        "urlscan_exact_hostname_matches": urlscan_exact_hostname,
        "urlscan_context_points": urlscan_context_points,
        "correlation_points": correlation_points,
        "dimension_percentages": dimensions,
        "raw_total_before_cap": raw_total,
        "high_findings": severity_counts["high"],
        "medium_findings": severity_counts["medium"],
        "low_findings": severity_counts["low"],
        "info_findings": severity_counts["info"],
    }

    # Keep per-layer detail in the same response for the frontend and PDF.
    factors["layer_details"] = layer_details

    return score, factors, dimensions, risk_events


def _coverage(
    osint_result: OSINTResult | None,
) -> dict:
    if osint_result is None:
        return {
            "osint_available": False,
            "provider_count": 0,
            "configured_provider_count": 0,
            "successful_provider_count": 0,
            "failed_provider_count": 0,
            "direct_threat_intel_sources_available": 0,
        }

    providers = list(osint_result.providers)

    successful_statuses = {
        "success",
        "no_match",
    }

    configured = [
        provider
        for provider in providers
        if provider.status != "not_configured"
    ]

    successful = [
        provider
        for provider in providers
        if provider.status in successful_statuses
    ]

    failed = [
        provider
        for provider in providers
        if provider.status not in successful_statuses
        and provider.status != "not_configured"
    ]

    direct_sources = 0
    historical_sources = 0

    # PhishTank and URLhaus provide direct threat-intelligence
    # listing coverage. urlscan is historical/contextual coverage
    # and is tracked separately so historical scans alone do not
    # masquerade as a direct threat-intelligence verdict.
    for source in (
        "PhishTank",
        "URLhaus",
    ):
        provider = _provider(
            osint_result,
            source,
        )

        if provider and provider.status in successful_statuses:
            direct_sources += 1

    urlscan = _provider(
        osint_result,
        "urlscan.io",
    )

    if urlscan and urlscan.status in successful_statuses:
        historical_sources += 1

    return {
        "osint_available": bool(providers),
        "provider_count": len(providers),
        "configured_provider_count": len(configured),
        "successful_provider_count": len(successful),
        "failed_provider_count": len(failed),
        "direct_threat_intel_sources_available": direct_sources,
        "historical_intelligence_sources_available": historical_sources,
    }


class FinalAssessmentService:
    """
    Step 6.7: consolidate all Step 6 evidence into a transparent
    final assessment.

    The service does not perform network requests.

    Decision rules are deliberately explicit:

    1. Strong direct threat-intelligence evidence takes precedence:
       - URLhaus exact URL listing, or
       - PhishTank exact URL listing whose record is both verified
         and valid.

    2. A PhishTank listing without both verified=True and valid=True
       remains direct OSINT evidence, but is not treated as strong
       confirmed threat evidence by itself.

    3. Without strong direct threat-intelligence evidence, actionable
       medium/high findings can produce a suspicious-indicators
       assessment.

    4. If no threat indicators are present but the direct OSINT layer
       has no usable provider coverage, the result is inconclusive.

    5. Otherwise, the result is no_significant_evidence.

    This layer intentionally does not call something "safe" because
    static inspection and third-party intelligence cannot prove that a
    URL is universally safe.
    """

    def analyze(
        self,
        *,
        osint_result: OSINTResult | None,
        url_security_result: URLSecurityResult | None = None,
        dns_security_result: DNSSecurityResult | None = None,
        ip_security_result=None,
        whois_security_result: WhoisSecurityResult | None = None,
        osint_security_result: OSINTSecurityResult | None = None,
        correlation_security_result: CorrelationSecurityResult | None = None,
    ) -> FinalAssessmentResult:
        findings = _all_findings(
            url_security=url_security_result,
            dns_security=dns_security_result,
            ip_security=ip_security_result,
            whois_security=whois_security_result,
            osint_security=osint_security_result,
            correlation_security=correlation_security_result,
        )

        actionable = _actionable_findings(findings)

        coverage = _coverage(
            osint_result
        )

        risk_score, risk_factors, risk_dimensions, risk_events = _risk_score(
            osint_result=osint_result,
            url_security=url_security_result,
            dns_security=dns_security_result,
            ip_security=ip_security_result,
            whois_security=whois_security_result,
            osint_security=osint_security_result,
            correlation_security=correlation_security_result,
        )

        phishtank = _provider(
            osint_result,
            "PhishTank",
        )

        urlhaus = _provider(
            osint_result,
            "URLhaus",
        )

        phishtank_matches = _exact_matches(
            phishtank,
            "exact_url",
        )

        verified_valid_phishtank = _phishtank_verified_valid(
            phishtank_matches
        )

        urlhaus_matches = _urlhaus_matches(
            _exact_matches(
                urlhaus,
                "malware_url",
            )
        )

        urlscan = _provider(
            osint_result,
            "urlscan.io",
        )

        urlscan_exact_url = _exact_matches(
            urlscan,
            "exact_url",
        )

        urlscan_exact_hostname = _exact_matches(
            urlscan,
            "exact_hostname",
        )

        # =====================================================
        # 1. Strong direct threat-intelligence evidence
        # =====================================================

        direct_sources: list[str] = []
        direct_references: list[str] = []
        direct_evidence: dict = {}

        if urlhaus_matches:
            direct_sources.append("URLhaus")
            direct_references.extend(
                _references(urlhaus_matches)
            )

        if verified_valid_phishtank:
            direct_sources.append("PhishTank")
            direct_references.extend(
                _references(verified_valid_phishtank)
            )

        if direct_sources:
            confidence: SecurityConfidence

            if len(direct_sources) >= 2:
                confidence = "high"
            elif verified_valid_phishtank:
                confidence = "high"
            else:
                confidence = "medium"

            rationale = [
                "Direct URL-level threat-intelligence evidence is present in the collected provider results."
            ]

            if urlhaus_matches:
                rationale.append(
                    f"URLhaus returned {len(urlhaus_matches)} matching URL listing(s)."
                )

            if verified_valid_phishtank:
                rationale.append(
                    "PhishTank returned an exact URL listing marked both verified and valid."
                )

            if phishtank_matches and not verified_valid_phishtank:
                rationale.append(
                    "A PhishTank listing was also present, but it was not counted as strong evidence because the returned record was not simultaneously marked verified and valid."
                )

            return FinalAssessmentResult(
                status="completed",
                verdict="confirmed_threat_evidence",
                confidence=confidence,
                risk_score=risk_score,
                risk_score_version="evidence-v2",
                risk_factors=risk_factors,
                risk_dimensions=risk_dimensions,
                risk_events=risk_events[:12],
                summary=(
                    "Direct threat-intelligence evidence was found for the analyzed URL."
                ),
                rationale=rationale,
                evidence_summary={
                    "direct_threat_intel": {
                        "sources": direct_sources,
                        "references": direct_references,
                        "urlhaus_match_count": len(urlhaus_matches),
                        "phishtank_verified_valid_count": len(verified_valid_phishtank),
                    },
                    "contextual_osint": {
                        "phishtank_total_exact_matches": len(phishtank_matches),
                        "urlscan_exact_url_count": len(urlscan_exact_url),
                        "urlscan_exact_hostname_count": len(urlscan_exact_hostname),
                    },
                    "actionable_finding_count": len(actionable),
                },
                coverage=coverage,
            )

        # =====================================================
        # 2. Suspicious indicators without strong TI
        # =====================================================

        if actionable:
            severity_counts = {
                "high": sum(
                    1
                    for finding in actionable
                    if finding.severity == "high"
                ),
                "medium": sum(
                    1
                    for finding in actionable
                    if finding.severity == "medium"
                ),
            }

            if severity_counts["high"]:
                confidence = "high"
            elif len(actionable) >= 3:
                confidence = "medium"
            else:
                confidence = "low"

            rationale = [
                f"{len(actionable)} actionable security finding(s) were produced across the Step 6 analysis layers."
            ]

            if severity_counts["high"]:
                rationale.append(
                    f"{severity_counts['high']} high-severity finding(s) are present."
                )

            if severity_counts["medium"]:
                rationale.append(
                    f"{severity_counts['medium']} medium-severity finding(s) are present."
                )

            return FinalAssessmentResult(
                status="completed",
                verdict="suspicious_indicators",
                confidence=confidence,
                risk_score=risk_score,
                risk_score_version="evidence-v2",
                risk_factors=risk_factors,
                risk_dimensions=risk_dimensions,
                risk_events=risk_events[:12],
                summary=(
                    "The analysis found security indicators that warrant review, but no strong direct threat-intelligence evidence was available."
                ),
                rationale=rationale,
                evidence_summary={
                    "direct_threat_intel": {
                        "sources": [],
                        "references": [],
                    },
                    "actionable_findings": [
                        {
                            "rule_id": finding.rule_id,
                            "category": finding.category,
                            "severity": finding.severity,
                            "confidence": finding.confidence,
                        }
                        for finding in actionable
                    ],
                    "actionable_finding_count": len(actionable),
                },
                coverage=coverage,
            )

        # =====================================================
        # 3. No meaningful direct evidence + insufficient OSINT
        # =====================================================

        direct_coverage_available = (
            coverage["direct_threat_intel_sources_available"] > 0
        )

        if not direct_coverage_available:
            return FinalAssessmentResult(
                status="completed",
                verdict="inconclusive",
                confidence="low",
                risk_score=risk_score,
                risk_score_version="evidence-v2",
                risk_factors=risk_factors,
                risk_dimensions=risk_dimensions,
                risk_events=risk_events[:12],
                summary=(
                    "No actionable indicators were found, but direct threat-intelligence coverage was not sufficient to support a stronger conclusion."
                ),
                rationale=[
                    "No actionable Step 6 findings were produced.",
                    "No configured direct threat-intelligence provider completed normally with usable coverage.",
                ],
                evidence_summary={
                    "direct_threat_intel": {
                        "sources": [],
                        "references": [],
                    },
                    "actionable_finding_count": 0,
                },
                coverage=coverage,
            )

        # =====================================================
        # 4. No significant evidence
        # =====================================================

        return FinalAssessmentResult(
            status="completed",
            verdict="no_significant_evidence",
            confidence="medium",
            risk_score=risk_score,
            risk_score_version="evidence-v2",
            risk_factors=risk_factors,
            risk_dimensions=risk_dimensions,
            risk_events=risk_events[:12],
            summary=(
                "The available analysis did not identify significant security indicators or direct threat-intelligence matches."
            ),
            rationale=[
                "No actionable Step 6 findings were produced.",
                "At least one direct threat-intelligence provider completed with usable coverage and did not return a matching listing."
            ],
            evidence_summary={
                "direct_threat_intel": {
                    "sources": [],
                    "references": [],
                },
                "actionable_finding_count": 0,
            },
            coverage=coverage,
        )
