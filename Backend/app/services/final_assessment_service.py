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
