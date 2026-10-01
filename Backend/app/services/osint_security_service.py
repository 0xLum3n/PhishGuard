from __future__ import annotations

from typing import Iterable

from app.schemas.response import (
    OSINTMatch,
    OSINTProviderResult,
    OSINTResult,
    OSINTSecurityResult,
    SecurityConfidence,
    SecurityFinding,
    SecuritySeverity,
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
    """Build a normalized OSINT security finding."""

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
    providers: Iterable[OSINTProviderResult],
    source: str,
) -> OSINTProviderResult | None:
    """Return the first provider result matching a source name."""

    for provider in providers:
        if provider.source.strip().lower() == source.lower():
            return provider

    return None


def _matches_of_type(
    matches: Iterable[OSINTMatch],
    match_type: str,
) -> list[OSINTMatch]:
    """Return matches with an exact match type."""

    return [
        match
        for match in matches
        if match.match_type == match_type
    ]


def _source_match_evidence(
    matches: list[OSINTMatch],
) -> list[dict]:
    """Create compact evidence objects without losing references."""

    return [
        {
            "indicator": match.indicator,
            "reference": match.reference,
            "details": match.details,
        }
        for match in matches
    ]


def _status_findings(
    provider: OSINTProviderResult,
) -> SecurityFinding | None:
    """Represent provider availability problems as context findings."""

    status = provider.status

    status_titles = {
        "not_configured": "OSINT provider is not configured",
        "rate_limited": "OSINT provider was rate-limited",
        "timeout": "OSINT provider lookup timed out",
        "unauthorized": "OSINT provider authentication failed",
        "forbidden": "OSINT provider request was forbidden",
        "invalid_request": "OSINT provider rejected the lookup request",
        "upstream_error": "OSINT provider returned an upstream error",
        "error": "OSINT provider returned an error",
    }

    if status not in status_titles:
        return None

    if status == "not_configured":
        severity: SecuritySeverity = "info"
    else:
        severity = "info"

    return _finding(
        rule_id=f"OSINT-{status.upper().replace('_', '-')}",
        category="osint-availability",
        title=status_titles[status],
        severity=severity,
        confidence="high",
        description=(
            f"The {provider.source} OSINT lookup completed with status "
            f"'{status}'. This affects intelligence coverage but does not "
            "indicate that the analyzed URL is malicious."
        ),
        evidence={
            "source": provider.source,
            "status": status,
            "query": provider.query,
            "error": provider.error,
            "metadata": provider.metadata,
        },
    )


# =========================================================
# Step 6.5 — OSINT security/context analysis
# =========================================================

class OSINTSecurityService:
    """
    Step 6.5: security/context analysis of collected OSINT.

    This service consumes already-collected PhishTank, URLhaus,
    and urlscan evidence. It performs no network requests.

    Important evidence rules:

        - PhishTank exact_url is a direct database-listing signal.
        - URLhaus malware_url is a direct URLhaus listing signal.
        - urlscan exact_url means a historical scan of the same URL.
        - urlscan exact_hostname means a historical scan whose original
          task hostname matched the analyzed hostname.
        - urlscan page-domain observations are contextual only.
        - Provider failures affect coverage, not maliciousness.

    No score and no final safe/suspicious/malicious verdict are produced.
    """

    def analyze(
        self,
        osint_result: OSINTResult | None,
    ) -> OSINTSecurityResult:
        findings: list[SecurityFinding] = []
        observations: list[str] = []

        if osint_result is None:
            observations.append(
                "No OSINT result was available for security analysis."
            )

            return OSINTSecurityResult(
                status="completed",
                total_findings=0,
                findings=[],
                observations=observations,
            )

        providers = list(osint_result.providers)

        # =====================================================
        # Provider coverage / availability
        # =====================================================

        successful_or_empty = {
            "success",
            "no_match",
        }

        for provider in providers:
            coverage_finding = _status_findings(provider)

            if coverage_finding is not None:
                findings.append(coverage_finding)

        failed_provider_count = sum(
            1
            for provider in providers
            if provider.status not in successful_or_empty
            and provider.status != "not_configured"
        )

        available_provider_count = sum(
            1
            for provider in providers
            if provider.status in successful_or_empty
        )

        configured_provider_count = sum(
            1
            for provider in providers
            if provider.status != "not_configured"
        )

        if osint_result.status == "partial":
            findings.append(
                _finding(
                    rule_id="OSINT-PARTIAL-COVERAGE",
                    category="osint-availability",
                    title="OSINT coverage is partial",
                    severity="info",
                    confidence="high",
                    description=(
                        "Some configured OSINT providers completed while one or more other "
                        "providers did not complete normally. The available evidence remains "
                        "usable, but the provider set does not provide complete coverage for this lookup."
                    ),
                    evidence={
                        "overall_status": osint_result.status,
                        "configured_provider_count": configured_provider_count,
                        "available_provider_count": available_provider_count,
                        "failed_provider_count": failed_provider_count,
                    },
                )
            )

        elif osint_result.status == "not_configured":
            findings.append(
                _finding(
                    rule_id="OSINT-NOT-CONFIGURED",
                    category="osint-availability",
                    title="No OSINT provider is configured for this analysis",
                    severity="info",
                    confidence="high",
                    description=(
                        "The OSINT aggregation layer has no configured provider results. "
                        "This indicates missing intelligence coverage rather than a clean or malicious result."
                    ),
                    evidence={
                        "overall_status": osint_result.status,
                        "provider_count": len(providers),
                    },
                )
            )

        # =====================================================
        # PhishTank
        # =====================================================

        phishtank = _provider(
            providers,
            "PhishTank",
        )

        phishtank_matches = _matches_of_type(
            phishtank.matches if phishtank else [],
            "exact_url",
        )

        if phishtank_matches:
            findings.append(
                _finding(
                    rule_id="OSINT-PHISHTANK-MATCH",
                    category="osint-phishing",
                    title="URL is listed by PhishTank",
                    severity="high",
                    confidence="high",
                    description=(
                        "PhishTank returned an exact URL entry for the analyzed URL. "
                        "The provider's verification and validity fields are preserved as evidence "
                        "and should be shown with the listing reference."
                    ),
                    evidence={
                        "provider": "PhishTank",
                        "match_count": len(phishtank_matches),
                        "matches": _source_match_evidence(
                            phishtank_matches
                        ),
                        "provider_metadata": (
                            phishtank.metadata
                            if phishtank
                            else {}
                        ),
                    },
                )
            )

            observations.append(
                "PhishTank returned an exact URL listing for the analyzed URL."
            )
        elif phishtank and phishtank.status == "success":
            observations.append(
                "PhishTank completed the URL lookup without returning an exact listing."
            )

        # =====================================================
        # URLhaus
        # =====================================================

        urlhaus = _provider(
            providers,
            "URLhaus",
        )

        urlhaus_matches = _matches_of_type(
            urlhaus.matches if urlhaus else [],
            "malware_url",
        )

        if urlhaus_matches:
            findings.append(
                _finding(
                    rule_id="OSINT-URLHAUS-MATCH",
                    category="osint-malware",
                    title="URL is listed by URLhaus",
                    severity="high",
                    confidence="high",
                    description=(
                        "URLhaus returned a matching URL entry. The provider response's "
                        "URL status, threat, tags, and blacklist information are retained as evidence."
                    ),
                    evidence={
                        "provider": "URLhaus",
                        "match_count": len(urlhaus_matches),
                        "matches": _source_match_evidence(
                            urlhaus_matches
                        ),
                    },
                )
            )

            observations.append(
                "URLhaus returned an exact URL listing for the analyzed URL."
            )
        elif urlhaus and urlhaus.status == "no_match":
            observations.append(
                "URLhaus completed the exact URL lookup without returning a matching entry."
            )

        # =====================================================
        # urlscan exact URL
        # =====================================================

        urlscan = _provider(
            providers,
            "urlscan.io",
        )

        if urlscan:
            exact_url_matches = _matches_of_type(
                urlscan.matches,
                "exact_url",
            )

            if exact_url_matches:
                findings.append(
                    _finding(
                        rule_id="OSINT-URLSCAN-EXACT-URL",
                        category="osint-history",
                        title="The exact URL has historical urlscan observations",
                        severity="info",
                        confidence="high",
                        description=(
                            "urlscan returned one or more historical scans whose original task URL "
                            "matches the analyzed URL. Historical scanning does not by itself establish maliciousness."
                        ),
                        evidence={
                            "match_count": len(exact_url_matches),
                            "matches": _source_match_evidence(
                                exact_url_matches
                            ),
                        },
                    )
                )

                observations.append(
                    "urlscan has historical observations for the exact submitted URL."
                )

            # -----------------------------------------------
            # urlscan exact hostname
            # -----------------------------------------------

            exact_hostname_matches = _matches_of_type(
                urlscan.matches,
                "exact_hostname",
            )

            if exact_hostname_matches:
                findings.append(
                    _finding(
                        rule_id="OSINT-URLSCAN-EXACT-HOSTNAME",
                        category="osint-history",
                        title="The exact hostname has historical urlscan observations",
                        severity="info",
                        confidence="high",
                        description=(
                            "urlscan returned historical observations for scans whose original task "
                            "hostname matched the analyzed hostname. This is historical context and is not a maliciousness verdict."
                        ),
                        evidence={
                            "match_count": len(exact_hostname_matches),
                            "matches": _source_match_evidence(
                                exact_hostname_matches
                            ),
                        },
                    )
                )

                observations.append(
                    "urlscan has historical observations for the analyzed hostname."
                )

            # -----------------------------------------------
            # page-domain observations — contextual only
            # -----------------------------------------------

            page_observations = urlscan.metadata.get(
                "page_domain_observations",
                [],
            )

            if isinstance(page_observations, list) and page_observations:
                observations.append(
                    "urlscan also returned resulting-page domain observations; these are retained as contextual evidence only."
                )

        # =====================================================
        # General aggregate observations
        # =====================================================

        if osint_result.status == "no_matches":
            observations.append(
                "No configured OSINT provider returned an exact database match."
            )

        elif osint_result.status == "completed":
            observations.append(
                "Configured OSINT providers completed without provider-level failures."
            )

        return OSINTSecurityResult(
            status="completed",
            total_findings=len(findings),
            findings=findings,
            observations=observations,
        )
