from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from app.schemas.response import (
    SecurityFinding,
    WhoisResult,
    WhoisSecurityResult,
)


SecuritySeverity = Literal[
    "info",
    "low",
    "medium",
    "high",
]

SecurityConfidence = Literal[
    "low",
    "medium",
    "high",
]


# These are deliberately conservative context thresholds.
# They are indicators, not a maliciousness score.
RECENT_REGISTRATION_DAYS = 30
EXPIRING_SOON_DAYS = 30


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


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        normalized = value.strip()

        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        parsed = datetime.fromisoformat(normalized)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (TypeError, ValueError):
        return None


class WhoisSecurityService:
    """
    Step 6.4: WHOIS/RDAP security/context analysis.

    This service consumes normalized WhoisResult data only.
    It does not perform network requests and does not produce a
    final safe/suspicious/malicious verdict.
    """

    def analyze(
        self,
        whois: WhoisResult | None,
    ) -> WhoisSecurityResult:
        findings: list[SecurityFinding] = []
        observations: list[str] = []

        # -----------------------------------------------------
        # No WHOIS/RDAP object available
        # -----------------------------------------------------
        if whois is None:
            observations.append(
                "No WHOIS/RDAP result was available for security analysis."
            )
            return WhoisSecurityResult(
                status="completed",
                total_findings=0,
                findings=[],
                observations=observations,
            )

        # -----------------------------------------------------
        # Lookup status
        # -----------------------------------------------------
        if whois.status != "success":
            findings.append(
                _finding(
                    rule_id="WHOIS-LOOKUP-UNAVAILABLE",
                    category="whois-provider",
                    title="WHOIS/RDAP data was not successfully retrieved",
                    severity="info",
                    confidence="high",
                    description=(
                        "The WHOIS/RDAP lookup did not return a successful domain record. "
                        "This is an intelligence-availability observation, not a maliciousness verdict."
                    ),
                    evidence={
                        "domain": whois.domain,
                        "status": whois.status,
                        "source": whois.source,
                        "rdap_server": whois.rdap_server,
                        "error": whois.error,
                    },
                )
            )

            observations.append(
                f"WHOIS/RDAP analysis is limited because the lookup status was '{whois.status}'."
            )

            return WhoisSecurityResult(
                status="completed",
                total_findings=len(findings),
                findings=findings,
                observations=observations,
            )

        now = datetime.now(timezone.utc)

        registration = _parse_datetime(
            whois.registration_date
        )
        expiration = _parse_datetime(
            whois.expiration_date
        )

        # -----------------------------------------------------
        # WHOIS-REGISTRATION-MISSING
        # -----------------------------------------------------
        if registration is None:
            findings.append(
                _finding(
                    rule_id="WHOIS-REGISTRATION-MISSING",
                    category="whois-lifecycle",
                    title="WHOIS/RDAP record has no usable registration date",
                    severity="info",
                    confidence="high",
                    description=(
                        "The normalized WHOIS/RDAP record does not contain a usable registration date."
                    ),
                    evidence={
                        "registration_date": whois.registration_date,
                    },
                )
            )

        # -----------------------------------------------------
        # WHOIS-EXPIRATION-MISSING
        # -----------------------------------------------------
        if expiration is None:
            findings.append(
                _finding(
                    rule_id="WHOIS-EXPIRATION-MISSING",
                    category="whois-lifecycle",
                    title="WHOIS/RDAP record has no usable expiration date",
                    severity="info",
                    confidence="high",
                    description=(
                        "The normalized WHOIS/RDAP record does not contain a usable expiration date."
                    ),
                    evidence={
                        "expiration_date": whois.expiration_date,
                    },
                )
            )

        # -----------------------------------------------------
        # WHOIS-LIFECYCLE-INCONSISTENT
        # -----------------------------------------------------
        if registration and expiration and expiration < registration:
            findings.append(
                _finding(
                    rule_id="WHOIS-LIFECYCLE-INCONSISTENT",
                    category="whois-lifecycle",
                    title="WHOIS/RDAP lifecycle dates are internally inconsistent",
                    severity="high",
                    confidence="high",
                    description=(
                        "The reported expiration date occurs before the reported registration date. "
                        "This is most likely a data-quality or registry-response issue and should be investigated."
                    ),
                    evidence={
                        "registration_date": whois.registration_date,
                        "expiration_date": whois.expiration_date,
                    },
                )
            )

        # -----------------------------------------------------
        # WHOIS-RECENTLY-REGISTERED
        # -----------------------------------------------------
        if registration:
            age_days = (now - registration).total_seconds() / 86400

            if 0 <= age_days <= RECENT_REGISTRATION_DAYS:
                findings.append(
                    _finding(
                        rule_id="WHOIS-RECENTLY-REGISTERED",
                        category="whois-lifecycle",
                        title="Domain was registered recently",
                        severity="medium",
                        confidence="high",
                        description=(
                            "The domain's reported registration date is within the configured recent-registration window. "
                            "Recently registered domains can be used for legitimate new services as well as short-lived abuse, "
                            "so this is contextual evidence only."
                        ),
                        evidence={
                            "registration_date": whois.registration_date,
                            "registration_age_days": round(age_days, 2),
                            "threshold_days": RECENT_REGISTRATION_DAYS,
                        },
                    )
                )

        # -----------------------------------------------------
        # WHOIS-EXPIRED
        # -----------------------------------------------------
        if expiration and expiration < now:
            days_expired = (now - expiration).total_seconds() / 86400

            findings.append(
                _finding(
                    rule_id="WHOIS-EXPIRED",
                    category="whois-lifecycle",
                    title="Domain expiration date is in the past",
                    severity="medium",
                    confidence="high",
                    description=(
                        "The normalized WHOIS/RDAP record reports an expiration date in the past. "
                        "The registry may still have an updated lifecycle state, so this should be interpreted with the domain status."
                    ),
                    evidence={
                        "expiration_date": whois.expiration_date,
                        "days_since_expiration": round(days_expired, 2),
                    },
                )
            )

        # -----------------------------------------------------
        # WHOIS-EXPIRING-SOON
        # -----------------------------------------------------
        elif expiration:
            days_until_expiration = (
                expiration - now
            ).total_seconds() / 86400

            if 0 <= days_until_expiration <= EXPIRING_SOON_DAYS:
                findings.append(
                    _finding(
                        rule_id="WHOIS-EXPIRING-SOON",
                        category="whois-lifecycle",
                        title="Domain is approaching its reported expiration date",
                        severity="info",
                        confidence="high",
                        description=(
                            "The reported domain expiration date is within the configured near-expiry window. "
                            "This is lifecycle context and is not, by itself, evidence of malicious activity."
                        ),
                        evidence={
                            "expiration_date": whois.expiration_date,
                            "days_until_expiration": round(days_until_expiration, 2),
                            "threshold_days": EXPIRING_SOON_DAYS,
                        },
                    )
                )

        # -----------------------------------------------------
        # WHOIS-NO-REGISTRAR
        # -----------------------------------------------------
        if not whois.registrar_name and not whois.registrar_id:
            findings.append(
                _finding(
                    rule_id="WHOIS-NO-REGISTRAR",
                    category="whois-registrar",
                    title="WHOIS/RDAP record does not expose registrar information",
                    severity="info",
                    confidence="medium",
                    description=(
                        "The normalized record contains neither a registrar name nor registrar identifier. "
                        "Some registries or privacy/redaction configurations may legitimately omit this information."
                    ),
                    evidence={
                        "registrar_name": whois.registrar_name,
                        "registrar_id": whois.registrar_id,
                    },
                )
            )

        # -----------------------------------------------------
        # WHOIS-NO-NAMESERVERS
        # -----------------------------------------------------
        if not whois.nameservers:
            findings.append(
                _finding(
                    rule_id="WHOIS-NO-NAMESERVERS",
                    category="whois-dns",
                    title="WHOIS/RDAP record exposes no nameservers",
                    severity="info",
                    confidence="high",
                    description=(
                        "The normalized WHOIS/RDAP record contains no nameserver entries. "
                        "This may reflect registry state, incomplete data, or a domain that is not currently delegated."
                    ),
                    evidence={
                        "nameserver_count": 0,
                    },
                )
            )

        # -----------------------------------------------------
        # WHOIS-DNSSEC-UNSIGNED
        # -----------------------------------------------------
        if whois.dnssec == "unsigned":
            findings.append(
                _finding(
                    rule_id="WHOIS-DNSSEC-UNSIGNED",
                    category="whois-dnssec",
                    title="Domain is reported as not DNSSEC signed",
                    severity="low",
                    confidence="high",
                    description=(
                        "The WHOIS/RDAP record explicitly reports an unsigned DNSSEC delegation. "
                        "Unsigned DNS does not mean that a domain is malicious; it is a DNS-security context indicator."
                    ),
                    evidence={
                        "dnssec": whois.dnssec,
                    },
                )
            )

        # -----------------------------------------------------
        # WHOIS-REDACTED
        # -----------------------------------------------------
        if whois.redacted:
            findings.append(
                _finding(
                    rule_id="WHOIS-REDACTED",
                    category="whois-privacy",
                    title="WHOIS/RDAP record contains redaction or privacy indicators",
                    severity="info",
                    confidence="high",
                    description=(
                        "The normalized WHOIS/RDAP record indicates that some information was redacted or privacy-related. "
                        "Privacy protection is common and is not evidence of malicious activity by itself."
                    ),
                    evidence={
                        "redacted": whois.redacted,
                    },
                )
            )

        # -----------------------------------------------------
        # Observations
        # -----------------------------------------------------
        observations.append(
            f"WHOIS/RDAP lookup succeeded for {whois.domain}."
        )

        if whois.registration_date:
            observations.append(
                "A registration date is available from the normalized RDAP record."
            )

        if whois.expiration_date:
            observations.append(
                "An expiration date is available from the normalized RDAP record."
            )

        if whois.registrar_name:
            observations.append(
                f"Registrar information is available: {whois.registrar_name}."
            )

        if whois.nameservers:
            observations.append(
                f"{len(whois.nameservers)} nameserver(s) were present in the RDAP record."
            )

        return WhoisSecurityResult(
            status="completed",
            total_findings=len(findings),
            findings=findings,
            observations=observations,
        )
