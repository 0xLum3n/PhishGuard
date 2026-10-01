from __future__ import annotations

import re
from typing import Literal

from app.schemas.response import (
    SecurityFinding,
    URLParts,
    URLSecurityResult,
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


# These thresholds are deliberately conservative. They are structural
# heuristics, not a maliciousness score.
MAX_SUBDOMAIN_DEPTH = 4
MAX_QUERY_PARAMETERS = 8
LONG_URL_LENGTH = 2048
HIGH_ENCODING_COUNT = 10

SENSITIVE_PARAMETER_NAMES = {
    "access_token",
    "apikey",
    "api_key",
    "auth",
    "authorization",
    "code",
    "credential",
    "credentials",
    "id_token",
    "otp",
    "pass",
    "passwd",
    "password",
    "pin",
    "refresh_token",
    "secret",
    "session",
    "sessionid",
    "sid",
    "token",
}

PERCENT_ENCODED_RE = re.compile(
    r"%[0-9A-Fa-f]{2}"
)

DOUBLE_ENCODED_RE = re.compile(
    r"%25[0-9A-Fa-f]{2}"
)


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


def _subdomain_depth(subdomain: str | None) -> int:
    """Return the number of labels in the parsed subdomain."""

    if not subdomain:
        return 0

    return len(
        [
            label
            for label in subdomain.split(".")
            if label
        ]
    )


def _query_parameter_occurrences(url_parts: URLParts) -> int:
    """
    Count actual query parameter occurrences, preserving duplicates.
    """

    total = 0

    for parameter in url_parts.query_parameters:
        if parameter.values:
            total += len(parameter.values)
        else:
            total += 1

    return total


def _sensitive_parameters(
    url_parts: URLParts,
) -> list[str]:
    """Return sensitive-looking parameter names."""

    names: list[str] = []

    for parameter in url_parts.query_parameters:
        name = parameter.name.strip().lower()

        if name in SENSITIVE_PARAMETER_NAMES:
            names.append(parameter.name)

    return list(dict.fromkeys(names))


def _duplicate_parameters(
    url_parts: URLParts,
) -> list[str]:
    """Return parameter names that occur more than once."""

    duplicates: list[str] = []

    for parameter in url_parts.query_parameters:
        values = parameter.values

        if len(values) > 1:
            duplicates.append(parameter.name)

    return duplicates


def _encoded_sequence_count(url_parts: URLParts) -> int:
    """Count percent-encoded byte sequences in the URL."""

    return len(
        PERCENT_ENCODED_RE.findall(
            url_parts.original
        )
    )


def _has_double_encoding(
    url_parts: URLParts,
) -> bool:
    """
    Detect an encoded percent sign followed by an encoded byte,
    e.g. %252F or %255C.
    """

    return bool(
        DOUBLE_ENCODED_RE.search(
            url_parts.original
        )
    )


class URLSecurityService:
    """
    Step 6.1: structural URL security analysis.

    This service consumes the output of the existing URL parser only.
    It does not perform network requests and does not generate a final
    safe/suspicious/malicious verdict.
    """

    def analyze(
        self,
        url_parts: URLParts,
    ) -> URLSecurityResult:
        findings: list[SecurityFinding] = []

        # -----------------------------------------------------
        # URL-IP-HOST
        # -----------------------------------------------------
        if url_parts.is_ip_address:
            findings.append(
                _finding(
                    rule_id="URL-IP-HOST",
                    category="authority",
                    title="URL uses an IP address as the hostname",
                    severity="medium",
                    confidence="high",
                    description=(
                        "The URL hostname is an IP address rather than a "
                        "domain name. This is sometimes legitimate, but it "
                        "removes normal domain-based identity information."
                    ),
                    evidence={
                        "hostname": url_parts.hostname,
                        "ip_address": True,
                    },
                )
            )

        # -----------------------------------------------------
        # URL-CREDENTIALS
        # -----------------------------------------------------
        if url_parts.has_credentials:
            findings.append(
                _finding(
                    rule_id="URL-CREDENTIALS",
                    category="authority",
                    title="URL contains embedded credentials",
                    severity="medium",
                    confidence="high",
                    description=(
                        "The URL authority contains username and/or password "
                        "information. Credentials embedded in URLs can expose "
                        "secrets through logs, history, or copied links."
                    ),
                    evidence={
                        "has_username": url_parts.username is not None,
                        "has_password": url_parts.password is not None,
                    },
                )
            )

        # -----------------------------------------------------
        # URL-NONSTANDARD-PORT
        # -----------------------------------------------------
        if (
            url_parts.port is not None
            and url_parts.port not in {80, 443}
        ):
            findings.append(
                _finding(
                    rule_id="URL-NONSTANDARD-PORT",
                    category="network",
                    title="URL uses a non-standard HTTP(S) port",
                    severity="low",
                    confidence="high",
                    description=(
                        "The URL uses a port other than the conventional "
                        "HTTP/HTTPS ports 80 and 443. Non-standard ports are "
                        "not inherently malicious, but they are useful context."
                    ),
                    evidence={
                        "scheme": url_parts.scheme,
                        "port": url_parts.port,
                        "standard_ports": [80, 443],
                    },
                )
            )

        # -----------------------------------------------------
        # URL-PUNYCODE
        # -----------------------------------------------------
        if "xn--" in url_parts.hostname.lower():
            findings.append(
                _finding(
                    rule_id="URL-PUNYCODE",
                    category="hostname",
                    title="Hostname contains an IDN/Punycode label",
                    severity="low",
                    confidence="high",
                    description=(
                        "The hostname contains the xn-- Punycode prefix used "
                        "for internationalized domain names. Punycode itself "
                        "is legitimate, but it can make visual inspection more "
                        "difficult."
                    ),
                    evidence={
                        "hostname": url_parts.hostname,
                        "punycode_present": True,
                    },
                )
            )

        # -----------------------------------------------------
        # URL-DEEP-SUBDOMAIN
        # -----------------------------------------------------
        subdomain_depth = _subdomain_depth(
            url_parts.subdomain
        )

        if subdomain_depth >= MAX_SUBDOMAIN_DEPTH:
            findings.append(
                _finding(
                    rule_id="URL-DEEP-SUBDOMAIN",
                    category="hostname",
                    title="Hostname has many nested subdomain labels",
                    severity="low",
                    confidence="medium",
                    description=(
                        "The hostname contains a deep subdomain hierarchy. "
                        "Deep nesting can be legitimate for large services, "
                        "so this finding is contextual rather than a malicious verdict."
                    ),
                    evidence={
                        "subdomain": url_parts.subdomain,
                        "subdomain_depth": subdomain_depth,
                        "threshold": MAX_SUBDOMAIN_DEPTH,
                    },
                )
            )

        # -----------------------------------------------------
        # URL-SENSITIVE-PARAMS
        # -----------------------------------------------------
        sensitive_parameters = _sensitive_parameters(
            url_parts
        )

        if sensitive_parameters:
            findings.append(
                _finding(
                    rule_id="URL-SENSITIVE-PARAMS",
                    category="query",
                    title="Query contains sensitive-looking parameter names",
                    severity="low",
                    confidence="high",
                    description=(
                        "The query string contains parameter names commonly "
                        "associated with authentication, session, credential, "
                        "or secret data. Their presence alone does not indicate abuse."
                    ),
                    evidence={
                        "parameter_names": sensitive_parameters,
                    },
                )
            )

        # -----------------------------------------------------
        # URL-DUPLICATE-PARAMS
        # -----------------------------------------------------
        duplicate_parameters = _duplicate_parameters(
            url_parts
        )

        if duplicate_parameters:
            findings.append(
                _finding(
                    rule_id="URL-DUPLICATE-PARAMS",
                    category="query",
                    title="Query contains duplicate parameter names",
                    severity="low",
                    confidence="high",
                    description=(
                        "One or more query parameter names occur multiple times. "
                        "Duplicate parameters can be valid, but they can also "
                        "create ambiguity between different URL consumers."
                    ),
                    evidence={
                        "parameter_names": duplicate_parameters,
                    },
                )
            )

        # -----------------------------------------------------
        # URL-MANY-QUERY-PARAMS
        # -----------------------------------------------------
        query_parameter_occurrences = _query_parameter_occurrences(
            url_parts
        )

        if query_parameter_occurrences > MAX_QUERY_PARAMETERS:
            findings.append(
                _finding(
                    rule_id="URL-MANY-QUERY-PARAMS",
                    category="query",
                    title="URL contains many query parameters",
                    severity="low",
                    confidence="medium",
                    description=(
                        "The URL contains a large number of query parameter "
                        "occurrences. This can be normal for complex applications, "
                        "so it is treated as contextual evidence."
                    ),
                    evidence={
                        "query_parameter_occurrences": query_parameter_occurrences,
                        "threshold": MAX_QUERY_PARAMETERS,
                    },
                )
            )

        # -----------------------------------------------------
        # URL-DOUBLE-ENCODING
        # -----------------------------------------------------
        if _has_double_encoding(url_parts):
            findings.append(
                _finding(
                    rule_id="URL-DOUBLE-ENCODING",
                    category="obfuscation",
                    title="URL contains double-encoded data",
                    severity="medium",
                    confidence="high",
                    description=(
                        "The URL contains an encoded percent sign followed by "
                        "another encoded byte, a common pattern in multi-stage "
                        "URL encoding. This is an obfuscation indicator, not proof of abuse."
                    ),
                    evidence={
                        "pattern": "%25XX",
                        "double_encoding_present": True,
                    },
                )
            )

        # -----------------------------------------------------
        # URL-HIGH-ENCODING
        # -----------------------------------------------------
        encoded_sequence_count = _encoded_sequence_count(
            url_parts
        )

        url_length = len(
            url_parts.original
        )

        encoding_ratio = (
            encoded_sequence_count / url_length
            if url_length
            else 0.0
        )

        if encoded_sequence_count >= HIGH_ENCODING_COUNT:
            findings.append(
                _finding(
                    rule_id="URL-HIGH-ENCODING",
                    category="obfuscation",
                    title="URL contains a high number of percent-encoded sequences",
                    severity="low",
                    confidence="medium",
                    description=(
                        "The URL contains many percent-encoded byte sequences. "
                        "Encoding is common in normal URLs, so the result is kept "
                        "as contextual evidence."
                    ),
                    evidence={
                        "encoded_sequence_count": encoded_sequence_count,
                        "url_length": url_length,
                        "encoding_ratio": round(
                            encoding_ratio,
                            4,
                        ),
                        "threshold": HIGH_ENCODING_COUNT,
                    },
                )
            )

        # -----------------------------------------------------
        # URL-LONG
        # -----------------------------------------------------
        if url_length > LONG_URL_LENGTH:
            findings.append(
                _finding(
                    rule_id="URL-LONG",
                    category="structure",
                    title="URL is unusually long",
                    severity="low",
                    confidence="high",
                    description=(
                        "The submitted URL is longer than the configured "
                        "structural threshold. Long URLs can be completely "
                        "legitimate, especially for applications with complex queries."
                    ),
                    evidence={
                        "url_length": url_length,
                        "threshold": LONG_URL_LENGTH,
                    },
                )
            )

        observations = [
            f"url_length={url_length}",
            f"subdomain_depth={subdomain_depth}",
            f"query_parameter_occurrences={query_parameter_occurrences}",
            f"percent_encoded_sequences={encoded_sequence_count}",
        ]

        if not findings:
            observations.append(
                "No Step 6.1 structural indicators were triggered."
            )

        return URLSecurityResult(
            status="completed",
            total_findings=len(findings),
            findings=findings,
            observations=observations,
        )
