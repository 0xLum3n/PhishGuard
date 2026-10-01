from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# =========================================================
# QUERY PARAMETER
# =========================================================

class QueryParameter(BaseModel):
    """
    One unique query parameter name and all associated values.
    """

    name: str

    value: str

    values: list[str] = Field(
        default_factory=list
    )


# =========================================================
# URL COMPONENTS
# =========================================================

class URLParts(BaseModel):
    """
    Complete decomposition of the submitted URL.
    """

    # -----------------------------------------------------
    # Original / normalized
    # -----------------------------------------------------

    original: str

    normalized: str

    # -----------------------------------------------------
    # URL authority
    # -----------------------------------------------------

    scheme: str

    username: Optional[str] = None

    password: Optional[str] = None

    hostname: str

    port: Optional[int] = None

    # -----------------------------------------------------
    # Domain hierarchy
    # -----------------------------------------------------

    subdomain: Optional[str] = None

    domain: Optional[str] = None

    registrable_domain: Optional[str] = None

    tld: Optional[str] = None

    # -----------------------------------------------------
    # URL resource
    # -----------------------------------------------------

    path: str

    query: Optional[str] = None

    query_parameters: list[QueryParameter] = Field(
        default_factory=list
    )

    fragment: Optional[str] = None

    # -----------------------------------------------------
    # Useful flags
    # -----------------------------------------------------

    has_credentials: bool = False

    has_query: bool = False

    has_fragment: bool = False

    is_ip_address: bool = False


# =========================================================
# DNS
# =========================================================

DNSQueryStatus = Literal[
    "success",
    "no_answer",
    "nxdomain",
    "timeout",
    "no_nameservers",
    "error",
]


DNSOverallStatus = Literal[
    "resolved",
    "partial",
    "no_data",
    "nxdomain",
    "error",
    "not_applicable",
]


class DNSRecordResult(BaseModel):
    """
    Result of querying one DNS record type at one DNS name.
    """

    record_type: str

    queried_name: str

    status: DNSQueryStatus

    records: list[str] = Field(
        default_factory=list
    )

    error: Optional[str] = None


class DNSResult(BaseModel):
    """
    Complete DNS intelligence.

    Preferred structured representation:

        hostname_records
        domain_records
        hostname_txt_records

    `records` is retained as a backward-compatible flat
    representation for older callers/tests.
    """

    hostname: str

    registrable_domain: Optional[str] = None

    status: DNSOverallStatus

    resolved_ips: list[str] = Field(
        default_factory=list
    )

    # -----------------------------------------------------
    # Preferred representation
    # -----------------------------------------------------

    hostname_records: dict[
        str,
        DNSRecordResult
    ] = Field(
        default_factory=dict
    )

    domain_records: dict[
        str,
        DNSRecordResult
    ] = Field(
        default_factory=dict
    )

    hostname_txt_records: Optional[
        DNSRecordResult
    ] = None

    # -----------------------------------------------------
    # Backward compatibility
    # -----------------------------------------------------

    records: dict[
        str,
        DNSRecordResult
    ] = Field(
        default_factory=dict
    )

# =========================================================
# IP INTELLIGENCE
# =========================================================

IPLookupStatus = Literal[
    "success",
    "private",
    "loopback",
    "link_local",
    "multicast",
    "reserved",
    "unspecified",
    "not_found",
    "rate_limited",
    "timeout",
    "error",
]


IPClassification = Literal[
    "public",
    "private",
    "loopback",
    "link_local",
    "multicast",
    "reserved",
    "unspecified",
]


class IPIntelligence(BaseModel):
    """
    Intelligence associated with a single IP address.

    Geolocation is approximate network-level information.
    """

    ip: str

    version: Literal[4, 6]

    classification: IPClassification

    status: IPLookupStatus

    # -----------------------------------------------------
    # Provider
    # -----------------------------------------------------

    source: Optional[str] = None

    # -----------------------------------------------------
    # Geographic information
    # -----------------------------------------------------

    country_code: Optional[str] = None

    country_name: Optional[str] = None

    region: Optional[str] = None

    region_code: Optional[str] = None

    city: Optional[str] = None

    postal: Optional[str] = None

    latitude: Optional[float] = None

    longitude: Optional[float] = None

    timezone: Optional[str] = None

    # -----------------------------------------------------
    # Network information
    # -----------------------------------------------------

    asn: Optional[str] = None

    organization: Optional[str] = None

    hostname: Optional[str] = None

    # -----------------------------------------------------
    # Error information
    # -----------------------------------------------------

    error: Optional[str] = None


class IPIntelligenceResponse(BaseModel):
    """
    Complete IP intelligence for all IPs discovered by DNS.
    """

    status: Literal[
        "completed",
        "partial",
        "no_public_ips",
        "error",
    ]

    total_ips: int = 0

    public_ips: int = 0

    enriched_ips: int = 0

    lookup_limit: int = 0

    limit_reached: bool = False

    results: list[IPIntelligence] = Field(
        default_factory=list
    )

# =========================================================
# WHOIS / RDAP
# =========================================================

RDAPStatus = Literal[
    "success",
    "not_found",
    "unsupported",
    "rate_limited",
    "forbidden",
    "timeout",
    "server_error",
    "invalid_response",
    "error",
    "not_applicable",
]


class RDAPEvent(BaseModel):
    """
    One registration lifecycle event.
    """

    action: str

    date: Optional[str] = None


class RDAPNameserver(BaseModel):
    """
    RDAP nameserver information.
    """

    hostname: str

    ipv4: list[str] = Field(
        default_factory=list
    )

    ipv6: list[str] = Field(
        default_factory=list
    )


class RDAPResult(BaseModel):
    """
    Normalized registration information for a domain.

    The actual source is RDAP even though the feature is
    presented to users as WHOIS / RDAP.
    """

    domain: str

    status: RDAPStatus

    source: Optional[str] = None

    rdap_server: Optional[str] = None

    # -----------------------------------------------------
    # Registration lifecycle
    # -----------------------------------------------------

    registration_date: Optional[str] = None

    expiration_date: Optional[str] = None

    last_updated_date: Optional[str] = None

    events: list[RDAPEvent] = Field(
        default_factory=list
    )

    # -----------------------------------------------------
    # Registrar / registry
    # -----------------------------------------------------

    registrar_name: Optional[str] = None

    registrar_id: Optional[str] = None

    registry_name: Optional[str] = None

    registry_id: Optional[str] = None

    # -----------------------------------------------------
    # Domain status
    # -----------------------------------------------------

    domain_status: list[str] = Field(
        default_factory=list
    )

    # -----------------------------------------------------
    # Nameservers
    # -----------------------------------------------------

    nameservers: list[RDAPNameserver] = Field(
        default_factory=list
    )

    # -----------------------------------------------------
    # DNSSEC
    # -----------------------------------------------------

    dnssec: Optional[str] = None

    # -----------------------------------------------------
    # Privacy / redaction
    # -----------------------------------------------------

    redacted: bool = False

    # -----------------------------------------------------
    # Raw-source metadata
    # -----------------------------------------------------

    raw_object_class: Optional[str] = None

    error: Optional[str] = None


class WhoisResult(BaseModel):
    """
    Public API naming for the WHOIS / RDAP feature.

    RDAPResult is kept as the normalized technical model,
    while WhoisResult gives the frontend a simple feature name.
    """

    domain: str

    status: RDAPStatus

    source: Optional[str] = None

    rdap_server: Optional[str] = None

    registration_date: Optional[str] = None

    expiration_date: Optional[str] = None

    last_updated_date: Optional[str] = None

    events: list[RDAPEvent] = Field(
        default_factory=list
    )

    registrar_name: Optional[str] = None

    registrar_id: Optional[str] = None

    registry_name: Optional[str] = None

    registry_id: Optional[str] = None

    domain_status: list[str] = Field(
        default_factory=list
    )

    nameservers: list[RDAPNameserver] = Field(
        default_factory=list
    )

    dnssec: Optional[str] = None

    redacted: bool = False

    error: Optional[str] = None

# =========================================================
# OSINT
# =========================================================

OSINTProviderStatus = Literal[
    "success",
    "no_match",
    "not_configured",
    "rate_limited",
    "timeout",
    "unauthorized",
    "forbidden",
    "invalid_request",
    "upstream_error",
    "error",
]


OSINTOverallStatus = Literal[
    "completed",
    "partial",
    "no_matches",
    "not_configured",
    "error",
]


class OSINTMatch(BaseModel):
    """
    One piece of evidence returned by an OSINT provider.

    This is evidence only.

    It does not represent PhishGuard's final threat score.
    """

    source: str

    match_type: str

    indicator: str

    reference: Optional[str] = None

    details: dict[str, Any] = Field(
        default_factory=dict
    )


class OSINTProviderResult(BaseModel):
    """
    Normalized result from one OSINT provider.
    """

    source: str

    status: OSINTProviderStatus

    query: str

    matched: bool = False

    match_count: int = 0

    matches: list[OSINTMatch] = Field(
        default_factory=list
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    error: Optional[str] = None


class OSINTResult(BaseModel):
    """
    Aggregated OSINT result across all providers.
    """

    status: OSINTOverallStatus

    providers: list[OSINTProviderResult] = Field(
        default_factory=list
    )

    matches: list[OSINTMatch] = Field(
        default_factory=list
    )

    total_matches: int = 0

# =========================================================
# FINAL ANALYSIS RESPONSE
# =========================================================

class AnalysisResponse(BaseModel):
    success: bool

    url: URLParts

    dns: DNSResult

    ip_intelligence: IPIntelligenceResponse

    whois: Optional[WhoisResult] = None
    
    osint: Optional[OSINTResult] = None