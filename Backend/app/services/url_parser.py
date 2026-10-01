from __future__ import annotations

import ipaddress
import re
from urllib.parse import (
    parse_qsl,
    quote,
    unquote,
    urlsplit,
    urlunsplit,
)

import tldextract

from app.schemas.response import QueryParameter, URLParts


# =========================================================
# Constants
# =========================================================

SUPPORTED_SCHEMES = {
    "http",
    "https",
}


# =========================================================
# Public Suffix List extractor
# =========================================================
#
# tldextract uses the Public Suffix List rather than a
# manually maintained list such as:
#
#     co.uk
#     co.in
#     com.au
#
# This gives us much more reliable domain boundaries.
#
# We keep private suffixes disabled for now because we want
# the normal ICANN/public suffix interpretation.
#
# fallback_to_snapshot=True means the package can still work
# from its bundled PSL snapshot if the live list cannot be
# downloaded.
# =========================================================

TLD_EXTRACTOR = tldextract.TLDExtract(
    include_psl_private_domains=False,
    fallback_to_snapshot=True,
)


# =========================================================
# Input handling
# =========================================================

def _clean_input(url: str) -> str:
    """
    Remove only accidental surrounding whitespace.

    We deliberately preserve the actual URL structure.
    """

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    cleaned = url.strip()

    if not cleaned:
        raise ValueError("URL cannot be empty.")

    return cleaned


def _has_explicit_scheme(url: str) -> bool:
    """
    Check whether the input explicitly contains a scheme.

    Examples:

        https://example.com -> True
        http://example.com  -> True
        example.com         -> False
    """

    return bool(
        re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            url,
        )
    )


def _normalize_input(url: str) -> str:
    """
    Prepare input for urllib.urlsplit().

    If the user supplies:

        example.com/login

    we temporarily interpret it as:

        https://example.com/login

    The original input is preserved separately.
    """

    if _has_explicit_scheme(url):
        return url

    if url.startswith("//"):
        raise ValueError(
            "Protocol-relative URLs are not supported. "
            "Please provide http:// or https:// explicitly."
        )

    return f"https://{url}"


# =========================================================
# Scheme
# =========================================================

def _validate_scheme(scheme: str) -> str:
    """
    Currently PhishGuard analyzes HTTP/HTTPS URLs.
    """

    scheme = scheme.lower()

    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(
            f"Unsupported URL scheme '{scheme}'. "
            "Only HTTP and HTTPS URLs are supported."
        )

    return scheme


# =========================================================
# Hostname
# =========================================================

def _validate_hostname(
    hostname: str | None,
) -> str:
    """
    Validate and normalize the hostname.
    """

    if not hostname:
        raise ValueError(
            "URL does not contain a valid hostname."
        )

    hostname = hostname.rstrip(".").lower()

    if not hostname:
        raise ValueError(
            "URL hostname is empty."
        )

    if any(character.isspace() for character in hostname):
        raise ValueError(
            "Hostname cannot contain whitespace."
        )

    return hostname


def _is_ip_address(hostname: str) -> bool:
    """
    Detect IPv4 and IPv6 addresses.
    """

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def _validate_ip_address(hostname: str) -> None:
    """
    Validate IPv6-like values that contain ':'.

    IPv4 addresses are handled naturally by ipaddress.
    """

    if _is_ip_address(hostname):
        return

    if ":" in hostname:
        raise ValueError(
            "Invalid IPv6 address."
        )


# =========================================================
# Domain extraction
# =========================================================

def _split_domain(
    hostname: str,
) -> tuple[
    str | None,
    str | None,
    str | None,
    str | None,
]:
    """
    Split a hostname using the Public Suffix List.

    Returns:

        subdomain
        registrable_domain
        domain
        public_suffix

    Example:

        login.account.example.com

    becomes:

        subdomain          = login.account
        registrable_domain = example.com
        domain             = example
        public_suffix      = com
    """

    # -----------------------------------------------------
    # IP addresses do not have domains/TLDs.
    # -----------------------------------------------------

    if _is_ip_address(hostname):

        return (
            None,
            hostname,
            hostname,
            None,
        )

    # -----------------------------------------------------
    # Extract using PSL.
    # -----------------------------------------------------

    extracted = TLD_EXTRACTOR(hostname)

    subdomain = extracted.subdomain or None

    domain = extracted.domain or None

    public_suffix = extracted.suffix or None

    registrable_domain = (
        extracted.top_domain_under_public_suffix
        or None
    )

    # -----------------------------------------------------
    # Unknown/unlisted suffix
    # -----------------------------------------------------
    #
    # For example:
    #
    #     something.internal
    #
    # If PSL doesn't recognize the suffix, we don't pretend
    # that "internal" is a valid public TLD.
    # -----------------------------------------------------

    if not public_suffix:

        if domain is None:

            return (
                subdomain,
                None,
                None,
                None,
            )

        return (
            subdomain,
            None,
            domain,
            None,
        )

    return (
        subdomain,
        registrable_domain,
        domain,
        public_suffix,
    )


# =========================================================
# Query parameters
# =========================================================

def _parse_query_parameters(
    query: str | None,
) -> list[QueryParameter]:
    """
    Parse query parameters while preserving duplicates.

    Example:

        ?id=1&id=2&lang=en

    becomes:

        id   -> [1, 2]
        lang -> [en]
    """

    if not query:
        return []

    pairs = parse_qsl(
        query,
        keep_blank_values=True,
        strict_parsing=False,
        encoding="utf-8",
        errors="replace",
    )

    grouped: dict[str, list[str]] = {}

    for name, value in pairs:

        decoded_name = unquote(name)

        decoded_value = unquote(value)

        grouped.setdefault(
            decoded_name,
            [],
        ).append(decoded_value)

    parameters: list[QueryParameter] = []

    for name, values in grouped.items():

        parameters.append(
            QueryParameter(
                name=name,
                value=values[0] if values else "",
                values=values,
            )
        )

    return parameters


# =========================================================
# URL reconstruction
# =========================================================

def _normalize_url(
    scheme: str,
    username: str | None,
    password: str | None,
    hostname: str,
    port: int | None,
    path: str,
    query: str | None,
    fragment: str | None,
) -> str:
    """
    Reconstruct a normalized URL.

    This is separate from `original`.
    """

    userinfo = ""

    if username is not None:

        userinfo = quote(
            username,
            safe="",
        )

        if password is not None:

            userinfo += ":"

            userinfo += quote(
                password,
                safe="",
            )

        userinfo += "@"

    # IPv6 must be surrounded by brackets in a URL.
    host_for_url = hostname

    if ":" in hostname and not hostname.startswith("["):

        host_for_url = f"[{hostname}]"

    netloc = f"{userinfo}{host_for_url}"

    if port is not None:

        netloc += f":{port}"

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            query or "",
            fragment or "",
        )
    )


# =========================================================
# Main parser
# =========================================================

def parse_url(
    original_url: str,
) -> URLParts:
    """
    Parse a URL into security-relevant components.
    """

    original = _clean_input(
        original_url
    )

    normalized_input = _normalize_input(
        original
    )

    # -----------------------------------------------------
    # Parse URL syntax
    # -----------------------------------------------------

    try:

        parsed = urlsplit(
            normalized_input
        )

    except ValueError as exc:

        raise ValueError(
            f"Invalid URL structure: {exc}"
        ) from exc

    # -----------------------------------------------------
    # Scheme
    # -----------------------------------------------------

    scheme = _validate_scheme(
        parsed.scheme
    )

    # -----------------------------------------------------
    # Hostname
    # -----------------------------------------------------

    hostname = _validate_hostname(
        parsed.hostname
    )

    _validate_ip_address(
        hostname
    )

    # -----------------------------------------------------
    # Port
    # -----------------------------------------------------

    try:

        port = parsed.port

    except ValueError as exc:

        raise ValueError(
            f"Invalid port: {exc}"
        ) from exc

    # -----------------------------------------------------
    # Credentials
    # -----------------------------------------------------

    username = parsed.username

    password = parsed.password

    # -----------------------------------------------------
    # Domain information
    # -----------------------------------------------------

    (
        subdomain,
        registrable_domain,
        domain,
        public_suffix,
    ) = _split_domain(
        hostname
    )

    # -----------------------------------------------------
    # Path
    # -----------------------------------------------------

    path = parsed.path or "/"

    # -----------------------------------------------------
    # Query
    # -----------------------------------------------------

    query = parsed.query or None

    query_parameters = (
        _parse_query_parameters(
            query
        )
    )

    # -----------------------------------------------------
    # Fragment
    # -----------------------------------------------------

    fragment = parsed.fragment or None

    # -----------------------------------------------------
    # Normalized URL
    # -----------------------------------------------------

    normalized = _normalize_url(
        scheme=scheme,
        username=username,
        password=password,
        hostname=hostname,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
    )

    # -----------------------------------------------------
    # Final response object
    # -----------------------------------------------------

    return URLParts(
        original=original,

        normalized=normalized,

        scheme=scheme,

        username=username,

        password=password,

        subdomain=subdomain,

        hostname=hostname,

        domain=domain,

        registrable_domain=registrable_domain,

        tld=public_suffix,

        port=port,

        path=path,

        query=query,

        query_parameters=query_parameters,

        fragment=fragment,

        has_credentials=(
            username is not None
            or password is not None
        ),

        has_query=query is not None,

        has_fragment=fragment is not None,

        is_ip_address=_is_ip_address(
            hostname
        ),
    )