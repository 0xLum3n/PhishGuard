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

from app.schemas.response import QueryParameter, URLParts

# ---------------------------------------------------------
# Constants
# ---------------------------------------------------------

SUPPORTED_SCHEMES = {
    "http",
    "https",
}

DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}

# ---------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------

def _clean_input(url: str) -> str:
    """
    Clean only accidental surrounding whitespace.

    We deliberately do NOT aggressively modify the URL because
    security analysis should preserve the user's original input.
    """

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    cleaned = url.strip()

    if not cleaned:
        raise ValueError("URL cannot be empty.")

    return cleaned


def _has_explicit_scheme(url: str) -> bool:
    """
    Determine whether the URL contains a scheme.

    Example:
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
    Normalize the minimum amount necessary for parsing.

    If the user enters:

        example.com/login

    we temporarily prepend https:// so urlsplit() interprets
    example.com as a hostname.

    The original input remains untouched and is returned separately.
    """

    if _has_explicit_scheme(url):
        return url

    # Reject protocol-relative URLs as direct analysis targets.
    if url.startswith("//"):
        raise ValueError(
            "Protocol-relative URLs are not supported. "
            "Provide http:// or https:// explicitly."
        )

    return f"https://{url}"


def _validate_scheme(scheme: str) -> str:
    """
    Validate the URL scheme.

    PhishGuard's URL checker currently focuses on HTTP/HTTPS URLs.
    """

    scheme = scheme.lower()

    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(
            f"Unsupported URL scheme '{scheme}'. "
            f"Only HTTP and HTTPS URLs are supported."
        )

    return scheme


def _validate_hostname(hostname: str | None) -> str:
    """
    Validate that a hostname exists and is structurally usable.
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

    # Hostnames cannot contain whitespace.
    if any(char.isspace() for char in hostname):
        raise ValueError(
            "Hostname cannot contain whitespace."
        )

    return hostname


def _is_ip_address(hostname: str) -> bool:
    """
    Return True when hostname is an IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _validate_ip_address(hostname: str) -> None:
    """
    Validate IP addresses explicitly.

    This catches malformed IP-like hostnames while allowing
    normal domain names.
    """

    if _is_ip_address(hostname):
        return

    # If it contains ':' it may be attempting to be IPv6.
    if ":" in hostname:
        raise ValueError(
            "Invalid IPv6 address."
        )


def _split_domain(
    hostname: str,
) -> tuple[str | None, str | None, str | None]:
    """
    Split hostname into:

        subdomain
        registrable domain
        TLD

    This implementation handles common multi-label public suffixes
    such as:

        co.uk
        com.au
        co.in
        org.uk
        gov.uk

    It is intentionally conservative. A proper Public Suffix List
    integration can be added later when we make domain intelligence
    more advanced.
    """

    if _is_ip_address(hostname):
        return None, hostname, None

    labels = hostname.split(".")

    if len(labels) < 2:
        return None, hostname, None

    known_multi_label_suffixes = {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",

        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "gen.in",
        "ind.in",

        "com.au",
        "net.au",
        "org.au",

        "co.nz",
        "net.nz",
        "org.nz",

        "co.jp",
        "ne.jp",
        "or.jp",

        "com.br",
        "net.br",

        "co.za",
        "org.za",
    }

    last_two = ".".join(labels[-2:])

    if last_two in known_multi_label_suffixes:

        if len(labels) < 3:
            return None, hostname, last_two

        registrable_domain = ".".join(labels[-3:])

        subdomain = ".".join(labels[:-3])

        return (
            subdomain or None,
            registrable_domain,
            last_two,
        )

    tld = labels[-1]

    registrable_domain = ".".join(labels[-2:])

    subdomain = ".".join(labels[:-2])

    return (
        subdomain or None,
        registrable_domain,
        tld,
    )


def _parse_query_parameters(
    query: str | None,
) -> list[QueryParameter]:
    """
    Parse query parameters while preserving duplicate parameters.

    Example:

        ?id=1&id=2&lang=en

    becomes:

        id -> values [1, 2]
        lang -> values [en]
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
    Produce a normalized URL for internal use.

    This does not replace the original URL.
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

    # IPv6 hosts need brackets when reconstructed.
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


# ---------------------------------------------------------
# Public parser
# ---------------------------------------------------------

def parse_url(
    original_url: str,
) -> URLParts:
    """
    Parse and validate a URL into security-relevant components.
    """

    original = _clean_input(original_url)

    normalized_input = _normalize_input(original)

    try:
        parsed = urlsplit(
            normalized_input,
        )

    except ValueError as exc:
        raise ValueError(
            f"Invalid URL structure: {exc}"
        ) from exc

    scheme = _validate_scheme(
        parsed.scheme
    )

    hostname = _validate_hostname(
        parsed.hostname
    )

    _validate_ip_address(hostname)

    # Accessing parsed.port can itself raise ValueError for
    # malformed/out-of-range ports.
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            f"Invalid port: {exc}"
        ) from exc

    # Explicit default ports remain explicit.
    #
    # https://example.com:443
    #
    # should return 443 because the user supplied it.
    #
    # https://example.com
    #
    # returns None because no explicit port was supplied.

    username = parsed.username
    password = parsed.password

    subdomain, registrable_domain, tld = _split_domain(
        hostname
    )

    query = parsed.query or None

    fragment = parsed.fragment or None

    path = parsed.path or "/"

    query_parameters = _parse_query_parameters(
        query
    )

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

    return URLParts(
        original=original,

        normalized=normalized,

        scheme=scheme,

        username=username,
        password=password,

        subdomain=subdomain,

        hostname=hostname,

        domain=registrable_domain,

        registrable_domain=registrable_domain,

        tld=tld,

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