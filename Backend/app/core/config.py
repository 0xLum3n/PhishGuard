from __future__ import annotations

import os

from dotenv import load_dotenv


# ---------------------------------------------------------
# Load .env
# ---------------------------------------------------------

load_dotenv()


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _get_float(
    name: str,
    default: float,
) -> float:
    value = os.getenv(name)

    if not value:
        return default

    try:
        parsed = float(value)

        if parsed <= 0:
            return default

        return parsed

    except ValueError:
        return default


def _get_int(
    name: str,
    default: int,
) -> int:
    value = os.getenv(name)

    if not value:
        return default

    try:
        parsed = int(value)

        if parsed <= 0:
            return default

        return parsed

    except ValueError:
        return default


# ---------------------------------------------------------
# Settings
# ---------------------------------------------------------

class Settings:
    """
    Application configuration.

    Secrets are read from environment variables and are never
    hard-coded into the application.
    """

    # -----------------------------------------------------
    # PhishTank
    # -----------------------------------------------------

    PHISHTANK_APP_KEY = os.getenv(
        "PHISHTANK_APP_KEY"
    )

    # -----------------------------------------------------
    # URLhaus
    # -----------------------------------------------------

    URLHAUS_AUTH_KEY = os.getenv(
        "URLHAUS_AUTH_KEY"
    )

    # -----------------------------------------------------
    # urlscan.io
    # -----------------------------------------------------

    URLSCAN_API_KEY = os.getenv(
        "URLSCAN_API_KEY"
    )

    # -----------------------------------------------------
    # OSINT
    # -----------------------------------------------------

    OSINT_TIMEOUT = _get_float(
        "OSINT_TIMEOUT",
        8.0,
    )

    URLSCAN_MAX_RESULTS = _get_int(
        "URLSCAN_MAX_RESULTS",
        10,
    )

    USER_AGENT = os.getenv(
        "PHISHGUARD_USER_AGENT",
        "PhishGuard/0.1",
    )

    # -----------------------------------------------------
    # Lowercase compatibility aliases
    # -----------------------------------------------------
    #
    # Providers use these names.
    # Keep the uppercase names above because they are part
    # of the existing configuration contract.
    # -----------------------------------------------------

    phishtank_app_key = PHISHTANK_APP_KEY
    urlhaus_auth_key = URLHAUS_AUTH_KEY
    urlscan_api_key = URLSCAN_API_KEY

    osint_timeout = OSINT_TIMEOUT
    urlscan_max_results = URLSCAN_MAX_RESULTS
    user_agent = USER_AGENT


settings = Settings()