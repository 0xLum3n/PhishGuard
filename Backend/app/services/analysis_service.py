from app.schemas.response import AnalysisResponse
from app.services.url_parser import parse_url


def analyze_url(
    url: str,
) -> AnalysisResponse:
    """
    Step 1 analysis pipeline.

    Currently this performs URL validation and decomposition only.

    DNS, WHOIS, IP intelligence, OSINT and threat analysis will
    be added in later phases.
    """

    parsed_url = parse_url(url)

    return AnalysisResponse(
        success=True,
        url=parsed_url,
    )