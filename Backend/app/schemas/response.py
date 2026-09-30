from pydantic import BaseModel,Field

# This is for response input validation , to be shown to the users

from typing import Optional

from pydantic import BaseModel, Field


class QueryParameter(BaseModel):
    # Represents one query-string parameter.
    name: str
    value: str
    values: list[str] = Field(default_factory=list)


class URLParts(BaseModel):
    """
    Fully decomposed URL.
    """

    original: str
    normalized: str
    scheme: str
    username: Optional[str] = None
    password: Optional[str] = None
    subdomain: Optional[str] = None
    hostname: str
    domain: Optional[str] = None
    registrable_domain: Optional[str] = None
    tld: Optional[str] = None
    port: Optional[int] = None
    path: str
    query: Optional[str] = None
    query_parameters: list[QueryParameter] = Field(
        default_factory=list
    )
    fragment: Optional[str] = None
    has_credentials: bool = False
    has_query: bool = False
    has_fragment: bool = False
    is_ip_address: bool = False


class AnalysisResponse(BaseModel):
    """
    Response returned by /api/analyze.
    """
    success: bool
    url: URLParts