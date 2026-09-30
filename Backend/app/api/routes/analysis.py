from fastapi import APIRouter, HTTPException, status

from app.schemas.request import AnalyzeRequest
from app.schemas.response import AnalysisResponse
from app.services.analysis_service import analyze_url


router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"],
)


@router.post(
    "",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
)
async def analyze(request: AnalyzeRequest,):
    """
    Analyze a URL.

    Step 1:
        Validate and decompose the URL.
    """

    try:
        return analyze_url(request.url)

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc