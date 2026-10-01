from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.api.routes.analysis import router as analysis_router


app = FastAPI(
    title="PhishGuard API",
    description="PhishGuard URL Analysis Backend",
    version="0.1.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    # Local development uses Vite (this project defaults to port 8443),
    # but Vite may move to another port if needed. Keep the explicit common
    # ports and allow loopback HTTP origins through the regex.
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8443",
        "http://127.0.0.1:8443",
    ],
    allow_origin_regex=r"^https?://(?:localhost|127\.0\.0\.1)(?::\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# Routes
# =========================================================

app.include_router(
    analysis_router,
    prefix="/api",
)


# =========================================================
# Health check
# =========================================================

@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "service": "PhishGuard API",
        "version": "0.1.0",
    }
