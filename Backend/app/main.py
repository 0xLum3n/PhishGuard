from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI,Response,status,HTTPException
from starlette.middleware.cors import (CORSMiddleware)
from ..app.api.routes.analysis import router as analysis_router

app = FastAPI(
    title="PhishGuard API",
    description="PhishGuard URL Analysis Backend",
    version="0.1.0"
)

#---------------------------------------
# CORS Middleware
#---------------------------------------

app.add_middleware( # type : ignore
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://localhost:5173",
        "https://127.0.0.1:5173",
        "http://localhost:8443",
        "http://127.0.0.1:8443",
        "https://localhost:8443",
        "https://127.0.0.1:8443",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# Routes
# ---------------------------------------------------------

app.include_router(
    analysis_router,
    prefix="/api",
)


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "service": "PhishGuard API",
        "version": "0.1.0",
    }
