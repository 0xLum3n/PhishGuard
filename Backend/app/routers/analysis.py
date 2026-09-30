from fastapi import FastAPI,Response,status,HTTPException,APIRouter
import whois
import os
from pydantic import BaseModel

router = APIRouter(
    prefix ="/api",
    tags=['']
)

