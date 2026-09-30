from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI,Response,status,HTTPException
import whois
import os
from pydantic import BaseModel

from .services.supabase_service import save_domain_scan

SUPABASE_URL : str = os.environ.get("SUPABASE_URL","")
SUPABASE_KEY : str = os.environ.get("SUPABASE_KEY","")
app = FastAPI()

@app.get("/")
def root():
    return {"Message":"Database is Running !"}

class DomainRequest(BaseModel):
    domain : str

