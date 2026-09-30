import os
from supabase import create_client, Client

# These variables evaluate correctly because main.py loads the .env file
# before this module is imported.
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

# Initialize the client once
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def save_domain_scan(scan_data: dict) -> dict:
    """
    Inserts a domain scan record into the 'domain_scans' table.
    """
    response = supabase.table("domain_scans").insert(scan_data).execute()

    # Return the successfully inserted row
    return response.data[0] if response.data else {}