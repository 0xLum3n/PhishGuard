from pydantic import BaseModel,Field

# This file is for defining the validation of the input in the request

class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=9999, description="URL to Analyze",
                     examples=["https://www.example.com/login?id=123&lang=en#section"]
                     )

