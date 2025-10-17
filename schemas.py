# schemas.py
from pydantic import BaseModel
from typing import Optional, List

class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str

class User(BaseModel):
    id: int
    email: str
    first_name: str
    last_name: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

# schemas.py (additions)

class Credits(BaseModel):
    remaining_credits: int
    used_credits: int

class EmailVerificationLite(BaseModel):
    id: int
    email: str
    created_at: str
    status: str
    state: str
    reason: Optional[str]
    score: Optional[int]
    domain: Optional[str]

    class Config:
        from_attributes = True
