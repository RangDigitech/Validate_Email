# schemas.py
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

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

class BlogPostCreate(BaseModel):
    title: str
    author_name: str
    cover_image_url: Optional[str] = None
    excerpt: Optional[str] = None
    content_md: str
    status: str = "draft"                 # 'draft' | 'published'
    published_at: Optional[datetime] = None

class BlogPostUpdate(BaseModel):
    title: Optional[str] = None
    author_name: Optional[str] = None
    cover_image_url: Optional[str] = None
    excerpt: Optional[str] = None
    content_md: Optional[str] = None
    status: Optional[str] = None          # 'draft' | 'published'
    published_at: Optional[datetime] = None

# Public response (no content_md)
class BlogPostPublicOut(BaseModel):
    id: int
    slug: str
    title: str
    author_name: str
    cover_image_url: Optional[str]
    excerpt: Optional[str]
    content_html: str
    status: str
    published_at: Optional[datetime]

    class Config:
        from_attributes = True

class BlogPostPublicList(BaseModel):
    items: List[BlogPostPublicOut]
    total: int
    page: int
    pages: int

# Admin response (includes content_md)
class BlogPostAdminOut(BlogPostPublicOut):
    content_md: str

class BlogPostAdminList(BaseModel):
    items: List[BlogPostAdminOut]