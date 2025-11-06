# blog_routes.py
from __future__ import annotations
import re
import unicodedata
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_, func

import models
import schemas
from database import get_db
from security import get_current_user

# Markdown -> HTML + sanitize
# pip install markdown bleach
import bleach
from markdown import markdown as md_to_html

router = APIRouter()

# ---------- Helpers ----------

ALLOWED_TAGS = bleach.sanitizer.ALLOWED_TAGS.union({
    "p", "pre", "span", "h1", "h2", "h3", "h4", "h5", "h6",
    "img", "hr", "br", "blockquote", "code", "ul", "ol", "li",
    "table", "thead", "tbody", "tr", "th", "td", "a", "strong", "em"
})
ALLOWED_ATTRS = {
    **bleach.sanitizer.ALLOWED_ATTRIBUTES,
    "img": ["src", "alt", "title", "width", "height"],
    "a": ["href", "title", "rel", "target"],
    "span": ["class"],
    "code": ["class"],
}
ALLOWED_PROTOCOLS = ["http", "https", "mailto"]

def render_markdown_sanitized(md_text: str) -> str:
    # Convert Markdown -> HTML
    html = md_to_html(md_text or "", extensions=["extra", "sane_lists", "tables", "codehilite"])
    # Sanitize
    html = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )
    # linkify (adds rel="nofollow" etc.)
    html = bleach.linkify(html)
    return html

_slug_strip_re = re.compile(r"[^\w\s-]")
_slug_hyphenate_re = re.compile(r"[-\s]+")

def slugify(value: str) -> str:
    value = str(value or "").strip().lower()
    value = unicodedata.normalize("NFKD", value)
    value = _slug_strip_re.sub("", value)
    value = _slug_hyphenate_re.sub("-", value).strip("-")
    return value or "post"

def unique_slug(session: Session, base_title: str) -> str:
    base = slugify(base_title)
    slug = base
    # check duplicates: base, base-2, base-3...
    i = 2
    while session.query(models.BlogPost).filter(models.BlogPost.slug == slug).first():
        slug = f"{base}-{i}"
        i += 1
    return slug

def assert_admin(user) -> None:
    if not getattr(user, "is_admin", False):
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")

# ---------- Admin Endpoints ----------

@router.post("/admin/blog-posts", response_model=schemas.BlogPostAdminOut, status_code=201)
def create_blog_post(
    payload: schemas.BlogPostCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    assert_admin(current_user)

    slug = unique_slug(db, payload.title)
    html = render_markdown_sanitized(payload.content_md)

    published_at = payload.published_at
    if payload.status == "published" and not published_at:
        published_at = datetime.now(timezone.utc)

    post = models.BlogPost(
        slug=slug,
        title=payload.title,
        author_name=payload.author_name,
        cover_image_url=payload.cover_image_url,
        excerpt=payload.excerpt,
        content_md=payload.content_md,
        content_html=html,
        status=payload.status,
        published_at=published_at,
    )
    db.add(post)
    db.commit()
    db.refresh(post)
    return post

@router.patch("/admin/blog-posts/{post_id}", response_model=schemas.BlogPostAdminOut)
def update_blog_post(
    post_id: int,
    payload: schemas.BlogPostUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    assert_admin(current_user)

    post = db.query(models.BlogPost).filter(models.BlogPost.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Apply updates
    if payload.title is not None and payload.title != post.title:
        post.title = payload.title
        post.slug = unique_slug(db, payload.title)  # regenerate if title changed

    if payload.author_name is not None:
        post.author_name = payload.author_name
    if payload.cover_image_url is not None:
        post.cover_image_url = payload.cover_image_url
    if payload.excerpt is not None:
        post.excerpt = payload.excerpt
    if payload.content_md is not None:
        post.content_md = payload.content_md
        post.content_html = render_markdown_sanitized(payload.content_md)
    if payload.status is not None:
        post.status = payload.status
    if payload.published_at is not None:
        post.published_at = payload.published_at
    elif post.status == "published" and not post.published_at:
        post.published_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(post)
    return post

@router.delete("/admin/blog-posts/{post_id}", status_code=204)
def delete_blog_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    assert_admin(current_user)

    post = db.query(models.BlogPost).filter(models.BlogPost.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    db.delete(post)
    db.commit()
    return None

@router.get("/admin/blog-posts", response_model=schemas.BlogPostAdminList)
def list_admin_blog_posts(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    assert_admin(current_user)
    posts = (db.query(models.BlogPost)
               .order_by(models.BlogPost.created_at.desc())
               .all())
    return {"items": posts}

# ---------- Public Endpoints ----------

@router.get("/blog-posts", response_model=schemas.BlogPostPublicList)
def list_public_blog_posts(
    page: int = Query(1, ge=1),
    limit: int = Query(12, ge=1, le=100),
    q: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(models.BlogPost).filter(
        models.BlogPost.status == "published",
        models.BlogPost.published_at.isnot(None)
    )
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(or_(
            func.lower(models.BlogPost.title).like(like),
            func.lower(models.BlogPost.content_md).like(like),
            func.lower(models.BlogPost.excerpt).like(like)
        ))

    total = query.count()
    items = (query
             .order_by(models.BlogPost.published_at.desc())
             .offset((page - 1) * limit)
             .limit(limit)
             .all())
    return {"items": items, "total": total, "page": page, "pages": (total + limit - 1) // limit}

@router.get("/blog-posts/{slug}", response_model=schemas.BlogPostPublicOut)
def get_public_blog_post(slug: str, db: Session = Depends(get_db)):
    post = (db.query(models.BlogPost)
              .filter(models.BlogPost.slug == slug,
                      models.BlogPost.status == "published")
              .first())
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return post
