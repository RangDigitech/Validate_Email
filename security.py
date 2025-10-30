from datetime import datetime, timedelta
from typing import Optional
import os
import base64
import hashlib
import hmac

from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import get_db

# Minimal password hashing (PBKDF2-HMAC-SHA256) without external backends.
_ALG = "pbkdf2_sha256"
_ITERATIONS = 260_000
_SALT_LEN = 16

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# JWT settings
SECRET_KEY = "abcdefghijklmnopqrstuvwxyzz"  # Change this in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 360


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password stored as: alg$iterations$salt_b64$hash_b64."""
    try:
        algo, iters_s, salt_b64, hash_b64 = (hashed_password or "").split("$", 4)
        if algo != _ALG:
            return False
        iterations = int(iters_s)
        salt = _b64d(salt_b64)
        expected = _b64d(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 (pure stdlib, no 72-byte limit)."""
    if not isinstance(password, str):
        password = str(password)
    salt = os.urandom(_SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"{_ALG}${_ITERATIONS}${_b64e(salt)}${_b64e(dk)}"



def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS))  # <-- days, not minutes
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[str]:
    """
    Decode and verify a JWT token.
    Returns the email (subject) if valid, otherwise None.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        return email
    except JWTError:
        return None


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Get the current authenticated user from the JWT token.
    This function is used as a dependency in protected routes.
    """
    import models

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    email = decode_access_token(token)
    if email is None:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user
