"""
Login tokens, password hashing and role checks (roadmap S6.5).

Tokens are JWTs (HS256, signed with SECRET_KEY) carrying the username, role
and the user's token_version. Every request re-reads the user, so disabling
a user, changing their role or password takes effect at once: a token whose
token_version is out of date is refused.

Passwords are hashed with scrypt (Python's hashlib, no extra dependency):
    scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>
"""

import base64
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, Header, HTTPException, WebSocket
from sqlalchemy.orm import Session

from ..config import settings
from ..database import SessionLocal, get_db
from ..models.user import ROLES, User

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
ISSUER = "kguard"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
MIN_PASSWORD_LENGTH = 10

# Values from old docs and examples that must never be used as the key
PLACEHOLDER_KEYS = ("change-this", "change-me", "changeme", "your-secret", "dev-secret", "secret-key-here")
MIN_SECRET_KEY_LENGTH = 32


def secret_key_problem(key: str) -> Optional[str]:
    """Why this SECRET_KEY must not be used, or None if it is fine"""
    if not key:
        return "SECRET_KEY is not set"
    if len(key) < MIN_SECRET_KEY_LENGTH:
        return f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters"
    if any(p in key.lower() for p in PLACEHOLDER_KEYS):
        return "SECRET_KEY is an example value"
    return None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    b64 = base64.b64encode
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt).decode()}${b64(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt),
                                n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# Checked against when the username is unknown, so a wrong username takes
# as long as a wrong password and does not reveal which names exist
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def authenticate(db: Session, username: str, password: str) -> Optional[User]:
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        verify_password(password, _DUMMY_HASH)
        return None
    if not verify_password(password, user.password_hash) or not user.is_active:
        return None
    return user


def create_token(user: User, now: datetime = None) -> str:
    problem = secret_key_problem(settings.secret_key)
    if problem:
        raise RuntimeError(problem)
    now = now or datetime.now(timezone.utc)
    claims = {
        "iss": ISSUER,
        "sub": user.username,
        "role": user.role,
        "ver": user.token_version,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(claims, settings.secret_key, algorithm=ALGORITHM)


def user_from_token(db: Session, token: str) -> Optional[User]:
    """The active user a valid, current token belongs to, else None"""
    if not token or secret_key_problem(settings.secret_key):
        return None
    try:
        claims = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM], issuer=ISSUER,
                            options={"require": ["exp", "iat", "sub", "ver"]})
    except jwt.PyJWTError:
        return None
    user = db.query(User).filter(User.username == claims["sub"]).first()
    if user is None or not user.is_active or user.token_version != claims["ver"]:
        return None
    return user


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def current_user(authorization: str = Header("", include_in_schema=False),
                 db: Session = Depends(get_db)) -> User:
    """Dependency: any logged-in user (viewer or admin)"""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _unauthorized("Not logged in")
    user = user_from_token(db, token.strip())
    if user is None:
        raise _unauthorized("Login expired or not valid")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    """Dependency: admin only; a viewer gets 403"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def websocket_user(websocket: WebSocket, token: str = "") -> Optional[User]:
    """
    Browsers cannot set headers on a WebSocket, so the token comes in the
    query string (/ws?token=...). The access log records only the path.
    """
    token = token or websocket.headers.get("authorization", "").partition(" ")[2]
    db = SessionLocal()
    try:
        return user_from_token(db, token)
    finally:
        db.close()


def ensure_bootstrap_admin() -> None:
    """
    With no users at all, create the first admin from ADMIN_USERNAME and
    ADMIN_PASSWORD. Once any user exists these settings are ignored.
    """
    db = SessionLocal()
    try:
        if db.query(User).count():
            return
        if not settings.admin_password:
            logger.warning("No users yet: set ADMIN_PASSWORD (and ADMIN_USERNAME) to create the first "
                           "admin, or run: python -m app.users create <name> --role admin")
            return
        if len(settings.admin_password) < MIN_PASSWORD_LENGTH:
            logger.error(f"ADMIN_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters; "
                         "no admin created")
            return
        db.add(User(username=settings.admin_username, password_hash=hash_password(settings.admin_password),
                    role="admin", is_active=True, token_version=0))
        db.commit()
        logger.info(f"Created the first admin user '{settings.admin_username}'")
    finally:
        db.close()


def check_role(role: str) -> str:
    if role not in ROLES:
        raise HTTPException(status_code=422, detail=f"Role must be one of {', '.join(ROLES)}")
    return role
