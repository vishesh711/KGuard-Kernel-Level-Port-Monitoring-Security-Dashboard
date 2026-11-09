"""
Login and user management (roadmap S6.5).

  POST   /api/auth/login              {"username", "password"} -> {"access_token", "role", ...}
  GET    /api/auth/me                 the logged-in user
  POST   /api/auth/password           change your own password (ends your other logins)
  GET    /api/auth/users              admin: every user
  POST   /api/auth/users              admin: {"username", "password", "role"}
  PATCH  /api/auth/users/{username}   admin: change role, enable/disable, set a password
  DELETE /api/auth/users/{username}   admin

The last active admin cannot be removed, disabled or made a viewer, so the
dashboard can never be left without one.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models.user import User
from ..security import login_throttle, too_many_requests
from ..services import auth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

USERNAME = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._@-]+$")


class LoginRequest(BaseModel):
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(..., max_length=256)
    new_password: str = Field(..., min_length=auth.MIN_PASSWORD_LENGTH, max_length=256)


class UserCreate(BaseModel):
    username: str = USERNAME
    password: str = Field(..., min_length=auth.MIN_PASSWORD_LENGTH, max_length=256)
    role: str = "viewer"


class UserUpdate(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=auth.MIN_PASSWORD_LENGTH, max_length=256)


@router.post("/login")
async def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client = request.client.host if request.client else "unknown"
    wait = login_throttle.retry_after(client, body.username)
    if wait:
        logger.warning("Login throttled", extra={"username": body.username, "client": client})
        return too_many_requests(wait, "Too many failed logins")

    user = auth.authenticate(db, body.username, body.password)
    if user is None:
        login_throttle.failed(client, body.username)
        logger.warning("Login failed", extra={"username": body.username, "client": client})
        raise HTTPException(status_code=401, detail="Wrong username or password",
                            headers={"WWW-Authenticate": "Bearer"})

    login_throttle.succeeded(body.username)
    user.last_login = datetime.utcnow()
    db.commit()
    logger.info("Login", extra={"username": user.username, "role": user.role, "client": client})
    return {
        "access_token": auth.create_token(user),
        "token_type": "bearer",
        "expires_in": settings.access_token_expire_minutes * 60,
        "username": user.username,
        "role": user.role,
    }


@router.get("/me")
async def me(user: User = Depends(auth.current_user)):
    return user.to_dict()


@router.post("/password")
async def change_password(body: PasswordChange, user: User = Depends(auth.current_user),
                          db: Session = Depends(get_db)):
    if not auth.verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is wrong")
    user.password_hash = auth.hash_password(body.new_password)
    user.token_version += 1
    db.commit()
    logger.info("Password changed", extra={"username": user.username})
    # The old token is now invalid; hand back a new one
    return {"access_token": auth.create_token(user), "token_type": "bearer"}


@router.get("/users", dependencies=[Depends(auth.require_admin)])
async def list_users(db: Session = Depends(get_db)):
    return [u.to_dict() for u in db.query(User).order_by(User.username)]


@router.post("/users", status_code=201)
async def create_user(body: UserCreate, admin: User = Depends(auth.require_admin),
                      db: Session = Depends(get_db)):
    auth.check_role(body.role)
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=409, detail="User already exists")
    user = User(username=body.username, password_hash=auth.hash_password(body.password),
                role=body.role, is_active=True, token_version=0)
    db.add(user)
    db.commit()
    logger.info("User created", extra={"username": body.username, "role": body.role, "by": admin.username})
    return user.to_dict()


def _other_active_admins(db: Session, user: User) -> int:
    return db.query(User).filter(User.role == "admin", User.is_active.is_(True), User.id != user.id).count()


def _get(db: Session, username: str) -> User:
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/users/{username}")
async def update_user(username: str, body: UserUpdate, admin: User = Depends(auth.require_admin),
                      db: Session = Depends(get_db)):
    user = _get(db, username)
    if body.role is not None:
        auth.check_role(body.role)
    loses_admin = user.role == "admin" and user.is_active and (
        (body.role is not None and body.role != "admin") or body.is_active is False)
    if loses_admin and not _other_active_admins(db, user):
        raise HTTPException(status_code=409, detail="Cannot remove the last active admin")

    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password is not None:
        user.password_hash = auth.hash_password(body.password)
    # Any change ends the user's current logins, so it applies at once
    user.token_version += 1
    db.commit()
    logger.info("User changed", extra={"username": username, "by": admin.username,
                                       "changes": body.model_dump(exclude_none=True, exclude={"password"})})
    return user.to_dict()


@router.delete("/users/{username}")
async def delete_user(username: str, admin: User = Depends(auth.require_admin),
                      db: Session = Depends(get_db)):
    user = _get(db, username)
    if user.role == "admin" and user.is_active and not _other_active_admins(db, user):
        raise HTTPException(status_code=409, detail="Cannot remove the last active admin")
    db.delete(user)
    db.commit()
    logger.info("User deleted", extra={"username": username, "by": admin.username})
    return {"success": True}
