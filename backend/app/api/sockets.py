"""
Listening ports and connections (roadmap U7.2). Reading needs a login;
marking a listener known needs admin.

  GET  /api/sockets?host_id=0          this server (0) or an agent's host
  POST /api/sockets/known              {"host_id", "proto", "port", "process"}
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models.agent import Agent
from ..models.listener import KnownListener, ListenerBaseline
from ..models.user import User
from ..services.auth import require_admin
from ..services.sockets import listener_key, snapshot

router = APIRouter(prefix="/api/sockets", tags=["sockets"])


class KnownRequest(BaseModel):
    host_id: int = Field(0, ge=0, description="0: this server")
    proto: str = Field(..., pattern="^(TCP|UDP)$")
    port: int = Field(..., ge=0, le=65535)
    process: str = Field("", max_length=64)


def ensure_baseline(db: Session, host_key: int, snap: Dict[str, Any], who: str = "baseline") -> None:
    """The first snapshot a host gives is its normal set of listeners"""
    if db.get(ListenerBaseline, host_key) is not None:
        return
    for key in {listener_key(item) for item in snap["listeners"]}:
        db.add(KnownListener(host_key=host_key, proto=key[0], port=key[1], process=key[2],
                             created_by=who))
    db.add(ListenerBaseline(host_key=host_key))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # another request baselined it first


def annotate(db: Session, host_key: int, snap: Dict[str, Any]) -> Dict[str, Any]:
    """Flag listeners that are not known"""
    ensure_baseline(db, host_key, snap)
    rows = db.query(KnownListener).filter(KnownListener.host_key == host_key)
    known = {(k.proto, k.port, k.process) for k in rows}
    listeners = [{**item, "new": listener_key(item) not in known} for item in snap["listeners"]]
    return {**snap, "listeners": listeners}


def baseline_this_server() -> None:
    """At start-up: what listens now is this server's normal set (first start only)"""
    from ..database import SessionLocal

    db = SessionLocal()
    try:
        ensure_baseline(db, 0, snapshot(settings.proc_root))
    finally:
        db.close()


@router.get("")
async def get_sockets(host_id: int = Query(0, ge=0), db: Session = Depends(get_db)):
    if host_id == 0:
        snap = await asyncio.get_running_loop().run_in_executor(None, snapshot, settings.proc_root)
        taken_at = datetime.utcnow()
        host = "this server"
    else:
        agent = db.get(Agent, host_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="No such agent")
        if not agent.sockets:
            return {"host": agent.name, "taken_at": None, "listeners": [], "connections": []}
        snap, taken_at, host = agent.sockets, agent.sockets_at, agent.name
    result = annotate(db, host_id, snap)
    return {"host": host, "taken_at": taken_at.isoformat() if taken_at else None, **result}


@router.post("/known", status_code=201)
async def mark_known(body: KnownRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if body.host_id and db.get(Agent, body.host_id) is None:
        raise HTTPException(status_code=404, detail="No such agent")
    db.add(KnownListener(host_key=body.host_id, proto=body.proto, port=body.port, process=body.process,
                         created_by=user.username))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
    return {"success": True}


class SocketItem(BaseModel):
    proto: str = Field(..., pattern="^(TCP|UDP)$")
    family: int = Field(4)
    local: str = Field(..., max_length=45)
    lport: int = Field(..., ge=0, le=65535)
    remote: str = Field("", max_length=45)
    rport: int = Field(0, ge=0, le=65535)
    state: str = Field(..., max_length=16)
    uid: int = Field(-1)
    inode: int = Field(0)
    pid: Optional[int] = None
    process: Optional[str] = Field(None, max_length=64)
    user: Optional[str] = Field(None, max_length=64)


class SocketSnapshot(BaseModel):
    listeners: list[SocketItem] = Field(default_factory=list, max_length=5000)
    connections: list[SocketItem] = Field(default_factory=list, max_length=5000)
