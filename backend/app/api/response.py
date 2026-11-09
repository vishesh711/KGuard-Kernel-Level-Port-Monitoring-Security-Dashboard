"""
Response API (roadmap S6.4). Reading needs a login; changing needs admin.

  GET    /api/response/blocks              active blocks (?include_removed=true for history)
  POST   /api/response/blocks              {"cidr", "reason", "minutes"?, "host_id"?}
  DELETE /api/response/blocks/{id}         unblock
  GET    /api/response/allowlist
  POST   /api/response/allowlist           {"cidr", "note"?}  (also unblocks what it covers)
  DELETE /api/response/allowlist/{id}
  GET    /api/response/audit               newest first, ?page=&size=&action=
  GET    /api/response/status              rules, this machine's enforcement, each agent's sync state
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models.agent import Agent
from ..models.response import AllowEntry, AuditEntry, Block
from ..models.user import User
from ..services.auth import require_admin
from ..services.local_enforcer import local_enforcer
from ..services.response import BlockRefused, response_engine

router = APIRouter(prefix="/api/response", tags=["response"])


class BlockRequest(BaseModel):
    cidr: str = Field(..., max_length=49, description="Address or prefix, e.g. 203.0.113.7 or 203.0.113.0/24")
    reason: str = Field(..., min_length=1, max_length=500)
    minutes: Optional[int] = Field(None, ge=1, le=366 * 24 * 60, description="Empty: until unblocked")
    host_id: Optional[int] = Field(None, description="Only on this agent's host; empty: every host")


class AllowRequest(BaseModel):
    cidr: str = Field(..., max_length=49)
    note: str = Field("", max_length=500)


@router.get("/blocks")
async def list_blocks(include_removed: bool = False, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    if include_removed:
        blocks = db.query(Block).order_by(desc(Block.id)).limit(1000).all()
    else:
        blocks = response_engine.active(db, now=now)
    return [b.to_dict(now) for b in blocks]


@router.post("/blocks", status_code=201)
async def add_block(body: BlockRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if body.host_id is not None and not db.get(Agent, body.host_id):
        raise HTTPException(status_code=404, detail="No such agent")
    try:
        block, created = response_engine.block(db, body.cidr, reason=body.reason, actor=user.username,
                                               minutes=body.minutes, host_id=body.host_id)
    except BlockRefused as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {**block.to_dict(), "created": created}


@router.delete("/blocks/{block_id}")
async def remove_block(block_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    block = db.get(Block, block_id)
    if block is None:
        raise HTTPException(status_code=404, detail="Block not found")
    if not response_engine.unblock(db, block, user.username):
        raise HTTPException(status_code=409, detail="Already removed")
    return block.to_dict()


@router.get("/allowlist")
async def list_allowlist(db: Session = Depends(get_db)):
    return [e.to_dict() for e in db.query(AllowEntry).order_by(AllowEntry.cidr)]


@router.post("/allowlist", status_code=201)
async def add_allow(body: AllowRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        return response_engine.allow(db, body.cidr, user.username, body.note).to_dict()
    except BlockRefused as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.delete("/allowlist/{entry_id}")
async def remove_allow(entry_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    entry = db.get(AllowEntry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Allowlist entry not found")
    response_engine.disallow(db, entry, user.username)
    return {"success": True}


@router.get("/audit")
async def audit_log(page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500),
                    action: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(AuditEntry)
    if action:
        query = query.filter(AuditEntry.action == action)
    total = query.count()
    items = query.order_by(desc(AuditEntry.id)).offset((page - 1) * size).limit(size).all()
    return {"items": [e.to_dict() for e in items], "total": total, "page": page, "size": size}


@router.get("/status")
async def status(db: Session = Depends(get_db)):
    agents = []
    for agent in db.query(Agent).order_by(Agent.name):
        _, version = response_engine.blocklist_text(response_engine.active(db, host_id=agent.id))
        agents.append({
            "id": agent.id,
            "name": agent.name,
            "engine": agent.engine,
            "in_sync": agent.blocklist_applied == version and not agent.blocklist_failed,
            "applied": agent.blocklist_applied,
            "current": version,
            "failed": agent.blocklist_failed,
            "enforcing": agent.blocklist_enforcing,
            "synced_at": agent.blocklist_synced_at.isoformat() if agent.blocklist_synced_at else None,
        })
    return {
        "rules": {
            "auto_block": settings.auto_block,
            "types": settings.auto_block_types,
            "min_severity": settings.auto_block_min_severity,
            "listed_sources": settings.auto_block_listed_sources,
            "minutes": settings.auto_block_minutes,
            "lease_seconds": settings.block_lease_seconds,
        },
        "active_blocks": len(response_engine.active(db)),
        "local": local_enforcer.get_stats(),
        "agents": agents,
        "stats": response_engine.get_stats(),
    }
