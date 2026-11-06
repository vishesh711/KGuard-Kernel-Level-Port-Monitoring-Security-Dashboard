"""
Agents API: remote hosts running kguard-agent.

  POST /api/agents/enroll   X-Enrollment-Key: <shared key>
                            {"name": "web-1", "hostname": "..."}
                            -> {"agent_id": 3, "token": "..."}
                            Enrolling an existing name issues a new token
                            (the old one stops working).
  POST /api/agents/ingest   Authorization: Bearer <token>
                            {"agent": {...}, "kernel_dropped": N,
                             "queue_dropped": N, "events": [...]}
  GET  /api/agents          every agent with its status and counters
"""

import hashlib
import hmac
import secrets
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models.agent import Agent
from ..services.data_collector import data_collector
from ..services.payloads import payload_service

router = APIRouter(prefix="/api/agents", tags=["agents"])

# The agent sends at most 256 per batch
MAX_INGEST_PAYLOADS = 2000


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class EnrollRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    hostname: str = Field("", max_length=255)


class AgentInfo(BaseModel):
    engine: str = Field("", max_length=16)
    version: str = Field("", max_length=32)
    hostname: str = Field("", max_length=255)


class IngestRequest(BaseModel):
    agent: AgentInfo = AgentInfo()
    kernel_dropped: int = Field(0, ge=0)
    queue_dropped: int = Field(0, ge=0)
    payload_dropped: int = Field(0, ge=0)
    events: List[Dict[str, Any]] = []
    # DNS messages and TLS ClientHellos sampled by the eBPF engine
    payloads: List[Dict[str, Any]] = []


@router.post("/enroll")
async def enroll(
    body: EnrollRequest,
    x_enrollment_key: str = Header("", alias="X-Enrollment-Key"),
    db: Session = Depends(get_db),
):
    expected = settings.agent_enrollment_key
    if not expected:
        raise HTTPException(status_code=403, detail="Agent enrollment is disabled (set AGENT_ENROLLMENT_KEY)")
    if not hmac.compare_digest(x_enrollment_key.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="Wrong enrollment key")

    token = secrets.token_urlsafe(32)
    agent = db.query(Agent).filter(Agent.name == body.name).first()
    if agent:
        agent.token_hash = hash_token(token)
        agent.hostname = body.hostname or agent.hostname
    else:
        agent = Agent(name=body.name, hostname=body.hostname, token_hash=hash_token(token),
                      events_received=0, kernel_dropped=0, queue_dropped=0)
        db.add(agent)
    db.commit()
    db.refresh(agent)
    return {"agent_id": agent.id, "token": token}


def current_agent(authorization: str = Header(""), db: Session = Depends(get_db)) -> Agent:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Missing agent token")
    agent = db.query(Agent).filter(Agent.token_hash == hash_token(token)).first()
    if not agent:
        raise HTTPException(status_code=401, detail="Unknown agent token")
    return agent


@router.post("/ingest")
async def ingest(
    body: IngestRequest,
    request: Request,
    agent: Agent = Depends(current_agent),
    db: Session = Depends(get_db),
):
    if len(body.events) > settings.max_ingest_events:
        raise HTTPException(status_code=413, detail=f"At most {settings.max_ingest_events} events per batch")

    if len(body.payloads) > MAX_INGEST_PAYLOADS:
        raise HTTPException(status_code=413,
                            detail=f"At most {MAX_INGEST_PAYLOADS} payload samples per batch")

    events = data_collector.valid_events(body.events)
    stored = await data_collector.ingest(events, host_id=agent.id) if events else 0
    samples = await payload_service.ingest(body.payloads, host_id=agent.id) if body.payloads else {}

    agent.last_seen = datetime.utcnow()
    agent.remote_addr = request.client.host if request.client else None
    agent.engine = body.agent.engine or agent.engine
    agent.version = body.agent.version or agent.version
    agent.hostname = body.agent.hostname or agent.hostname
    agent.events_received = (agent.events_received or 0) + stored
    # The agent reports running totals
    agent.kernel_dropped = body.kernel_dropped
    agent.queue_dropped = body.queue_dropped
    agent.payload_dropped = body.payload_dropped
    db.commit()

    return {"accepted": stored, "rejected": len(body.events) - len(events),
            "payloads_accepted": samples.get("accepted", 0)}


@router.get("/")
async def list_agents(db: Session = Depends(get_db)):
    agents = db.query(Agent).order_by(Agent.name).all()
    return [a.to_dict() for a in agents]
