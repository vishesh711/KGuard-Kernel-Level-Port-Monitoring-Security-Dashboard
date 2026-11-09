"""
Notifications API (roadmap S6.7)

  GET  /api/notifications/status   which channels are configured, sent/failed/held back (any user)
  POST /api/notifications/test     send a test alert to every channel now (admin)
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from ..models.user import User
from ..services.auth import require_admin
from ..services.notifier import notifier

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("/status")
async def status():
    return notifier.get_stats()


@router.post("/test")
async def send_test(user: User = Depends(require_admin)):
    if not any(c.configured() for c in notifier.channels):
        raise HTTPException(status_code=409, detail="No channel configured (set SLACK_WEBHOOK_URL, "
                            "TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, or SMTP_HOST, EMAIL_FROM and EMAIL_TO)")
    alert = {
        "alert_type": "TEST", "severity": "HIGH", "title": "Test notification from KGuard",
        "description": f"Sent by {user.username} at {datetime.utcnow().isoformat(timespec='seconds')} UTC "
                       "to check this channel.",
    }
    return {"results": await notifier.deliver(alert, test=True)}
