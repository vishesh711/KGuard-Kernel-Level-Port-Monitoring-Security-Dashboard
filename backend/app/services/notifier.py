"""
Alert notifications (roadmap S6.7): Slack, email and Telegram.

Every new alert at or above NOTIFY_MIN_SEVERITY (HIGH) goes to each
configured channel:

    Slack      SLACK_WEBHOOK_URL (an incoming webhook)
    Telegram   TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID (Bot API sendMessage)
    email      SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_STARTTLS,
               EMAIL_FROM, EMAIL_TO

Sending happens in a background task, so a slow or unreachable service
never holds up detection. Each channel has its own rate limit,
NOTIFY_MAX_PER_HOUR (30): past it, alerts are counted instead of sent, and
the next message that goes out says how many were held back. A failed send
is retried three times (honouring Slack's and Telegram's Retry-After).

Webhook URLs, bot tokens and passwords are secrets: they are never logged
or returned by the API.

POST /api/notifications/test (admin) sends a test alert to every channel and
reports each result, so a new webhook can be checked straight away.
"""

import asyncio
import json
import logging
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from collections import deque
from email.message import EmailMessage
from typing import Any, Callable, Deque, Dict, List, Optional

from ..config import settings

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MARK = {"LOW": "🔵", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
QUEUE_LIMIT = 1000
RETRIES = 3


class SendError(Exception):
    def __init__(self, message: str, retry_after: Optional[float] = None, permanent: bool = False):
        super().__init__(message)
        self.retry_after = retry_after
        self.permanent = permanent


def _post_json(url: str, payload: Dict[str, Any], timeout: float = 10) -> None:
    request = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read()
    except urllib.error.HTTPError as e:
        # The message names the status only: the URL may hold a secret
        retry = e.headers.get("Retry-After") if e.headers else None
        body = e.read()[:200].decode(errors="replace")
        raise SendError(f"HTTP {e.code}: {body}", float(retry) if retry and retry.isdigit() else None,
                        permanent=e.code in (400, 401, 403, 404))
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise SendError(f"cannot connect: {reason}")


def summary(alert: Dict[str, Any]) -> Dict[str, str]:
    """Title and lines of text shared by every channel"""
    severity = alert.get("severity") or "?"
    lines = [alert.get("description") or ""]
    where = []
    if alert.get("src_ip"):
        where.append(f"from {alert['src_ip']}")
    if alert.get("dst_ip"):
        where.append(f"to {alert['dst_ip']}" + (f":{alert['dst_port']}" if alert.get("dst_port") else ""))
    if where:
        lines.append(" ".join(where))
    enrichment = (alert.get("metadata") or {}).get("enrichment") or {}
    src = enrichment.get("src") or {}
    extra = []
    if src.get("country"):
        extra.append(f"country {src['country']}" + (f", AS{src['asn']} {src.get('as_org') or ''}".rstrip()
                                                      if src.get("asn") else ""))
    if src.get("threat_lists"):
        extra.append("on " + ", ".join(src["threat_lists"]))
    if enrichment.get("mitre"):
        extra.append("ATT&CK " + ", ".join(t["id"] for t in enrichment["mitre"]))
    if extra:
        lines.append(" · ".join(extra))
    if settings.dashboard_url and alert.get("id"):
        lines.append(f"{settings.dashboard_url.rstrip('/')}/alerts?id={alert['id']}")
    title = f"{MARK.get(severity, '')} [{severity}] {alert.get('title') or alert.get('alert_type')}".strip()
    return {"title": title, "text": "\n".join(line for line in lines if line)}


class Channel:
    name = "channel"

    def __init__(self):
        self.sent_times: Deque[float] = deque()
        self.held_back = 0
        self.stats = {"sent": 0, "failed": 0, "held_back": 0, "last_error": None, "last_sent": None}

    def configured(self) -> bool:
        raise NotImplementedError

    def send(self, title: str, text: str) -> None:
        raise NotImplementedError

    def allow(self, now: float) -> bool:
        """Per-channel rate limit: at most NOTIFY_MAX_PER_HOUR in any hour"""
        limit = settings.notify_max_per_hour
        while self.sent_times and now - self.sent_times[0] > 3600:
            self.sent_times.popleft()
        return limit <= 0 or len(self.sent_times) < limit


class SlackChannel(Channel):
    name = "slack"

    def configured(self) -> bool:
        return bool(settings.slack_webhook_url)

    def send(self, title: str, text: str) -> None:
        _post_json(settings.slack_webhook_url, {
            "text": f"{title}\n{text}",  # shown in notifications
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
                {"type": "section", "text": {"type": "mrkdwn", "text": text[:2900] or " "}},
            ],
        })


class TelegramChannel(Channel):
    name = "telegram"

    def configured(self) -> bool:
        return bool(settings.telegram_bot_token and settings.telegram_chat_id)

    def send(self, title: str, text: str) -> None:
        url = f"{settings.telegram_api_base.rstrip('/')}/bot{settings.telegram_bot_token}/sendMessage"
        _post_json(url, {"chat_id": settings.telegram_chat_id, "text": f"{title}\n\n{text}"[:4000],
                         "disable_web_page_preview": True})


class EmailChannel(Channel):
    name = "email"

    def configured(self) -> bool:
        return bool(settings.smtp_host and settings.email_to and settings.email_from)

    def send(self, title: str, text: str) -> None:
        message = EmailMessage()
        message["Subject"] = f"KGuard: {title}"
        message["From"] = settings.email_from
        message["To"] = ", ".join(settings.email_to)
        message.set_content(text)
        try:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
                if settings.smtp_starttls:
                    smtp.starttls(context=ssl.create_default_context())
                if settings.smtp_user:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(message)
        except smtplib.SMTPAuthenticationError as e:
            raise SendError(f"SMTP login refused ({e.smtp_code})", permanent=True)
        except (smtplib.SMTPException, OSError) as e:
            raise SendError(f"SMTP: {e}")


class Notifier:
    def __init__(self):
        self.channels: List[Channel] = [SlackChannel(), TelegramChannel(), EmailChannel()]
        self.queue: Optional[asyncio.Queue] = None
        self.task: Optional[asyncio.Task] = None
        self.sleep: Callable = asyncio.sleep
        self.dropped = 0

    # --- lifecycle --------------------------------------------------------

    def start(self) -> None:
        self.queue = asyncio.Queue(maxsize=QUEUE_LIMIT)
        self.task = asyncio.create_task(self._run(), name="notifier")
        active = [c.name for c in self.channels if c.configured()]
        if active:
            logger.info(f"Notifications on: {', '.join(active)} "
                        f"(alerts at or above {settings.notify_min_severity})")

    async def stop(self) -> None:
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
            self.task = None

    # --- intake -------------------------------------------------------------

    def wanted(self, alert: Dict[str, Any]) -> bool:
        return (SEVERITY_RANK.get(alert.get("severity"), 0)
                >= SEVERITY_RANK.get(settings.notify_min_severity.upper(), 3))

    def on_alert(self, alert: Dict[str, Any]) -> None:
        """Queue an alert for sending (called for every new alert; never blocks)"""
        if self.queue is None or not self.wanted(alert) or not any(c.configured() for c in self.channels):
            return
        try:
            self.queue.put_nowait(alert)
        except asyncio.QueueFull:
            self.dropped += 1

    async def _run(self) -> None:
        while True:
            alert = await self.queue.get()
            try:
                await self.deliver(alert)
            except Exception as e:
                logger.error(f"Notification failed: {e}")

    # --- delivery -----------------------------------------------------------

    async def deliver(self, alert: Dict[str, Any], test: bool = False) -> Dict[str, str]:
        """Send one alert to every configured channel; returns each channel's result"""
        content = summary(alert)
        results = {}
        loop = asyncio.get_running_loop()
        for channel in self.channels:
            if not channel.configured():
                continue
            now = time.time()
            if not test and not channel.allow(now):
                channel.held_back += 1
                channel.stats["held_back"] += 1
                results[channel.name] = "held back (rate limit)"
                continue
            text = content["text"]
            if channel.held_back:
                text += f"\n({channel.held_back} more alert(s) were held back by the rate limit)"
            results[channel.name] = await self._send(loop, channel, content["title"], text)
            if results[channel.name] == "sent":
                channel.held_back = 0
                if not test:
                    channel.sent_times.append(now)
        return results

    async def _send(self, loop, channel: Channel, title: str, text: str) -> str:
        delay = 1.0
        for attempt in range(1, RETRIES + 1):
            try:
                await loop.run_in_executor(None, channel.send, title, text)
                channel.stats["sent"] += 1
                channel.stats["last_sent"] = time.time()
                return "sent"
            except SendError as e:
                channel.stats["last_error"] = str(e)
                if e.permanent or attempt == RETRIES:
                    channel.stats["failed"] += 1
                    logger.error(f"{channel.name} notification failed: {e}")
                    return f"failed: {e}"
                await self.sleep(min(e.retry_after or delay, 60))
                delay *= 2
        return "failed"

    def get_stats(self) -> Dict[str, Any]:
        return {
            "min_severity": settings.notify_min_severity,
            "max_per_hour": settings.notify_max_per_hour,
            "queued": self.queue.qsize() if self.queue else 0,
            "dropped": self.dropped,
            "channels": {c.name: {"configured": c.configured(), **c.stats} for c in self.channels},
        }

    def reset(self) -> None:
        for c in self.channels:
            c.sent_times.clear()
            c.held_back = 0
            c.stats.update(sent=0, failed=0, held_back=0, last_error=None, last_sent=None)
        self.dropped = 0


notifier = Notifier()
