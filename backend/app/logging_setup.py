"""
Structured logging (roadmap S6.9).

Every log line is one JSON object:

    {"time": "2026-11-09T17:22:22.497Z", "level": "INFO", "logger": "kguard.access",
     "message": "GET /api/alerts/ 200", "request_id": "3f2a...", "method": "GET",
     "path": "/api/alerts/", "status": 200, "duration_ms": 4.1, "client": "127.0.0.1"}

Each HTTP request and WebSocket connection gets an ID (the client's
X-Request-ID if it sends a sensible one, else a new one). It is returned in
the X-Request-ID response header and added to every line logged while the
request is handled, so one request's lines can be pulled out of a busy log.

Uvicorn's own loggers, Python warnings and uncaught exceptions (main thread
and other threads) go through the same handler, so nothing is printed as
plain text. LOG_FORMAT=text gives the old readable format instead.

LOG_FILE also writes to a file, rotated at LOG_MAX_BYTES with LOG_BACKUP_COUNT
old files kept. Rotation is safe in one process only; the backend runs as one
process (python -m app). In Docker, log to stdout and let Docker rotate.
"""

import json
import logging
import logging.handlers
import re
import sys
import threading
import time
import traceback
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse

request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

_VALID_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Attributes every LogRecord has; anything else was passed with extra={...}
# (color_message is uvicorn's copy of the message with terminal colour codes)
_STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message", "asctime", "color_message"}

UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi")

access_logger = logging.getLogger("kguard.access")


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not getattr(record, "request_id", None):
            record.request_id = request_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": datetime.fromtimestamp(record.created, timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if getattr(record, "request_id", None):
            entry["request_id"] = record.request_id
        for key, value in vars(record).items():
            if key not in _STANDARD and key != "request_id" and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            entry["stack"] = self.formatStack(record.stack_info)
        return json.dumps(entry, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    def __init__(self):
        super().__init__("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        request_id = getattr(record, "request_id", None)
        return f"{line} [request_id={request_id}]" if request_id else line


def configure_logging(level: str = None, fmt: str = None, log_file: str = None,
                      max_bytes: int = None, backup_count: int = None) -> None:
    """Send all logging, uvicorn's included, through one formatter. Safe to call again."""
    from .config import settings

    level = (level or settings.log_level).upper()
    fmt = fmt or settings.log_format
    log_file = settings.log_file if log_file is None else log_file
    formatter = TextFormatter() if fmt == "text" else JsonFormatter()

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes or settings.log_max_bytes,
            backupCount=settings.log_backup_count if backup_count is None else backup_count,
            encoding="utf-8",
        ))
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(RequestIdFilter())
        handler._kguard = True

    # Replace handlers from basicConfig or an earlier call; leave others
    # (e.g. pytest's capture handlers) in place
    root = logging.getLogger()
    for old in root.handlers[:]:
        if getattr(old, "_kguard", False) or type(old) is logging.StreamHandler:
            root.removeHandler(old)
            if getattr(old, "_kguard", False):
                old.close()
    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(level)

    # Uvicorn configures its own handlers and formats; route it through ours.
    # The access log is replaced by RequestContextMiddleware's, which has the
    # request ID and timing.
    for name in UVICORN_LOGGERS:
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
        lg.setLevel(level)
    logging.getLogger("uvicorn.access").disabled = True

    logging.captureWarnings(True)
    sys.excepthook = _log_uncaught
    threading.excepthook = _log_thread_exception


def _log_uncaught(exc_type, exc, tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc, tb)
        return
    logging.getLogger("kguard").critical("Uncaught exception", exc_info=(exc_type, exc, tb))


def _log_thread_exception(args):
    if args.exc_type is SystemExit:
        return
    logging.getLogger("kguard").error(
        f"Uncaught exception in thread {args.thread.name if args.thread else '?'}",
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback))


def new_request_id(supplied: Optional[str]) -> str:
    if supplied and _VALID_ID.match(supplied):
        return supplied
    return uuid.uuid4().hex


class RequestContextMiddleware:
    """
    Pure ASGI middleware (so the ID is set for the whole request, WebSockets
    included): assigns the request ID, logs one access line per request and
    turns an unhandled exception into a logged 500 that still carries the ID.
    """

    def __init__(self, app, debug: bool = False):
        self.app = app
        self.debug = debug

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        supplied = headers.get(b"x-request-id", b"").decode("latin-1")
        request_id = new_request_id(supplied)
        token = request_id_var.set(request_id)
        start = time.perf_counter()
        status = {"code": None}
        client = scope.get("client")
        fields = {
            "method": scope.get("method", "WEBSOCKET"),
            "path": scope.get("path", ""),
            "client": client[0] if client else None,
        }

        async def send_with_id(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        try:
            if scope["type"] == "websocket":
                access_logger.info(f"WebSocket {fields['path']} opened", extra=fields)
                await self.app(scope, receive, send)
                return
            await self.app(scope, receive, send_with_id)
        except Exception as exc:
            logging.getLogger("kguard").error(f"Unhandled exception: {exc}", exc_info=True)
            if scope["type"] == "http" and status["code"] is None:
                detail = "".join(traceback.format_exception_only(type(exc), exc)).strip()
                response = JSONResponse(
                    status_code=500,
                    content={"error": "Internal server error",
                             "detail": detail if self.debug else "An unexpected error occurred",
                             "request_id": request_id})
                await response(scope, receive, send_with_id)
            else:
                raise
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            if scope["type"] == "http":
                code = status["code"] or 500
                access_logger.info(f"{fields['method']} {fields['path']} {code}",
                                   extra={**fields, "status": code, "duration_ms": duration_ms})
            else:
                access_logger.info(f"WebSocket {fields['path']} closed",
                                   extra={**fields, "duration_ms": duration_ms})
            request_id_var.reset(token)
