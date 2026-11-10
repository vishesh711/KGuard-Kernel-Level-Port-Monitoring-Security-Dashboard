"""Login, roles (S6.5) and hardening (S6.6)"""

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models.user import User
from app.security import SecurityMiddleware, TokenBuckets, login_throttle, security_problems
from app.services import auth

from .conftest import TEST_PASSWORD, token_for

BACKEND = Path(__file__).resolve().parent.parent

# Reachable without a dashboard login (and why)
PUBLIC = {
    ("POST", "/api/auth/login"),     # how you get a login
    ("GET", "/api/health/"),         # liveness probe for Docker
    ("GET", "/"),                    # name and version
    ("POST", "/api/agents/enroll"),  # enrollment key instead
    ("POST", "/api/agents/ingest"),  # agent token instead
    ("GET", "/api/agents/blocklist"),  # agent token instead
    ("POST", "/api/agents/sockets"),   # agent token instead
    ("GET", "/metrics"),             # METRICS_TOKEN instead (Prometheus)
}
# Changes a logged-in viewer may make (to their own account)
VIEWER_WRITES = {("POST", "/api/auth/password")}
# Reads only an admin may make
ADMIN_READS = {("GET", "/api/auth/users")}


def routes():
    """Every HTTP endpoint, from the OpenAPI schema (which lists included routers on every FastAPI version)"""
    for path, operations in app.openapi()["paths"].items():
        for method in operations:
            yield method.upper(), path


def test_no_endpoint_is_hidden_from_the_schema():
    from fastapi.routing import APIRouter

    from app.api import (
        agents_router,
        alerts_router,
        auth_router,
        events_router,
        health_router,
        payloads_router,
    )
    for router in (agents_router, alerts_router, auth_router, events_router, health_router, payloads_router):
        assert isinstance(router, APIRouter)
        assert all(r.include_in_schema for r in router.routes if isinstance(r, APIRoute))


def concrete(path):
    return path.replace("{alert_id}", "1").replace("{event_id}", "1").replace("{username}", "test-viewer")


def test_every_endpoint_is_listed():
    found = set(routes())
    assert len(found) >= 30
    assert PUBLIC <= found


@pytest.mark.parametrize("method,path", sorted(set(routes()) - PUBLIC))
def test_every_endpoint_needs_a_login(anon, method, path):
    response = anon.request(method, concrete(path), json={})
    assert response.status_code == 401, response.text
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_agent_endpoints_need_their_own_credentials(anon):
    assert anon.post("/api/agents/ingest", json={"events": []}).status_code == 401
    assert anon.post("/api/agents/enroll", json={"name": "x"}).status_code == 403


@pytest.mark.parametrize("method,path", sorted(
    (m, p) for m, p in set(routes()) - PUBLIC - VIEWER_WRITES if m in ("POST", "PUT", "PATCH", "DELETE")))
def test_viewers_cannot_change_anything(viewer, method, path):
    response = viewer.request(method, concrete(path), json={})
    assert response.status_code == 403, response.text


@pytest.mark.parametrize("path", sorted(p for m, p in set(routes()) - PUBLIC - ADMIN_READS
                                         if m == "GET" and "{" not in p))
def test_viewers_can_read_everything(viewer, path):
    assert viewer.get(path).status_code == 200, path


def test_viewers_cannot_list_users(viewer):
    for method, path in ADMIN_READS:
        assert viewer.request(method, path).status_code == 403


def test_bad_tokens_are_refused(anon):
    user = SessionLocal().query(User).filter(User.username == "test-admin").one()
    now = datetime.now(timezone.utc)
    claims = {"iss": "kguard", "sub": "test-admin", "role": "admin", "ver": 0, "iat": now,
              "exp": now + timedelta(hours=1)}
    bad = {
        "garbage": "not-a-jwt",
        "wrong key": jwt.encode(claims, "x" * 40, algorithm="HS256"),
        "alg none": jwt.encode(claims, None, algorithm="none"),
        "expired": auth.create_token(user, now=now - timedelta(days=2)),
        "unknown user": jwt.encode({**claims, "sub": "nobody"}, settings.secret_key, algorithm="HS256"),
        "old version": jwt.encode({**claims, "ver": 7}, settings.secret_key, algorithm="HS256"),
        "no expiry": jwt.encode({k: v for k, v in claims.items() if k != "exp"}, settings.secret_key,
                                algorithm="HS256"),
    }
    for name, token in bad.items():
        assert anon.get("/api/events/", headers={"Authorization": f"Bearer {token}"}).status_code == 401, name
    basic = {"Authorization": f"Basic {token_for('test-admin')}"}
    assert anon.get("/api/events/", headers=basic).status_code == 401


def test_login_gives_a_working_token(anon):
    response = anon.post("/api/auth/login", json={"username": "test-viewer", "password": TEST_PASSWORD})
    assert response.status_code == 200
    body = response.json()
    assert (body["role"], body["token_type"]) == ("viewer", "bearer")
    me = anon.get("/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}).json()
    assert (me["username"], me["role"]) == ("test-viewer", "viewer")
    assert me["last_login"] is not None


def test_wrong_logins_say_the_same_thing(anon):
    wrong_password = anon.post("/api/auth/login", json={"username": "test-admin", "password": "nope"})
    unknown_user = anon.post("/api/auth/login", json={"username": "ghost", "password": "nope"})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_password_change_ends_old_logins(anon):
    old = token_for("test-viewer")
    response = anon.post("/api/auth/password", headers=bearer(old),
                         json={"current_password": TEST_PASSWORD, "new_password": "a brand new pass"})
    assert response.status_code == 200
    assert anon.get("/api/auth/me", headers=bearer(old)).status_code == 401
    assert anon.get("/api/auth/me", headers=bearer(response.json()["access_token"])).status_code == 200
    assert anon.post("/api/auth/login", json={"username": "test-viewer",
                                              "password": "a brand new pass"}).status_code == 200


def test_admin_manages_users(client, anon):
    created = client.post("/api/auth/users", json={"username": "carol", "password": "carols password",
                                                   "role": "viewer"})
    assert created.status_code == 201
    assert client.post("/api/auth/users", json={"username": "carol", "password": "x" * 12}).status_code == 409
    assert client.post("/api/auth/users", json={"username": "dave", "password": "short"}).status_code == 422
    assert client.post("/api/auth/users", json={"username": "dave", "password": "long enough!",
                                                "role": "root"}).status_code == 422
    assert {u["username"] for u in client.get("/api/auth/users").json()} >= {"carol", "test-admin"}
    assert "password_hash" not in json.dumps(client.get("/api/auth/users").json())

    token = anon.post("/api/auth/login", json={"username": "carol", "password": "carols password"}).json()
    assert client.patch("/api/auth/users/carol", json={"role": "admin"}).json()["role"] == "admin"
    # The role change ended carol's login
    assert anon.get("/api/auth/me", headers=bearer(token["access_token"])).status_code == 401

    assert client.patch("/api/auth/users/carol", json={"is_active": False}).status_code == 200
    disabled = anon.post("/api/auth/login", json={"username": "carol", "password": "carols password"})
    assert disabled.status_code == 401
    assert client.delete("/api/auth/users/carol").status_code == 200
    assert client.delete("/api/auth/users/carol").status_code == 404


def test_last_admin_cannot_be_removed(client):
    assert client.patch("/api/auth/users/test-admin", json={"role": "viewer"}).status_code == 409
    assert client.patch("/api/auth/users/test-admin", json={"is_active": False}).status_code == 409
    assert client.delete("/api/auth/users/test-admin").status_code == 409


def test_websocket_needs_a_token(anon):
    for url in ("/ws", "/ws?token=garbage"):
        with pytest.raises(WebSocketDisconnect) as refused:
            with anon.websocket_connect(url) as ws:
                ws.receive_text()
        assert refused.value.code == 1008
    with anon.websocket_connect(f"/ws?token={token_for('test-viewer')}") as ws:
        ws.send_text(json.dumps({"type": "ping"}))
        assert json.loads(ws.receive_text())


def test_first_admin_from_settings(monkeypatch):
    db = SessionLocal()
    db.query(User).delete()
    db.commit()
    monkeypatch.setattr(settings, "admin_password", "short")
    auth.ensure_bootstrap_admin()
    assert db.query(User).count() == 0
    monkeypatch.setattr(settings, "admin_username", "root-admin")
    monkeypatch.setattr(settings, "admin_password", "a long first password")
    auth.ensure_bootstrap_admin()
    user = db.query(User).one()
    assert (user.username, user.role) == ("root-admin", "admin")
    assert auth.verify_password("a long first password", user.password_hash)
    # Ignored once users exist
    monkeypatch.setattr(settings, "admin_username", "second")
    auth.ensure_bootstrap_admin()
    assert db.query(User).count() == 1
    db.close()


def test_password_hashing():
    stored = auth.hash_password("hunter2hunter2")
    assert stored.startswith("scrypt$") and "hunter2" not in stored
    assert auth.verify_password("hunter2hunter2", stored)
    assert not auth.verify_password("hunter2hunter3", stored)
    assert auth.hash_password("hunter2hunter2") != stored  # salted
    for broken in ("", "plain", "md5$x$y$z$a$b", "scrypt$1$2$3$!!$!!"):
        assert not auth.verify_password("x", broken)


def test_users_cli(tmp_path):
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{tmp_path}/cli.db"}

    def run(*args, stdin=""):
        return subprocess.run([sys.executable, "-m", "app.users", *args], cwd=BACKEND, env=env,
                              input=stdin, capture_output=True, text=True)

    created = run("create", "eve", "--role", "admin", "--password-stdin", stdin="eves password\n")
    assert created.returncode == 0
    assert run("create", "eve", "--password-stdin", stdin="eves password\n").returncode != 0
    assert run("create", "zed", "--password-stdin", stdin="short\n").returncode != 0
    assert run("set-role", "eve", "viewer").returncode == 0
    assert run("disable", "eve").returncode == 0
    listing = run("list").stdout
    assert "eve" in listing and "viewer" in listing and "disabled" in listing and "zed" not in listing


# --- S6.6 hardening ---------------------------------------------------------

def test_secret_key_rules():
    assert auth.secret_key_problem("") == "SECRET_KEY is not set"
    assert "at least 32" in auth.secret_key_problem("short")
    for example in ("change-this-in-production-very-secret-key", "your-secret-key-change-this-in-production",
                    "dev-secret-key-change-in-production-0000000"):
        assert auth.secret_key_problem(example)
    assert auth.secret_key_problem("3f9c1e7a5b2d4c6e8f0a1b3c5d7e9f1a3b5c7d9e") is None


def test_unsafe_settings_are_reported(monkeypatch):
    assert security_problems() == []
    monkeypatch.setattr(settings, "allowed_origins", ["*"])
    monkeypatch.setattr(settings, "allowed_hosts", ["*"])
    monkeypatch.setattr(settings, "secret_key", "")
    assert len(security_problems()) == 3


@pytest.mark.parametrize("extra", [
    {"SECRET_KEY": ""},
    {"SECRET_KEY": "change-this-in-production-very-secret-key"},
    {"ALLOWED_ORIGINS": '["*"]'},
])
def test_refuses_to_start_unsafely(tmp_path, extra):
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{tmp_path}/x.db", "API_PORT": "0", "DEBUG": "false",
           **extra}
    if not extra.get("SECRET_KEY", "x"):
        env.pop("SECRET_KEY")
    proc = subprocess.run([sys.executable, "-m", "app"], cwd=BACKEND, env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0
    lines = [json.loads(line) for line in proc.stdout.splitlines()]
    assert any(e["level"] == "CRITICAL" and e["message"].startswith("Refusing to start") for e in lines)
    assert not any("Uvicorn running" in e["message"] for e in lines)


def limited_app(per_minute):
    small = FastAPI()

    @small.get("/api/thing")
    def thing():
        return {}

    @small.get("/api/health/")
    def health():
        return {}

    small.add_middleware(SecurityMiddleware)
    return small, per_minute


def test_rate_limit(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_minute", 5)
    small, _ = limited_app(5)
    c = TestClient(small)
    codes = [c.get("/api/thing").status_code for _ in range(7)]
    assert codes == [200] * 5 + [429] * 2
    limited = c.get("/api/thing")
    assert int(limited.headers["Retry-After"]) >= 1
    assert c.get("/api/health/").status_code == 200  # probes are exempt


def test_token_bucket_refills():
    buckets = TokenBuckets(60)  # one a second
    assert all(buckets.take("a", now=100.0) == 0 for _ in range(60))
    assert buckets.take("a", now=100.0) > 0
    assert buckets.take("b", now=100.0) == 0  # per client
    assert buckets.take("a", now=101.5) == 0
    assert TokenBuckets(0).take("a") == 0  # 0 = off


def test_failed_logins_are_throttled(anon, monkeypatch):
    monkeypatch.setattr(settings, "login_attempts_per_minute", 3)
    login_throttle.reset()
    try:
        for _ in range(3):
            wrong = anon.post("/api/auth/login", json={"username": "test-admin", "password": "x"})
            assert wrong.status_code == 401
        blocked = anon.post("/api/auth/login", json={"username": "test-admin", "password": TEST_PASSWORD})
        assert blocked.status_code == 429  # even the right password, until the minute is up
        assert int(blocked.headers["Retry-After"]) >= 1
    finally:
        login_throttle.reset()


def test_login_throttle_by_username_and_address():
    throttle = type(login_throttle)()
    settings_limit = settings.login_attempts_per_minute
    settings.login_attempts_per_minute = 2
    try:
        throttle.failed("1.1.1.1", "alice", now=0)
        throttle.failed("2.2.2.2", "Alice", now=1)
        assert throttle.retry_after("3.3.3.3", "alice", now=2) > 0  # same user, any address
        assert throttle.retry_after("3.3.3.3", "bob", now=2) == 0
        throttle.failed("4.4.4.4", "u1", now=2)
        throttle.failed("4.4.4.4", "u2", now=2)
        assert throttle.retry_after("4.4.4.4", "u3", now=3) > 0  # same address, any user
        assert throttle.retry_after("4.4.4.4", "u3", now=63) == 0  # a minute later
    finally:
        settings.login_attempts_per_minute = settings_limit


def test_security_headers(anon):
    response = anon.get("/api/health/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"


def test_cors_allows_only_listed_origins(anon):
    def preflight(origin):
        return anon.options("/api/events/", headers={"Origin": origin, "Access-Control-Request-Method": "GET",
                                                     "Access-Control-Request-Headers": "authorization"})
    good = preflight("http://localhost:5173")
    assert good.status_code == 200
    assert good.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in good.headers
    bad = preflight("https://evil.example")
    assert bad.status_code == 400
    assert "access-control-allow-origin" not in bad.headers
    assert "access-control-allow-origin" not in anon.get(
        "/api/health/", headers={"Origin": "https://evil.example"}).headers


def test_unknown_host_names_are_refused(anon):
    assert anon.get("/api/health/", headers={"Host": "evil.example"}).status_code == 400
    assert anon.get("/api/health/", headers={"Host": "localhost"}).status_code == 200
