"""Response engine (S6.4): blocks, allowlist, expiry, audit, automatic rules, enforcement"""

import errno
from datetime import datetime, timedelta

import pytest

from app.config import settings
from app.models.response import AuditEntry, Block
from app.services.local_enforcer import LocalEnforcer
from app.services.response import response_engine

from .conftest import make_event
from .test_agents import enroll


def block(client, cidr, **extra):
    return client.post("/api/response/blocks", json={"cidr": cidr, "reason": "test", **extra})


def actions(db):
    return [(e.actor, e.action, e.target) for e in db.query(AuditEntry).order_by(AuditEntry.id)]


@pytest.fixture
def agent(client, monkeypatch):
    monkeypatch.setattr(settings, "agent_enrollment_key", "s3cret")
    token = enroll(client, "web-1").json()["token"]
    return {"Authorization": f"Bearer {token}"}


def blocklist(client, headers, **params):
    response = client.get("/api/agents/blocklist", headers=headers, params=params)
    assert response.status_code == 200
    lines = response.text.splitlines()
    assert lines[0].startswith("version ") and lines[1].startswith("lease ")
    return lines[0].split()[1], [line.split()[1:] for line in lines[2:]]


def test_block_and_unblock_through_the_api(client, agent, db):
    created = block(client, "198.51.100.7", minutes=30)
    assert created.status_code == 201
    item = created.json()
    assert (item["cidr"], item["active"], item["created_by"]) == ("198.51.100.7/32", True, "test-admin")
    assert 29 * 60 < item["seconds_left"] <= 30 * 60

    version, entries = blocklist(client, agent)
    assert [e[0] for e in entries] == ["198.51.100.7/32"]
    assert int(entries[0][1]) > 0  # expiry in Unix seconds
    assert [b["cidr"] for b in client.get("/api/response/blocks").json()] == ["198.51.100.7/32"]

    assert client.delete(f"/api/response/blocks/{item['id']}").status_code == 200
    assert client.delete(f"/api/response/blocks/{item['id']}").status_code == 409
    new_version, entries = blocklist(client, agent)
    assert entries == [] and new_version != version
    assert client.get("/api/response/blocks").json() == []
    history = client.get("/api/response/blocks", params={"include_removed": True}).json()
    assert history[0]["removed_by"] == "test-admin" and history[0]["active"] is False
    assert actions(db) == [("test-admin", "block", "198.51.100.7/32"),
                           ("test-admin", "unblock", "198.51.100.7/32")]


@pytest.mark.parametrize("cidr,why", [
    ("127.0.0.1", "loopback"),
    ("::1", "loopback"),
    ("fe80::1", "link-local"),
    ("224.0.0.5", "multicast"),
    ("0.0.0.0", "unspecified"),
    ("10.0.0.0/8", "wider than /16"),
    ("2001:db8::/16", "wider than /32"),
    ("::ffff:198.51.100.7", "IPv4-mapped"),
    ("not-an-ip", "Not an IP"),
])
def test_unsafe_blocks_are_refused(client, cidr, why):
    response = block(client, cidr)
    assert response.status_code == 422
    assert why in response.json()["detail"]


def test_allowlist_protects_and_unblocks(client, db):
    block(client, "198.51.100.0/24")
    added = client.post("/api/response/allowlist", json={"cidr": "198.51.100.10", "note": "office"})
    assert added.status_code == 201
    assert client.get("/api/response/blocks").json() == []  # the /24 covered it
    assert "allowlist" in block(client, "198.51.100.10").json()["detail"]
    assert "allowlist" in block(client, "198.51.100.0/25").json()["detail"]
    assert block(client, "198.51.100.200").status_code == 201  # outside the /32
    assert client.post("/api/response/allowlist", json={"cidr": "198.51.100.10"}).status_code == 422
    entry = client.get("/api/response/allowlist").json()[0]
    assert client.delete(f"/api/response/allowlist/{entry['id']}").status_code == 200
    assert block(client, "198.51.100.10").status_code == 201
    assert [a[1] for a in actions(db)] == ["block", "allow", "unblock_allowlisted", "block",
                                           "allow_remove", "block"]


def test_enrolled_agents_cannot_be_cut_off(client, agent):
    # The test client's address is "testclient", not an IP; give the agent a real one
    from app.database import SessionLocal
    from app.models.agent import Agent
    db = SessionLocal()
    db.query(Agent).update({"remote_addr": "198.51.100.50"})
    db.commit()
    db.close()
    assert "enrolled agent" in block(client, "198.51.100.0/24").json()["detail"]


def test_blocks_can_be_for_one_host(client, agent, monkeypatch):
    other = {"Authorization": f"Bearer {enroll(client, 'web-2').json()['token']}"}
    agents = {a["name"]: a["id"] for a in client.get("/api/agents/").json()}
    assert block(client, "198.51.100.1", host_id=agents["web-1"]).status_code == 201
    assert block(client, "198.51.100.2").status_code == 201
    assert block(client, "198.51.100.3", host_id=999).status_code == 404
    assert [e[0] for e in blocklist(client, agent)[1]] == ["198.51.100.1/32", "198.51.100.2/32"]
    assert [e[0] for e in blocklist(client, other)[1]] == ["198.51.100.2/32"]


def test_blocking_again_extends_but_never_shortens(client, db):
    first = block(client, "198.51.100.7", minutes=10).json()
    longer = block(client, "198.51.100.7", minutes=60).json()
    assert longer["id"] == first["id"] and longer["created"] is False
    assert longer["seconds_left"] > 50 * 60
    shorter = block(client, "198.51.100.7", minutes=5).json()
    assert shorter["seconds_left"] > 50 * 60
    assert block(client, "198.51.100.7").json()["expires_at"] is None  # until unblocked
    assert [a[1] for a in actions(db)] == ["block", "extend", "extend"]


def test_blocks_expire(client, agent, db):
    item = block(client, "198.51.100.7", minutes=1).json()
    later = datetime.utcnow() + timedelta(minutes=2)
    # Already out of the active list (and the agents'), before the job runs
    assert response_engine.active(db, now=later) == []
    assert response_engine.expire(now=later) == 1
    db.expire_all()
    row = db.get(Block, item["id"])
    assert row.removed_by == "expiry"
    assert actions(db)[-1] == ("expiry", "expire", "198.51.100.7/32")
    assert response_engine.expire(now=later) == 0


def test_agent_reports_what_it_applied(client, agent):
    block(client, "198.51.100.7")
    version, _ = blocklist(client, agent)
    status = client.get("/api/response/status").json()
    assert status["agents"][0]["in_sync"] is False  # not applied yet
    blocklist(client, agent, applied=version, failed=0, enforcing=1)
    status = client.get("/api/response/status").json()
    assert status["agents"][0] | {"synced_at": None} == {
        "id": status["agents"][0]["id"], "name": "web-1", "engine": None, "in_sync": True, "applied": version,
        "current": version, "failed": 0, "enforcing": True, "synced_at": None}
    blocklist(client, agent, applied=version, failed=2, enforcing=0)
    status = client.get("/api/response/status").json()
    assert status["agents"][0]["in_sync"] is False and status["agents"][0]["enforcing"] is False
    bad = client.get("/api/agents/blocklist", params={"applied": "not hex"}, headers=agent)
    assert bad.status_code == 422


def test_blocklist_needs_an_agent_token(anon, client):
    assert anon.get("/api/agents/blocklist").status_code == 401
    # A dashboard login is not an agent token
    assert client.get("/api/agents/blocklist").status_code == 401


# --- automatic rules ---------------------------------------------------------

def scan(fake_kernel, collect, src="198.51.100.9", ports=40):
    fake_kernel.write([make_event(src_ip=src, dst_port=1000 + p) for p in range(ports)])
    collect()


@pytest.fixture
def auto(monkeypatch):
    monkeypatch.setattr(settings, "auto_block", True)
    monkeypatch.setattr(settings, "auto_block_min_severity", "MEDIUM")


def test_no_automatic_blocks_unless_turned_on(fake_kernel, collect, db):
    scan(fake_kernel, collect)
    assert db.query(Block).count() == 0


def test_scan_source_is_blocked_automatically(fake_kernel, collect, db, auto, client):
    scan(fake_kernel, collect)
    row = db.query(Block).one()
    assert (row.cidr, row.source, row.created_by) == ("198.51.100.9/32", "auto", "auto-response")
    assert row.alert_id is not None and "PORT_SCAN" in row.reason
    minutes = (row.expires_at - row.created_at).total_seconds() / 60
    assert 59 <= minutes <= 61
    assert actions(db)[0][:2] == ("auto-response", "block")


def test_repeat_offenders_get_longer_blocks(db, auto):
    alert = {"id": 1, "alert_type": "PORT_SCAN", "severity": "HIGH", "src_ip": "198.51.100.9"}
    first = response_engine.on_alert(alert)
    response_engine.unblock(db, db.get(Block, first.id), "test")
    second = response_engine.on_alert(alert)
    db.expire_all()
    row = db.get(Block, second.id)
    assert (row.expires_at - row.created_at) >= timedelta(minutes=119)


def test_automatic_rules_respect_type_severity_and_allowlist(db, auto, client, monkeypatch):
    base = {"id": 1, "src_ip": "198.51.100.9"}
    assert response_engine.on_alert({**base, "alert_type": "SYN_FLOOD", "severity": "CRITICAL"}) is None
    monkeypatch.setattr(settings, "auto_block_min_severity", "HIGH")
    assert response_engine.on_alert({**base, "alert_type": "PORT_SCAN", "severity": "MEDIUM"}) is None
    client.post("/api/response/allowlist", json={"cidr": "198.51.100.0/24"})
    assert response_engine.on_alert({**base, "alert_type": "PORT_SCAN", "severity": "HIGH"}) is None
    assert actions(db)[-1][:2] == ("auto-response", "auto_refused")
    assert db.query(Block).count() == 0


def test_listed_sources_can_be_blocked(db, monkeypatch):
    monkeypatch.setattr(settings, "auto_block", True)
    monkeypatch.setattr(settings, "auto_block_listed_sources", True)
    alert = {"id": 1, "alert_type": "SUSPICIOUS_PORT", "severity": "LOW", "src_ip": "198.51.100.9",
             "metadata": {"enrichment": {"src": {"threat_lists": ["firehol_level1"]}}}}
    assert "threat list" in response_engine.on_alert(alert).reason


# --- this machine's kernel, over Netlink -----------------------------------

class FakeKernel:
    def __init__(self, enforce=True, refuse=()):
        self.blocks, self.calls, self.enforce, self.refuse = {}, [], enforce, set(refuse)

    def block_add(self, addr, timeout):
        self.calls.append(("add", addr, timeout))
        if addr in self.refuse:
            raise OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")
        self.blocks[addr] = timeout

    def block_del(self, addr):
        self.calls.append(("del", addr))
        if addr not in self.blocks:
            raise OSError(errno.ENOENT, "No such file or directory")
        del self.blocks[addr]

    def enforcing(self):
        return self.enforce

    def close(self):
        pass


@pytest.fixture
def local(monkeypatch):
    monkeypatch.setattr(settings, "local_enforcement", "auto")
    kernel = FakeKernel()
    return kernel, LocalEnforcer(lambda: kernel)


def test_local_enforcer_applies_leases(client, local):
    kernel, enforcer = local
    block(client, "198.51.100.7")
    block(client, "198.51.100.8", minutes=2)
    block(client, "198.51.100.0/28")  # a prefix: the module blocks single addresses
    assert enforcer.sync(now=1000.0) == "enforcing"
    assert kernel.blocks == {"198.51.100.7": settings.block_lease_seconds, "198.51.100.8": pytest.approx(
        kernel.blocks["198.51.100.8"])}
    assert kernel.blocks["198.51.100.8"] <= settings.block_lease_seconds
    assert enforcer.stats["skipped_prefixes"] == 1

    calls = len(kernel.calls)
    enforcer.sync(now=1001.0)
    assert len(kernel.calls) == calls  # nothing to do yet
    enforcer.sync(now=1000.0 + settings.block_lease_seconds)
    assert ("add", "198.51.100.7", settings.block_lease_seconds) in kernel.calls[calls:]  # renewed


def test_local_enforcer_removes_unblocked_addresses(client, local):
    kernel, enforcer = local
    item = block(client, "198.51.100.7").json()
    enforcer.sync()
    client.delete(f"/api/response/blocks/{item['id']}")
    enforcer.sync()
    assert kernel.blocks == {} and ("del", "198.51.100.7") in kernel.calls


def test_local_enforcer_status(client, local, monkeypatch):
    kernel, enforcer = local
    kernel.enforce = False
    block(client, "198.51.100.7")
    assert enforcer.sync() == "monitor only"
    kernel.refuse.add("198.51.100.9")
    block(client, "198.51.100.9")
    enforcer.sync()
    assert enforcer.stats["failed"] == 1

    def no_permission(addr, timeout):
        raise PermissionError(errno.EPERM, "Operation not permitted")
    enforcer.managed.clear()
    monkeypatch.setattr(kernel, "block_add", no_permission)
    assert enforcer.sync() == "not permitted"

    def no_module():
        raise OSError(errno.ENOENT, "no family")
    assert LocalEnforcer(no_module).sync() == "no module"
    monkeypatch.setattr(settings, "local_enforcement", "off")
    assert enforcer.sync() == "off"
