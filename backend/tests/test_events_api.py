"""Events API and grouped statistics queries (B1.6)"""

from datetime import datetime, timedelta

from sqlalchemy import event as sa_event

from app.database import engine
from app.models.network_event import NetworkEvent


def add_events(db, count, created_at=None, **fields):
    defaults = dict(timestamp=1, src_ip="10.0.0.5", dst_ip="10.0.0.1", src_port=40000,
                    dst_port=80, protocol="TCP", flags=0x10)
    defaults.update(fields)
    for i in range(count):
        row = NetworkEvent(**{**defaults, "src_port": defaults["src_port"] + i})
        if created_at is not None:
            row.created_at = created_at
        db.add(row)
    db.commit()


class QueryCounter:
    def __init__(self):
        self.count = 0

    def __call__(self, *args, **kwargs):
        self.count += 1

    def __enter__(self):
        sa_event.listen(engine, "before_cursor_execute", self)
        return self

    def __exit__(self, *exc):
        sa_event.remove(engine, "before_cursor_execute", self)


def test_list_and_filter_events(client, db):
    add_events(db, 30)
    add_events(db, 5, protocol="UDP", dst_port=53)

    page = client.get("/api/events/", params={"size": 10, "page": 2}).json()
    assert page["total"] == 35
    assert page["pages"] == 4
    assert len(page["items"]) == 10

    udp = client.get("/api/events/", params={"protocol": "UDP"}).json()
    assert udp["total"] == 5
    assert all(e["dst_port"] == 53 for e in udp["items"])


def test_event_stats_summary(client, db):
    now = datetime.utcnow()
    add_events(db, 4)
    add_events(db, 3, created_at=now - timedelta(hours=3), protocol="UDP", src_ip="10.0.0.9")

    stats = client.get("/api/events/stats/summary").json()
    assert stats["total_events"] == 7
    assert stats["unique_src_ips"] == 2
    assert stats["protocol_distribution"] == {"TCP": 4, "UDP": 3}
    assert len(stats["events_per_hour"]) == 24
    assert sum(h["count"] for h in stats["events_per_hour"]) == 7
    assert stats["events_per_hour"][-1]["count"] == 4


def test_traffic_summary(client, db):
    now = datetime.utcnow()
    add_events(db, 4)
    add_events(db, 2, protocol="UDP", dst_port=53)
    add_events(db, 1, protocol="ICMP", src_port=0, dst_port=0)
    add_events(db, 5, created_at=now - timedelta(hours=6), is_suspicious=True)

    summaries = client.get("/api/events/stats/traffic", params={"hours": 24, "interval": 4}).json()
    assert len(summaries) == 6
    assert sum(s["total_packets"] for s in summaries) == 12

    latest = summaries[-1]
    assert latest["total_packets"] == 7
    assert latest["tcp_packets"] == 4
    assert latest["udp_packets"] == 2
    assert latest["icmp_packets"] == 1
    assert latest["unique_connections"] == 7
    assert sum(s["suspicious_activity"] for s in summaries) == 5

    times = [s["timestamp"] for s in summaries]
    assert times == sorted(times)


def test_stats_use_a_fixed_number_of_queries(client, db):
    add_events(db, 3)
    with QueryCounter() as small:
        client.get("/api/events/stats/summary", params={"hours": 24})
    with QueryCounter() as large:
        client.get("/api/events/stats/summary", params={"hours": 168})
    assert large.count == small.count

    with QueryCounter() as traffic:
        client.get("/api/events/stats/traffic", params={"hours": 168, "interval": 1})
    assert traffic.count <= 3


def test_cleanup_old_events(client, db):
    add_events(db, 2, created_at=datetime.utcnow() - timedelta(days=40))
    add_events(db, 3)
    result = client.delete("/api/events/cleanup", params={"days": 30}).json()
    assert result["deleted_count"] == 2
    assert client.get("/api/events/").json()["total"] == 3
