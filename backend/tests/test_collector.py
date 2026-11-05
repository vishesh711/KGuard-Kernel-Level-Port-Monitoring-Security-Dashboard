"""Data collector: reading the kernel interface and storing events (F0.3)"""

from app.models.network_event import NetworkEvent

from .conftest import TCP_ACK, make_event


def test_collects_events_from_fake_kernel(fake_kernel, collect, db):
    events = [make_event(src_port=40000 + i, dst_port=443, flags=TCP_ACK) for i in range(50)]
    fake_kernel.write(events)

    assert collect() == 50
    assert db.query(NetworkEvent).count() == 50

    stored = db.query(NetworkEvent).order_by(NetworkEvent.id).first()
    assert stored.src_ip == "10.0.0.5"
    assert stored.dst_port == 443
    assert stored.protocol == "TCP"
    assert stored.flags == TCP_ACK
    assert stored.is_suspicious is False


def test_empty_kernel_buffer(fake_kernel, collect, db):
    fake_kernel.write([])
    assert collect() == 0
    assert db.query(NetworkEvent).count() == 0


def test_missing_kernel_interface(fake_kernel, collect):
    fake_kernel.remove()
    assert collect() == 0


def test_invalid_events_are_skipped(fake_kernel, collect, db):
    fake_kernel.write_raw(
        '{"dropped": 0, "events": ['
        '{"timestamp": 1, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 1, '
        '"dst_port": 2, "protocol": "UDP", "flags": 0},'
        '{"timestamp": 1, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 99999, '
        '"dst_port": 2, "protocol": "UDP", "flags": 0},'
        '{"src_ip": "1.1.1.1"}'
        "]}"
    )
    assert collect() == 1
    assert db.query(NetworkEvent).count() == 1


def test_malformed_json_is_ignored(fake_kernel, collect, db):
    fake_kernel.write_raw('{"dropped": 0, "events": [')
    assert collect() == 0
    assert db.query(NetworkEvent).count() == 0


def test_records_kernel_drop_counter(fake_kernel, collect, client):
    from app.services.data_collector import data_collector

    fake_kernel.write([make_event(flags=TCP_ACK)], dropped=1234)
    collect()
    assert data_collector.stats["kernel_events_dropped"] == 1234

    status = client.get("/api/health/kernel").json()
    assert status["details"]["kernel_events_dropped"] == 1234


def test_collects_kernel_output_with_all_protocols(fake_kernel, collect, db):
    fake_kernel.write([
        make_event(protocol="TCP", flags=TCP_ACK),
        make_event(protocol="UDP", flags=0, dst_port=53),
        make_event(protocol="ICMP", flags=0, src_port=0, dst_port=0),
        make_event(protocol="OTHER", flags=0, src_port=0, dst_port=0),
    ])
    assert collect() == 4
    protocols = sorted(p for (p,) in db.query(NetworkEvent.protocol).all())
    assert protocols == ["ICMP", "OTHER", "TCP", "UDP"]
