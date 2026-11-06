"""Phase 5 header-based detection: OS fingerprints, spoofing, amplification"""

import time

import pytest

from app.models.network_event import NetworkEvent
from app.models.security_alert import AlertType, SecurityAlert
from app.services.anomaly_detector import anomaly_detector
from app.services.fingerprint import fingerprint_syn, initial_ttl
from app.services.kernel_alerts import alert_from_kernel, kernel_alerts
from app.services.kguard_device import build_fake_device
from app.services.kguard_netlink import decode_alert, encode_alert, genl_split, iter_messages
from app.services.spoofing import bogon_category

from .test_device import v2_event

SYN, ACK = 0x02, 0x10

# SYN headers as each stack sends them (initial TTL, window, MSS, wscale, options)
STACKS = {
    "Linux": dict(ttl=64, tcp_window=64240, tcp_mss=1460, tcp_wscale=7, tcp_options="M,S,T,N,W"),
    "Windows": dict(ttl=128, tcp_window=64240, tcp_mss=1460, tcp_wscale=8, tcp_options="M,N,W,N,N,S"),
    "macOS": dict(ttl=64, tcp_window=65535, tcp_mss=1460, tcp_wscale=6, tcp_options="M,N,W,N,N,T,S,E"),
    "nmap": dict(ttl=47, tcp_window=1024, tcp_mss=1460, tcp_wscale=-1, tcp_options="M"),
    "masscan": dict(ttl=255, tcp_window=1024, tcp_mss=0, tcp_wscale=-1, tcp_options=""),
    "crafted": dict(ttl=64, tcp_window=512, tcp_mss=0, tcp_wscale=-1, tcp_options=""),
}


def alerts(db, alert_type=None):
    query = db.query(SecurityAlert).order_by(SecurityAlert.id)
    if alert_type:
        query = query.filter(SecurityAlert.alert_type == alert_type)
    return query.all()


def syn(stack, hops=0, **fields):
    headers = dict(STACKS[stack])
    headers["ttl"] -= hops
    return v2_event(flags=SYN, ct_state="new", direction="in", **{**headers, **fields})


# ---- fingerprints ----

def test_initial_ttl_and_hops():
    observed = (30, 33, 64, 65, 117, 128, 200, 255)
    assert [initial_ttl(t) for t in observed] == [32, 64, 64, 128, 128, 128, 255, 255]
    fp = fingerprint_syn(52, 64240, 1460, 7, "M,S,T,N,W", True)
    assert (fp.name, fp.initial_ttl, fp.hops, fp.exact) == ("Linux", 64, 12, True)
    assert fp.signature == "64:64240:1460:7:M,S,T,N,W:df"


@pytest.mark.parametrize("stack", STACKS)
def test_each_stack_is_recognised(stack):
    h = STACKS[stack]
    wscale = h["tcp_wscale"] if h["tcp_wscale"] >= 0 else None
    fp = fingerprint_syn(h["ttl"] - 6, h["tcp_window"], h["tcp_mss"] or None, wscale, h["tcp_options"])
    assert fp.name == stack
    assert fp.is_tool == (stack in ("nmap", "masscan", "crafted"))


def test_right_options_wrong_ttl_is_an_inexact_match():
    fp = fingerprint_syn(120, 64240, 1460, 7, "M,S,T,N,W")  # Linux options, Windows TTL
    assert (fp.name, fp.exact) == ("Linux", False)
    assert fingerprint_syn(64, 5840, 1400, 2, "M,T,S,N,W").name == "unknown"


def test_collector_stores_headers_and_fingerprint(fake_device, collect, db):
    build_fake_device(fake_device, [[syn("Windows", hops=10, src_ip="10.9.0.1"),
                                     v2_event(src_ip="10.9.0.2", ttl=55, ip_len=1500, df=False)]])
    collect()
    windows, plain = db.query(NetworkEvent).order_by(NetworkEvent.src_ip).all()
    assert (windows.ttl, windows.tcp_window, windows.tcp_mss, windows.tcp_wscale) == (118, 64240, 1460, 8)
    assert (windows.tcp_options, windows.os_guess, windows.df) == ("M,N,W,N,N,S", "Windows", True)
    # Not a SYN: no options and no guess
    assert (plain.ttl, plain.ip_len, plain.df) == (55, 1500, False)
    assert (plain.os_guess, plain.tcp_options) == (None, None)
    assert windows.to_dict()["os_guess"] == "Windows"


def test_events_api_returns_the_fingerprint(client, fake_device, collect):
    build_fake_device(fake_device, [[syn("macOS", hops=3, src_ip="10.9.0.3")]])
    collect()
    (item,) = client.get("/api/events/?src_ip=10.9.0.3").json()["items"]
    assert (item["os_guess"], item["ttl"], item["tcp_options"]) == ("macOS", 61, "M,N,W,N,N,T,S,E")


def test_older_module_leaves_header_fields_empty(fake_device, collect, db):
    build_fake_device(fake_device, [[v2_event(ttl=0, ip_len=0, flags=SYN, tcp_window=0)]])
    collect()
    row = db.query(NetworkEvent).one()
    assert (row.ttl, row.ip_len, row.df, row.tcp_window, row.os_guess) == (None, None, None, None, None)


def test_scan_alert_names_the_scanning_tool(fake_device, collect, db):
    build_fake_device(fake_device, [[syn("nmap", src_ip="10.9.0.66", dst_port=p) for p in range(1000, 1030)]])
    collect()
    (scan,) = alerts(db, AlertType.PORT_SCAN)
    assert scan.alert_metadata["sender_fingerprint"] == "nmap"
    assert "nmap's TCP fingerprint" in scan.description


def test_kernel_scan_alert_also_names_the_tool(client, fake_device, collect, db):
    probes = [syn("masscan", src_ip="10.9.0.67", dst_port=p) for p in range(1000, 1030)]
    build_fake_device(fake_device, [probes])
    anomaly_detector.kernel_detection = True
    collect()
    alert = client.portal.call(kernel_alerts.handle, {
        "type": "scan", "action": "none", "src_ip": "10.9.0.67", "netns": 1,
        "ports": 30, "attempts": 30, "timestamp": time.time_ns()})
    assert alert.alert_metadata["sender_fingerprint"] == "masscan"


def test_kernel_scan_label_ignores_the_sources_older_traffic(client, fake_device, collect, db):
    now = time.time_ns()
    browsing = [syn("Linux", src_ip="10.9.0.68", src_port=40000 + i, timestamp=now - 10 * 10**9 + i)
                for i in range(40)]
    probes = [syn("nmap", src_ip="10.9.0.68", dst_port=p, timestamp=now + p) for p in range(1000, 1025)]
    build_fake_device(fake_device, [browsing + probes])
    anomaly_detector.kernel_detection = True
    collect()
    alert = client.portal.call(kernel_alerts.handle, {
        "type": "scan", "action": "none", "src_ip": "10.9.0.68", "netns": 1,
        "ports": 20, "attempts": 20, "timestamp": now + 1020})
    assert alert.alert_metadata["fingerprints"] == {"nmap": 25}
    assert alert.title == "SYN Scan Detected from 10.9.0.68"


# ---- spoofing ----

def test_ttl_jump_from_one_source_is_spoofing(fake_device, collect, db):
    real = [v2_event(src_ip="10.9.1.1", src_port=50000 + i, ttl=58, flags=ACK) for i in range(10)]
    # Sent by a real stack elsewhere (a spoofer's own Linux kernel), 18 hops further away
    forged = [syn("Linux", src_ip="10.9.1.1", src_port=51000 + i, ttl=40) for i in range(3)]
    build_fake_device(fake_device, [real + forged])
    collect()
    (alert,) = alerts(db, AlertType.SPOOFED_TRAFFIC)
    assert alert.src_ip == "10.9.1.1"
    meta = alert.alert_metadata
    assert (meta["usual_hops"], meta["odd_hops"], meta["odd_packets"]) == (6, [24], 3)
    assert len(alert.related_event_ids) == 3


def test_normal_ttl_jitter_and_nat_are_not_spoofing(fake_device, collect, db):
    jitter = [v2_event(src_ip="10.9.1.2", src_port=50000 + i, ttl=58 - i % 3) for i in range(30)]
    # Windows and Linux machines behind one NAT address
    nat = [v2_event(src_ip="10.9.1.3", src_port=50000 + i, ttl=118 if i % 2 else 52) for i in range(30)]
    build_fake_device(fake_device, [jitter + nat])
    collect()
    assert alerts(db, AlertType.SPOOFED_TRAFFIC) == []


def test_scanner_ttls_are_not_spoofing(fake_device, collect, db):
    # nmap picks its own TTL for crafted probes; the host's own stack uses 64
    real = [v2_event(src_ip="10.9.1.4", src_port=50000 + i, ttl=64, flags=ACK) for i in range(10)]
    probes = [syn("nmap", src_ip="10.9.1.4", dst_port=p) for p in range(1000, 1004)]
    build_fake_device(fake_device, [real + probes])
    collect()
    assert alerts(db, AlertType.SPOOFED_TRAFFIC) == []

    # A known scanner's crafted UDP probes (no fingerprint) are not reported twice
    anomaly_detector._start_cooldown("port_scan_10.9.1.5")
    real = [v2_event(src_ip="10.9.1.5", src_port=50000 + i, ttl=64, flags=ACK) for i in range(10)]
    udp = [v2_event(src_ip="10.9.1.5", dst_port=p, protocol="UDP", flags=0, ttl=44) for p in range(5)]
    build_fake_device(fake_device, [real + udp])
    collect()
    assert alerts(db, AlertType.SPOOFED_TRAFFIC) == []


def test_bogon_categories():
    assert bogon_category("192.0.2.7") == "documentation"
    assert bogon_category("198.18.3.4") == "benchmarking"
    assert bogon_category("240.1.2.3") == "reserved"
    assert bogon_category("2001:db8::1") == "documentation"
    assert bogon_category("::ffff:10.0.0.1") == "ipv4-mapped"
    assert bogon_category("10.0.0.1") is None  # private ranges are normal on a LAN
    assert bogon_category("169.254.1.1") is None
    assert bogon_category("8.8.8.8") is None


def test_bogon_source_is_spoofing(fake_device, collect, db):
    anomaly_detector.spoofing.check_bogons = True
    build_fake_device(fake_device, [[
        v2_event(src_ip="198.18.0.9", dst_port=80, flags=SYN, ct_state="new"),
        v2_event(src_ip="198.18.0.9", dst_port=81, flags=SYN, ct_state="new"),
        v2_event(src_ip="127.0.0.1", dst_ip="127.0.0.1", dst_port=8000),  # host talking to itself
    ]])
    collect()
    (alert,) = alerts(db, AlertType.SPOOFED_TRAFFIC)
    assert alert.src_ip == "198.18.0.9"
    assert alert.alert_metadata["bogon_category"] == "benchmarking"
    assert alert.alert_metadata["packets"] == 2


def test_random_bogon_sources_give_one_alert(fake_device, collect, db):
    anomaly_detector.spoofing.check_bogons = True
    flood = [v2_event(src_ip=f"24{i % 10}.{i // 250 % 250}.{i % 250}.1", flags=SYN, ct_state="new",
                      src_port=1024 + i) for i in range(2000)]
    build_fake_device(fake_device, [flood[:1000], flood[1000:]])
    collect()
    collect()
    (alert,) = alerts(db, AlertType.SPOOFED_TRAFFIC)
    assert alert.title == "Impossible Source Addresses (2000 reserved)"
    assert alert.src_ip is None
    assert alert.alert_metadata["distinct_sources"] == 2000


def test_kernel_reports_loopback_spoofing_for_this_server(fake_device, collect, db):
    anomaly_detector.spoofing.check_bogons = True
    anomaly_detector.kernel_detection = True
    build_fake_device(fake_device, [[v2_event(src_ip="127.0.0.5", dst_ip="10.0.0.1", flags=SYN)]])
    collect()
    assert alerts(db, AlertType.SPOOFED_TRAFFIC) == []  # left to the kernel's SPOOF alert
    anomaly_detector.kernel_detection = False
    anomaly_detector.reset()
    anomaly_detector.spoofing.check_bogons = True
    build_fake_device(fake_device, [[v2_event(src_ip="127.0.0.5", dst_ip="10.0.0.1", flags=SYN)]])
    collect()
    assert alerts(db, AlertType.SPOOFED_TRAFFIC)[0].alert_metadata["bogon_category"] == "loopback"


def test_kernel_spoof_alert():
    event = {"type": "spoof", "action": "dropped", "src_ip": "10.0.0.1", "netns": 1, "ports": 0,
             "attempts": 1, "timestamp": time.time_ns(), "spoof_reason": "local", "ifindex": 3}
    (msg,) = list(iter_messages(encode_alert(event)))
    assert decode_alert(genl_split(msg[1])[1]) == event

    alert = alert_from_kernel(event)
    assert alert.alert_type == AlertType.SPOOFED_TRAFFIC
    assert alert.title == "Spoofed Packets Claiming 10.0.0.1"
    assert "this host's own addresses" in alert.description
    assert "dropped" in alert.description
    assert (alert.alert_metadata["spoof_reason"], alert.alert_metadata["ifindex"]) == ("local", 3)


# ---- amplification ----

def dns_reply(i, **fields):
    base = dict(src_ip=f"8.8.{i % 4}.8", src_port=53, dst_ip="10.0.0.1", dst_port=40000 + i,
                protocol="UDP", flags=0, ct_state="new", direction="in", ip_len=1400)
    base.update(fields)
    return v2_event(**base)


def test_unsolicited_dns_replies_are_amplification(fake_device, collect, db):
    build_fake_device(fake_device, [[dns_reply(i) for i in range(60)]])
    collect()
    (alert,) = alerts(db, AlertType.AMPLIFICATION)
    assert alert.title == "DNS Amplification Attack Against 10.0.0.1"
    meta = alert.alert_metadata
    assert (meta["role"], meta["replies"], meta["reflectors"], meta["bytes"]) == ("victim", 60, 4, 84000)


def test_each_reflector_service_is_reported(fake_device, collect, db):
    build_fake_device(fake_device, [[dns_reply(i) for i in range(60)]
                                    + [dns_reply(i, src_port=123, ip_len=468) for i in range(60)]])
    collect()
    titles = sorted(a.title for a in alerts(db, AlertType.AMPLIFICATION))
    assert titles == [f"{service} Amplification Attack Against 10.0.0.1" for service in ("DNS", "NTP")]


def test_replies_we_asked_for_or_small_ones_are_not(fake_device, collect, db):
    build_fake_device(fake_device, [
        [dns_reply(i, ct_state="established") for i in range(60)]
        + [dns_reply(i, src_ip="8.8.4.4", ip_len=120) for i in range(60)]
    ])
    collect()
    assert alerts(db, AlertType.AMPLIFICATION) == []


def test_without_conntrack_our_own_queries_are_remembered(fake_device, collect, db):
    queries = [v2_event(src_ip="10.0.0.1", dst_ip="9.9.9.9", src_port=40000 + i, dst_port=53,
                        protocol="UDP", flags=0, ct_state="none", direction="out", ip_len=60)
               for i in range(60)]
    answers = [dns_reply(i, src_ip="9.9.9.9", ct_state="none") for i in range(60)]
    unasked = [dns_reply(i, src_ip="1.0.0.1", ct_state="none", src_port=123) for i in range(60)]
    build_fake_device(fake_device, [queries + answers + unasked])
    collect()
    (alert,) = alerts(db, AlertType.AMPLIFICATION)
    assert alert.alert_metadata["service"] == "NTP"
    assert alert.src_ip == "1.0.0.1"


def test_this_host_as_a_reflector(fake_device, collect, db):
    requests = [v2_event(src_ip="10.9.2.2", dst_port=123, src_port=40000 + i, protocol="UDP", flags=0,
                         ct_state="new", direction="in", ip_len=36) for i in range(80)]
    replies = [v2_event(src_ip="10.0.0.1", dst_ip="10.9.2.2", src_port=123, dst_port=40000 + i,
                        protocol="UDP", flags=0, ct_state="established", direction="out", ip_len=1400)
               for i in range(80)]
    build_fake_device(fake_device, [requests + replies])
    collect()
    (alert,) = alerts(db, AlertType.AMPLIFICATION)
    meta = alert.alert_metadata
    assert alert.title == "Host Used as NTP Reflector Against 10.9.2.2"
    assert (meta["role"], meta["request_bytes"], meta["reply_bytes"]) == ("reflector", 2880, 112000)
    assert meta["amplification"] == pytest.approx(38.9)
