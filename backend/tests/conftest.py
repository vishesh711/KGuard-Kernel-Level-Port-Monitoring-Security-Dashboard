"""
Shared test setup.

Points the backend at a temporary SQLite database and a fake /proc/kguard
file before the app is imported, so tests never need the kernel module.
"""

import os
import tempfile
import time

_TMP = tempfile.mkdtemp(prefix="kguard-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP}/kguard-test.db"
os.environ["PROC_KGUARD_PATH"] = f"{_TMP}/kguard"
# No device by default, so "auto" falls back to the fake /proc file
os.environ["KGUARD_DEVICE_PATH"] = f"{_TMP}/kguard-dev"
# No kernel module: the backend uses its own detection rules
os.environ["KGUARD_MODULE_PATH"] = f"{_TMP}/no-such-module"
os.environ["DEBUG"] = "true"
# Keep the background collector idle; tests run collection cycles themselves
os.environ["DATA_COLLECTION_INTERVAL"] = "3600"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services.anomaly_detector import anomaly_detector  # noqa: E402
from app.services.data_collector import data_collector  # noqa: E402

TCP_SYN = 0x02
TCP_ACK = 0x10


def make_event(src_ip="10.0.0.5", dst_ip="10.0.0.1", src_port=40000, dst_port=80,
               protocol="TCP", flags=TCP_SYN, timestamp=None):
    """One event as the kernel module reports it"""
    return {
        "timestamp": timestamp if timestamp is not None else time.time_ns(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "flags": flags,
    }


def kernel_output(events, dropped=0):
    """Render events exactly as kguard_proc.c prints them"""
    lines = []
    for e in events:
        lines.append(
            f'{{"timestamp": {e["timestamp"]}, "src_ip": "{e["src_ip"]}", '
            f'"dst_ip": "{e["dst_ip"]}", "src_port": {e["src_port"]}, '
            f'"dst_port": {e["dst_port"]}, "protocol": "{e["protocol"]}", '
            f'"flags": {e["flags"]}}}'
        )
    return f'{{"dropped": {dropped}, "events": [\n' + ",\n".join(lines) + "\n]}\n"


class FakeKernel:
    """Writes events to the fake /proc/kguard and removes them once read"""

    def __init__(self, path):
        self.path = path

    def write(self, events, dropped=0):
        with open(self.path, "w") as f:
            f.write(kernel_output(events, dropped))

    def write_raw(self, text):
        with open(self.path, "w") as f:
            f.write(text)

    def remove(self):
        if os.path.exists(self.path):
            os.remove(self.path)


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def collect(client):
    """Run one collection cycle inside the app's event loop"""
    def run():
        return client.portal.call(data_collector.collect_once)
    return run


@pytest.fixture
def fake_kernel():
    kernel = FakeKernel(os.environ["PROC_KGUARD_PATH"])
    kernel.remove()
    yield kernel
    kernel.remove()


@pytest.fixture(autouse=True)
def clean_state():
    """Empty every table and reset in-memory detector state between tests"""
    init_db()
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
    anomaly_detector.reset()
    anomaly_detector.kernel_detection = False
    from app.services.kernel_alerts import kernel_alerts
    kernel_alerts.reset()
    from app.services.baseline import traffic_baseline
    traffic_baseline.reset()
    data_collector.close_device()
    data_collector.active_source = None
    data_collector.stats.update(
        events_collected=0, events_stored=0, alerts_generated=0,
        kernel_events_dropped=0, errors=0, last_collection=None,
    )
    yield


@pytest.fixture
def fake_device():
    """Path for a fake /dev/kguard (a file with the same mmap layout)"""
    path = os.environ["KGUARD_DEVICE_PATH"]
    yield path
    data_collector.close_device()
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
