"""Startup and health checks (B1.1)"""

from app.services.data_collector import DataCollectorService


def test_app_starts_and_reports_health(client):
    response = client.get("/api/health/")
    assert response.status_code == 200
    body = response.json()
    assert body["database"] is True
    assert body["kernel_module"] is False
    assert body["status"] == "degraded"


def test_health_with_kernel_interface_present(client, fake_kernel):
    fake_kernel.write([])
    body = client.get("/api/health/").json()
    assert body["kernel_module"] is True
    assert body["status"] == "healthy"


def test_health_check_never_reads_kernel_events(client, fake_kernel, monkeypatch):
    # Reading /proc/kguard removes events, so health checks must not read it
    def fail(*args, **kwargs):
        raise AssertionError("health check read /proc/kguard")

    monkeypatch.setattr(DataCollectorService, "_read_kernel_events", fail)
    fake_kernel.write([])
    for path in ("/api/health/", "/api/health/kernel", "/api/health/detailed"):
        assert client.get(path).status_code == 200


def test_kernel_health_without_module(client, fake_kernel):
    body = client.get("/api/health/kernel").json()
    assert body["status"] == "unhealthy"
    assert any("insmod" in r for r in body["recommendations"])


def test_root(client):
    assert client.get("/").json()["status"] == "running"


def test_every_health_endpoint_answers(client):
    for path in ("/api/health/database", "/api/health/services", "/api/health/metrics"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.json().get("status") != "error", path

    database = client.get("/api/health/database").json()
    assert database["status"] == "healthy"
