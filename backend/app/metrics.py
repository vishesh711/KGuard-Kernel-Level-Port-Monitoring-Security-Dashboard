"""
Prometheus metrics (roadmap S6.8), served at GET /metrics.

/metrics needs its own bearer token, METRICS_TOKEN (Prometheus sends it with
`authorization: {credentials_file: ...}`); without one set, it is off.

Counted as things happen:
    kguard_events_total{host}                 events stored ("local" or the agent's name)
    kguard_alerts_total{type, severity}       alerts raised
    kguard_detection_seconds                  time to analyse one batch (histogram)
    kguard_http_requests_total{method,status} API requests
    kguard_http_request_seconds               API latency (histogram)

Read from the running services at each scrape:
    kguard_kernel_events_dropped_total{host}  lost in kernel buffers (this server and each agent)
    kguard_agent_queue_dropped_total{agent}   lost in an agent's queue
    kguard_agent_online{agent}                1 if the agent sent anything in the last 30 s
    kguard_agent_blocklist_in_sync{agent}     1 if the agent applied the current blocklist
    kguard_blocks_active                      addresses blocked now
    kguard_collector_errors_total             collection errors on this server
    kguard_detection_state{backend}           1 for memory, redis or "memory fallback"
"""

import hmac
from typing import Optional

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    disable_created_metrics,
    generate_latest,
)
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

# No *_created timestamp series: they double the output and dashboards do not use them
disable_created_metrics()
registry = CollectorRegistry()

EVENTS = Counter("kguard_events", "Events stored", ["host"], registry=registry)
ALERTS = Counter("kguard_alerts", "Alerts raised", ["type", "severity"], registry=registry)
DETECTION_SECONDS = Histogram(
    "kguard_detection_seconds", "Time to analyse one batch of events",
    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
    registry=registry)
HTTP_REQUESTS = Counter("kguard_http_requests", "API requests", ["method", "status"], registry=registry)
HTTP_SECONDS = Histogram("kguard_http_request_seconds", "API request duration",
                         buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10), registry=registry)


def host_label(host_id: Optional[int], names: dict = {}) -> str:  # noqa: B006 (deliberate cache)
    if host_id is None:
        return "local"
    if host_id not in names:
        from .database import SessionLocal
        from .models.agent import Agent

        db = SessionLocal()
        try:
            agent = db.get(Agent, host_id)
            names[host_id] = agent.name if agent else str(host_id)
        finally:
            db.close()
    return names[host_id]


def observe_request(method: str, status: int, seconds: float) -> None:
    HTTP_REQUESTS.labels(method, str(status)).inc()
    HTTP_SECONDS.observe(seconds)


class LiveCollector:
    """Values the services already keep, read at scrape time"""

    def collect(self):
        from .database import SessionLocal
        from .models.agent import Agent
        from .services.anomaly_detector import anomaly_detector
        from .services.data_collector import data_collector
        from .services.response import response_engine

        dropped = CounterMetricFamily("kguard_kernel_events_dropped", "Events lost in kernel buffers",
                                      labels=["host"])
        dropped.add_metric(["local"], data_collector.stats.get("kernel_events_dropped", 0))
        queue = CounterMetricFamily("kguard_agent_queue_dropped", "Events lost in an agent's queue",
                                    labels=["agent"])
        online = GaugeMetricFamily("kguard_agent_online", "Agent sent something in the last 30 s",
                                   labels=["agent"])
        in_sync = GaugeMetricFamily("kguard_agent_blocklist_in_sync", "Agent applied the current blocklist",
                                    labels=["agent"])
        blocks = GaugeMetricFamily("kguard_blocks_active", "Addresses and prefixes blocked now")
        db = SessionLocal()
        try:
            for agent in db.query(Agent):
                dropped.add_metric([agent.name], agent.kernel_dropped or 0)
                queue.add_metric([agent.name], agent.queue_dropped or 0)
                online.add_metric([agent.name], 1 if agent.is_online() else 0)
                _, version = response_engine.blocklist_text(response_engine.active(db, host_id=agent.id))
                in_sync.add_metric([agent.name], 1 if agent.blocklist_applied == version
                                   and not agent.blocklist_failed else 0)
            blocks.add_metric([], len(response_engine.active(db)))
        finally:
            db.close()
        yield from (dropped, queue, online, in_sync, blocks)

        errors = CounterMetricFamily("kguard_collector_errors", "Collection errors on this server")
        errors.add_metric([], data_collector.stats.get("errors", 0))
        yield errors
        state = GaugeMetricFamily("kguard_detection_state", "Where detection state is kept",
                                  labels=["backend"])
        state.add_metric([anomaly_detector.state.status], 1)
        yield state


registry.register(LiveCollector())


def token_ok(authorization: str, token: str) -> bool:
    scheme, _, supplied = authorization.partition(" ")
    return (bool(token) and scheme.lower() == "bearer"
            and hmac.compare_digest(supplied.encode(), token.encode()))


def render() -> tuple:
    return generate_latest(registry), CONTENT_TYPE_LATEST
