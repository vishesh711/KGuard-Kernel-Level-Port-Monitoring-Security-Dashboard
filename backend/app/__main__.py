"""
Run the backend: python -m app

Logging is configured before uvicorn starts, so its start-up lines are JSON
too (uvicorn is told to leave logging alone). One process: the collector
reads the kernel rings and keeps detection state in memory, so several
workers would split the event stream between them.
"""

import uvicorn

from .config import settings
from .logging_setup import configure_logging

configure_logging()

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_config=None,
        access_log=False,
        # Behind the frontend's nginx: take the client address from
        # X-Forwarded-For, but only when nginx sent it
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
    )
