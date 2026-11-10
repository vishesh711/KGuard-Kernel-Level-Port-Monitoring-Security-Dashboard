"""
The access column of docs/API.md is generated from each route's
dependencies (app/apidoc.py). These tests check it against what the API
actually does, and that the published reference is up to date.
"""

import os
import re

import pytest

from app import apidoc
from app.main import app

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def endpoints():
    found = []
    for route in apidoc.api_routes(app):
        if not route.include_in_schema:
            continue
        for method in sorted(route.methods - {"HEAD"}):
            found.append((method, route.path, apidoc.access_of(route)))
    return found


def concrete(path):
    # Placeholder values: the call must be refused before they are looked up
    return re.sub(r"\{[^}]+\}", "1", path)


ENDPOINTS = endpoints()


def test_every_endpoint_has_an_access_level():
    labels = {access for _, _, access in ENDPOINTS}
    assert labels <= {"public", "logged in", "admin", "agent token", "enrollment key", "metrics token"}
    public = sorted(path for _, path, access in ENDPOINTS if access == "public")
    # Anything else made public by mistake shows up here
    assert public == ["/", "/api/auth/login", "/api/health/"]


@pytest.mark.parametrize("method,path,access", [e for e in ENDPOINTS if e[2] != "public"],
                         ids=lambda v: v if isinstance(v, str) else None)
def test_anonymous_calls_are_refused(anon, method, path, access):
    # Enrollment validates its body before the key: give it a valid one
    body = {"name": "probe"} if access == "enrollment key" else {}
    response = anon.request(method, concrete(path), json=body)
    # The enrollment endpoint answers a missing key with 403 (enrollment off or wrong key)
    expected = {403} if access == "enrollment key" else {401}
    if access == "metrics token":
        expected = {401, 404}  # 404 when METRICS_TOKEN is not set
    assert response.status_code in expected, (method, path, response.status_code, response.text[:200])


@pytest.mark.parametrize("method,path,access", [e for e in ENDPOINTS if e[2] == "admin"],
                         ids=lambda v: v if isinstance(v, str) else None)
def test_viewers_cannot_call_admin_endpoints(viewer, method, path, access):
    response = viewer.request(method, concrete(path), json={})
    assert response.status_code == 403, (method, path, response.status_code, response.text[:200])


def test_published_api_reference_is_current():
    with open(os.path.join(REPO, "docs", "API.md")) as f:
        assert f.read() == apidoc.render(app) + "\n", \
            "docs/API.md is out of date: cd backend && python -m app.apidoc > ../docs/API.md"
