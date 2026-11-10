"""
Generate docs/API.md from the application itself, so the API reference
cannot drift from the code:

    python -m app.apidoc > ../docs/API.md        (from backend/)
    python -m app.apidoc --check ../docs/API.md  (CI: fails if out of date)

Who may call each endpoint is read from its dependencies (current_user,
require_admin, current_agent, ...); tests/test_api_access.py checks that
every endpoint labelled as needing a login really refuses an anonymous call.
"""

import argparse
import difflib
import inspect
import sys

from fastapi import routing as fastapi_routing
from fastapi.routing import APIRoute, APIWebSocketRoute

# Who may call an endpoint, from the dependency that guards it (strongest wins)
ACCESS = [
    ("require_admin", "admin"),
    ("current_user", "logged in"),
    ("current_agent", "agent token"),
]
SPECIAL = {
    "/api/agents/enroll": "enrollment key",
    "/metrics": "metrics token",
    "/api/auth/login": "public",
}
SECTION_TITLES = {
    "auth": "Login and users", "events": "Events", "alerts": "Alerts", "health": "Health",
    "agents": "Agents", "payloads": "DNS and TLS", "response": "Response (blocking)",
    "notifications": "Notifications", "sockets": "Sockets and listeners", "metrics": "Metrics",
}


def dependency_names(dependant):
    names = []
    for dep in dependant.dependencies:
        if dep.call is not None:
            names.append(getattr(dep.call, "__name__", ""))
        names.extend(dependency_names(dep))
    return names


def access_of(route) -> str:
    if route.path in SPECIAL:
        return SPECIAL[route.path]
    names = dependency_names(route.dependant)
    for name, label in ACCESS:
        if name in names:
            return label
    return "public"


def first_paragraph(text: str) -> str:
    text = inspect.cleandoc(text or "")
    return " ".join(text.split("\n\n")[0].split())


def type_name(schema: dict, spec: dict) -> str:
    if "$ref" in schema:
        return schema["$ref"].rsplit("/", 1)[-1]
    if "anyOf" in schema:
        kinds = [type_name(s, spec) for s in schema["anyOf"] if s.get("type") != "null"]
        return " | ".join(kinds) or "null"
    if schema.get("type") == "array":
        return f"list[{type_name(schema.get('items', {}), spec)}]"
    if "enum" in schema:
        return " \\| ".join(f"`{v}`" for v in schema["enum"])
    return schema.get("type", "any")


def parameters(op: dict, spec: dict) -> list:
    rows = []
    for p in op.get("parameters", []):
        if p.get("in") == "header":
            continue
        schema = p.get("schema", {})
        default = schema.get("default")
        rows.append(f"`{p['name']}` ({p['in']}, {type_name(schema, spec)}"
                    + (", required" if p.get("required") else "")
                    + (f", default `{default}`" if default not in (None, "") else "") + ")")
    return rows


def body_of(op: dict, spec: dict) -> str:
    content = op.get("requestBody", {}).get("content", {})
    for media in content.values():
        schema = media.get("schema", {})
        name = type_name(schema, spec)
        ref = schema.get("$ref", "").rsplit("/", 1)[-1]
        fields = spec["components"]["schemas"].get(ref, {}).get("properties", {})
        required = set(spec["components"]["schemas"].get(ref, {}).get("required", []))
        if fields:
            return name + ": " + ", ".join(f"`{k}`" + ("" if k in required else "?") for k in fields)
        return name
    return ""


def api_routes(app):
    """Every HTTP route with the dependencies it really runs with, including
    those its router was included with (FastAPI >= 0.16x keeps included
    routers nested; iter_route_contexts flattens them as OpenAPI does)"""
    iter_contexts = getattr(fastapi_routing, "iter_route_contexts", None)
    if iter_contexts is None:
        return [r for r in app.routes if isinstance(r, APIRoute)]
    return [c for c in iter_contexts(app.routes) if isinstance(c.original_route, APIRoute)]


def render(app) -> str:
    spec = app.openapi()
    routes = {}
    for route in api_routes(app):
        if route.include_in_schema:
            for method in sorted(route.methods - {"HEAD"}):
                routes[(route.path, method.lower())] = route
    sections = {}
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            route = routes.get((path, method))
            tag = (op.get("tags") or ["other"])[0]
            sections.setdefault(tag, []).append((path, method, op, route))

    out = [
        "# KGuard API reference",
        "",
        "Generated from the backend by `python -m app.apidoc` (CI fails when this file is out of date).",
        "A backend started with `DEBUG=true` also serves an interactive version at `/docs`",
        "(OpenAPI schema at `/openapi.json`).",
        "",
        "**Authentication.** Log in with `POST /api/auth/login` and send the returned `access_token` as",
        "`Authorization: Bearer <token>`. *logged in* means any user (viewer or admin); *admin* means the",
        "admin role (a viewer gets 403). Agents use the token they received at enrollment; Prometheus uses",
        "`METRICS_TOKEN`. Calls without the required credentials get 401.",
        "",
    ]
    order = list(SECTION_TITLES)
    for tag in sorted(sections, key=lambda t: order.index(t) if t in order else len(order)):
        out += [f"## {SECTION_TITLES.get(tag, tag.title())}", "", "| Method | Path | Access | What it does |",
                "|---|---|---|---|"]
        for path, method, op, route in sections[tag]:
            access = access_of(route) if route else "public"
            what = first_paragraph(route.description if route else op.get("description", "")) \
                or op.get("summary", "")
            extras = parameters(op, spec)
            body = body_of(op, spec)
            if body:
                extras.append(f"body {body}")
            detail = (what + ("<br>" + "; ".join(extras) if extras else "")).replace("|", r"\|")
            out.append(f"| {method.upper()} | `{path}` | {access} | {detail} |")
        out.append("")

    ws = [r for r in app.routes if isinstance(r, APIWebSocketRoute)]
    if ws:
        out += ["## WebSocket", ""]
        for r in ws:
            out += [f"`{r.path}?token=<access_token>` (logged in): {first_paragraph(r.endpoint.__doc__)}", ""]
        out += [
            "Messages are JSON objects `{\"type\": ..., \"data\": ..., \"timestamp\": ...}`; the types are",
            "listed in `backend/app/services/websocket_manager.py`.",
            "",
        ]
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", metavar="FILE", help="exit 1 if FILE differs from the generated text")
    args = parser.parse_args()
    from .main import app

    text = render(app) + "\n"
    if args.check:
        current = open(args.check).read()
        if current != text:
            sys.stdout.writelines(difflib.unified_diff(current.splitlines(True), text.splitlines(True),
                                                       args.check, "generated"))
            print(f"\n{args.check} is out of date: run python -m app.apidoc > {args.check}", file=sys.stderr)
            return 1
        print(f"{args.check} is up to date")
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
