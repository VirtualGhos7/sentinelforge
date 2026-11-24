import csv
import io
import os
import secrets
import time
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import Field, ValidationError
import httpx
from connectors.public import CVE, PublicIntelligence

from backend.core import (PERMISSIONS, Advisory, Asset, Denied, Store, Strict,
                          approve, audit, gateway, ingest_advisory, paths, reconcile)


class Login(Strict):
    username: Literal["analyst", "verifier", "approver", "viewer", "admin"]
    password: str = Field(max_length=200)


class Call(Strict):
    agent: str = Field(max_length=40)
    tool: str = Field(max_length=40)
    arguments: dict = Field(default_factory=dict)


class Switch(Strict):
    enabled: bool


class Import(Strict):
    format: Literal["json", "csv", "cyclonedx"]
    content: str = Field(max_length=200000)


def create_app(database=None):
    store = Store(database or os.getenv("SF_DATABASE", "sqlite:///sentinelforge.db"))
    app = FastAPI(title="SentinelForge", version="0.1.0", docs_url=None, redoc_url=None)
    app.state.store = store
    sessions = {}
    rates = {}
    bearer = HTTPBearer(auto_error=False)

    @app.middleware("http")
    async def security(request: Request, call_next):
        key = (request.client.host if request.client else "unknown", int(time.time() // 60))
        rates[key] = rates.get(key, 0) + 1
        for old in list(rates):
            if old[1] < key[1] - 1:
                rates.pop(old)
        if rates[key] > 240:
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
        size = 0
        chunks = []
        async for chunk in request.stream():
            size += len(chunk)
            if size > 262144:
                return JSONResponse({"detail": "Request too large"}, status_code=413)
            chunks.append(chunk)
        request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                                 "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
                                 "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"})
        return response

    def principal(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
        session = sessions.get(credentials.credentials if credentials else "")
        if not session or session["expires"] < time.time():
            raise HTTPException(401, "Session expired or invalid")
        return session

    def require(user, *roles):
        if user["role"] not in roles:
            raise HTTPException(403, "Role denied")

    @app.exception_handler(Denied)
    async def denied_handler(request, error):
        return JSONResponse({"detail": str(error)}, status_code=403)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "mode": "synthetic-offline"}

    @app.post("/api/login")
    def login(body: Login):
        expected = os.getenv("SF_PASSWORD_" + body.username.upper())
        if expected is None and os.getenv("SF_DEMO", "0") == "1":
            expected = "local-demo-" + body.username
        if not expected or not secrets.compare_digest(expected, body.password):
            raise HTTPException(401, "Invalid credentials or demo disabled")
        now = time.time()
        for key in list(sessions):
            if sessions[key]["expires"] < now:
                sessions.pop(key)
        token = secrets.token_urlsafe(32)
        sessions[token] = {"name": body.username, "role": "analyst" if body.username == "verifier" else body.username,
                           "expires": now + 3600}
        return {"token": token, **sessions[token]}

    @app.post("/api/logout")
    def logout(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
        if credentials:
            sessions.pop(credentials.credentials, None)
        return {"logged_out": True}

    @app.get("/api/state")
    def state(user=Depends(principal)):
        s = store.read()
        return {**s, "permissions": PERMISSIONS, "paths": paths(s), "mode": "deterministic-offline",
                "metrics": {"assets": len(s["assets"]), "open": sum(c["status"] != "verified closed" for c in s["cases"].values()),
                            "closed": sum(c["status"] == "verified closed" for c in s["cases"].values()),
                            "ownership_gaps": sum(not a["owner"] for a in s["assets"].values()),
                            "denials": sum(e["event"] == "policy-denied" for e in s["audit"]),
                            "stale_assets": sum(time.time() - a["last_seen"] > 86400 * 30 for a in s["assets"].values())}}

    @app.post("/api/tools")
    def tool(body: Call, user=Depends(principal)):
        try:
            with store.transaction() as s:
                result = gateway(s, user["name"], user["role"], body.agent, body.tool, body.arguments, set(s["assets"]))
            return result
        except (Denied, ValidationError) as error:
            with store.transaction() as s:
                audit(s, user["name"], "policy-denied", {"agent": body.agent, "tool": body.tool, "reason": "validation or authorization failure"})
            raise HTTPException(403, str(error) if isinstance(error, Denied) else "Invalid tool arguments") from error

    @app.post("/api/approvals/{approval_id}")
    def grant(approval_id: str, user=Depends(principal)):
        with store.transaction() as s:
            approve(s, approval_id, user["name"], user["role"])
        return {"approved": approval_id}

    @app.post("/api/kill")
    def kill(body: Switch, user=Depends(principal)):
        require(user, "admin")
        with store.transaction() as s:
            s["kill"] = body.enabled
            audit(s, user["name"], "kill-switch", {"enabled": body.enabled})
        return {"enabled": body.enabled}

    @app.post("/api/intelligence")
    def intelligence(body: Advisory, user=Depends(principal)):
        require(user, "analyst", "admin")
        with store.transaction() as s:
            eid = ingest_advisory(s, body, user["name"])
        return {"evidence": eid}

    @app.post("/api/scenario/reveal")
    def reveal(user=Depends(principal)):
        require(user, "analyst", "admin")
        with store.transaction() as s:
            old = s["advisories"]["SF-ZERO-001"]
            updated = {k: v for k, v in old.items() if k not in ("evidence", "trusted_patch")}
            updated.update(source="fictional-vendor", fixed="1.5", affected=["1.4"], observed=time.time(),
                           description="Synthetic vendor confirms 1.4 affected and 1.5 fixed; unknown worker version still needs evidence.")
            eid = ingest_advisory(s, Advisory.model_validate(updated), user["name"], trusted_patch=True)
        return {"evidence": eid}

    @app.post("/api/sync/cve")
    def sync_cve(body: CVE, user=Depends(principal)):
        require(user, "analyst", "admin")
        try:
            with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as client:
                result = PublicIntelligence(client).cve(body.id)
            with store.transaction() as s:
                eid = ingest_advisory(s, Advisory.model_validate(result["normalized"]), user["name"])
                s["evidence"][eid]["original_responses"] = result["raw"]
            return {"evidence": eid, "limitation": result["limitation"]}
        except (httpx.HTTPError, ValueError, KeyError, IndexError) as error:
            with store.transaction() as s:
                audit(s, user["name"], "sync-failed", {"source": "public-cve", "cve": body.id})
            raise HTTPException(502, "Public intelligence unavailable or malformed; no partial import") from error

    @app.post("/api/inventory")
    def inventory(body: list[Asset], user=Depends(principal)):
        require(user, "analyst", "admin")
        if len(body) > 500:
            raise HTTPException(422, "Maximum 500 assets")
        with store.transaction() as s:
            reconcile(s, body, user["name"])
        return {"imported": len(body)}

    @app.post("/api/import")
    def import_file(body: Import, user=Depends(principal)):
        import json
        require(user, "analyst", "admin")
        try:
            if body.format == "csv":
                rows = list(csv.DictReader(io.StringIO(body.content)))
            else:
                rows = json.loads(body.content)
            if body.format == "cyclonedx":
                if rows.get("bomFormat") != "CycloneDX":
                    raise ValueError("Invalid SBOM")
                rows = [{"id": "sbom-" + str(i), "hostname": c["name"], "kind": "container", "package": c["name"],
                         "version": c.get("version"), "purl": c.get("purl"), "source": "cyclonedx"}
                        for i, c in enumerate(rows.get("components", []))]
            if not isinstance(rows, list) or len(rows) > 500:
                raise ValueError("Invalid inventory size")
            assets = [Asset.model_validate(row) for row in rows]
        except (ValueError, KeyError, TypeError) as error:
            raise HTTPException(422, "Invalid import schema") from error
        return inventory(assets, user)

    @app.get("/api/report")
    def report(user=Depends(principal)):
        s = store.read()
        return {"generated": time.time(), "mode": "synthetic-offline", "cases": s["cases"],
                "evidence": s["evidence"], "timeline": s["audit"], "paths": paths(s)}

    frontend = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    if frontend.exists():
        app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
    return app
