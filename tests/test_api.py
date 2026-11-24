import pytest
from fastapi.testclient import TestClient
from backend.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SF_DEMO", "1")
    return TestClient(create_app("sqlite:///" + str(tmp_path / "api.db")))


def login(client, user):
    response = client.post("/api/login", json={"username": user, "password": "local-demo-" + user})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["token"]}


def test_auth_and_role_enforcement(client):
    assert client.get("/api/state").status_code == 401
    assert client.post("/api/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    viewer = login(client, "viewer")
    assert client.get("/api/state", headers=viewer).status_code == 200
    assert client.post("/api/tools", headers=viewer, json={"agent": "investigator", "tool": "investigate"}).status_code == 403
    assert client.post("/api/kill", headers=viewer, json={"enabled": True}).status_code == 403


def test_api_workflow(client):
    analyst, approver, verifier = [login(client, u) for u in ("analyst", "approver", "verifier")]
    def tool(h, agent, name, args=None):
        return client.post("/api/tools", headers=h, json={"agent": agent, "tool": name, "arguments": args or {}})
    assert tool(analyst, "investigator", "investigate").status_code == 200
    p = tool(analyst, "responder", "propose", {"case": "edge:SF-ZERO-001", "operation": "isolate"}).json()["result"]["approval"]
    assert client.post("/api/approvals/" + p, headers=analyst).status_code == 403
    assert client.post("/api/approvals/" + p, headers=approver).status_code == 200
    assert tool(analyst, "remediator", "execute", {"approval": p}).status_code == 200
    assert tool(verifier, "verifier", "verify", {"case": "edge:SF-ZERO-001"}).json()["result"]["status"] == "mitigated"
    assert tool(analyst, "remediator", "execute", {"approval": p}).status_code == 403
    report = client.get("/api/report", headers=verifier).json()
    assert any(e["event"] == "policy-denied" for e in report["timeline"])


def test_headers_size_schema_logout(client):
    h = login(client, "analyst")
    response = client.get("/api/state", headers=h)
    assert response.headers["x-frame-options"] == "DENY"
    assert client.post("/api/import", headers=h, content=b"x" * 262145).status_code == 413
    assert client.post("/api/inventory", headers=h, json=[{"id": "x", "extra": True}]).status_code == 422
    assert client.post("/api/logout", headers=h).status_code == 200
    assert client.get("/api/state", headers=h).status_code == 401


@pytest.mark.parametrize("format,content", [
    ("json", '[{"id":"new","hostname":"new","kind":"server"}]'),
    ("csv", "id,hostname,kind\nnew,new,server"),
    ("cyclonedx", '{"bomFormat":"CycloneDX","components":[{"name":"library","version":"1.0"}]}')])
def test_import_formats(client, format, content):
    h = login(client, "analyst")
    r = client.post("/api/import", headers=h, json={"format": format, "content": content})
    assert r.status_code == 200, r.text
    assert len(client.get("/api/state", headers=h).json()["assets"]) == 11
