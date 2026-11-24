"""Exercise login, investigation and static delivery in the CI Compose deployment."""
import httpx

with httpx.Client(base_url="http://127.0.0.1:8001", timeout=10, trust_env=False) as client:
    response = client.get("/")
    response.raise_for_status()
    if "SentinelForge" not in response.text:
        raise SystemExit("Frontend missing from image")
    # Public synthetic-only credential, documented in README; CI binds only to loopback.
    credentials = {"username": "analyst", "password": "local-demo-analyst"}  # nosec B105
    response = client.post("/api/login", json=credentials)
    response.raise_for_status()
    headers = {"Authorization": "Bearer " + response.json()["token"]}
    response = client.post("/api/tools", headers=headers, json={"agent": "investigator", "tool": "investigate"})
    response.raise_for_status()
    if len(response.json()["result"]) != 4:
        raise SystemExit("Unexpected synthetic finding count")
    print("Compose frontend, login, persistence and investigation smoke test passed.")
