# Operational runbook

Use the README host instructions. The database is created on first start. Start only one Uvicorn worker because sessions are in memory. Build frontend assets before starting the server; otherwise only the API is mounted. Login failures with correct demo credentials generally mean `SF_DEMO=1` was not set in the server process. The example env file is documentation; the app does not automatically load it.

To reset a host demo, stop the server, then run `python -m scripts.reset_demo --confirm-synthetic-reset`. This deletes only the repository-root `sentinelforge.db`, refuses symlinks and accepts no arbitrary target path. Restart to reseed. It does not reset a custom `SF_DATABASE` URL. For Compose, `docker compose down -v` removes this Compose project's named volume; verify the project context first.

To reproduce browser tests, use a fresh database and the loopback server on port 8000. `npm test --prefix frontend` switches among demo principals. The browser test intentionally modifies synthetic data. Running it again requires a fresh database.

Back up the SQLite file only while the app is stopped. No high-availability, disaster recovery SLA or backup encryption is configured. Reports can contain imported advisory text; keep imports synthetic when sharing demonstrations. Do not point this application at an existing production database.

Container runtime checks were not possible on the development host. The Linux CI Compose smoke test passed frontend delivery, login and persisted investigation with the named volume and hardening enabled. This does not prove operational reliability or Windows Docker compatibility. `SF_PORT=8001` can select a different loopback host port if 8000 is occupied. Validate your own deployment before relying on it.
