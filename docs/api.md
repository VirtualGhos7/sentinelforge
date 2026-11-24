# API and connector guide

All `/api` endpoints except health/login require a bearer token from `POST /api/login` with `{ "username": "analyst", "password": "local-demo-analyst" }` in explicitly enabled local demo mode. `POST /api/logout` revokes the token. `/openapi.json` describes schemas; interactive documentation is disabled.

| Endpoint | Authorization and behavior |
|---|---|
| GET /api/state | Authenticated; inventory, findings, approval queue, audit and metrics |
| POST /api/tools | Analyst/admin; `{agent, tool, arguments}` checked by gateway |
| POST /api/approvals/{id} | Approver only, independent of requester |
| POST /api/kill | Admin only; `{enabled: true}` |
| POST /api/inventory | Analyst/admin; array of Asset schema objects, maximum 500 |
| POST /api/import | Analyst/admin; `{format: "json" / "csv" / "cyclonedx", content: "..."}` |
| POST /api/intelligence | Analyst/admin; validated normalized Advisory, retained original record |
| POST /api/sync/cve | Analyst/admin; `{id: "CVE-2021-44228"}`, fixed public sources |
| POST /api/scenario/reveal | Analyst/admin; synthetic trusted vendor update |
| GET /api/report | Authenticated; JSON evidence and timeline export |

Tool identities and permissions are defined in `backend/core.py:PERMISSIONS`. Read tools accept no arguments. Proposal arguments are `case`, `operation` and optional `version`. Execution accepts only `approval`; verification accepts only `case`. There is no generic update/close endpoint.

The request limit is 256 KiB. Per-IP API budget is 240 requests/minute; per-actor tool budget is 60 calls/minute. Unauthorized roles receive 403; invalid authentication 401; malformed input 422; oversized input 413. Sessions last one hour and are local to the process. CORS is not enabled.

`PublicIntelligence.cve(id)` combines NVD, CISA KEV and FIRST EPSS. `PublicIntelligence.package("PyPI", "requests", "2.19.0")` queries OSV and follows up to ten pages. HTTP destinations are constants, redirects are disabled, environment proxy credentials are ignored, each request has a 15-second timeout, response bytes are capped at 8 MB, transient errors receive at most three attempts, and cached responses last five minutes within that client instance. Callers must close owned clients. The API constructs a new client per sync; its cache is therefore short-lived.

Original source responses are retained alongside normalized CVE imports. Source timestamps, evidence IDs and sync failures are visible in the audit/report. No public feed is trusted to assert remediation success. Rate limits, schema changes, unavailable records and malformed responses fail without partial imports.
