# Engineering journal

## 2026-11-24 — AI-assisted initial implementation

The project owner supplied a detailed scope and authorized public publication of a new isolated repository. Codex inspected an empty Git workspace and available runtimes, researched official documentation, and implemented the initial MVP. No human code review, personal incident investigation or production validation is claimed.

- The Windows sandbox launcher failed before executing commands. Read-only and development commands were retried through the available escalation mechanism; no existing project files were overwritten.
- The `python` executable was a Windows Store alias, but `py` provided Python 3.10.11. A repository-local virtual environment was used. Node 24 was available; Docker was absent.
- Chose SQLite JSON snapshot persistence through SQLAlchemy to make approval consumption transactional without adding infrastructure. The tradeoff is limited throughput and no relational enterprise model.
- First security/API suite passed 33 tests. Review then identified that a same-source import could modify simulated version state and that untrusted patch claims could authorize a change. Existing imports now remain conflict observations; only the explicit synthetic vendor scenario grants patch authority. Added regression tests instead of relying on prompt instructions.
- Bound pending actions to the advisory snapshot as well as asset state after recognizing that intelligence could change between proposal and execution.
- Frontend TypeScript initially failed because a CSS module side-effect declaration was missing. Added Vite client types. A subsequent build failed because an unnecessary data-URL CSS import was treated as a file; removed it. Production build then passed.
- Ruff flagged a reused fixture import; moved fixture exposure to the test plugin mechanism. Final lint passed.
- The Chromium workflow passed end to end with real UI interactions and captured actual application screenshots. An agent visually inspected the overview; this is not a human accessibility review.
- Live NVD/CISA/EPSS lookup of CVE-2021-44228 succeeded; OSV returned ten records for requests 2.19.0. No third-party scanning or exploitation was performed.
- Added a separate optional Responses API fixture adapter with bounded calls, cost reservation, structured output and gateway-enforced tools. Four mocked tests passed; no API key was configured, so no live model outcomes were recorded.
- Final initial suite: 46 Python tests, 88% aggregate statement coverage, one passing Chromium workflow. Ruff, Bandit, pip-audit and npm audit passed as documented. A FastAPI/Starlette TestClient deprecation warning remains; it did not invalidate results.

Important remaining debt: normalized persistence, identity federation, independent external observations, durable audit integrity, supported-runtime migration, broader model evaluation, Docker runtime validation and production-grade input/data lifecycle management. See limitations and roadmap.

## Publication and remote validation

Published the reviewed new repository to the authorized GitHub account. The initial remote workflow passed all checks, including Linux tests, browser workflow, dependency audits, SBOM generation and Docker image build. Added a separate Compose deployment smoke test to validate runtime behavior remotely. Bandit flagged its deliberately public local demo password; documented a narrow B105 exception for this fixture credential. It is not an undisclosed real credential or an exception for production authentication.

The revised complete workflow passed, including the hardened Compose deployment on a separate loopback port. The image served the built UI, authenticated the demo analyst and persisted four seeded investigation findings. This adds remote Linux deployment evidence; Windows Docker remains untested. The public tree was checked to exclude private preparation, environment secrets and runtime databases.
