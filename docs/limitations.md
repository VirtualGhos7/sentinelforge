# Known limitations and unfinished scope

This is a tested offline MVP, not the complete enterprise platform described by the original scope.

## Highest-priority remaining work

1. Replace public demo principals with real identity federation, distinct provisioned users, durable sessions and tenant-scoped authorization.
2. Integrate independent scanners or signed observations. Current verification reads the same fictional database through a separate principal and code path.
3. Normalize persistence, introduce migrations and validate PostgreSQL, concurrent writers and larger data volumes. Current whole-state JSON transactions do not scale; audit growth and API state responses are unbounded over long operation.
4. Run live-model repeated trials against labeled datasets, including unconstrained isolated baselines. Validate factual entailment, abstention, recommendation accuracy and cost. The optional live adapter is mock-tested only.
5. Add real ecosystem version ranges/CPE mapping, source trust review, contradiction resolution and incremental scheduled synchronization.
6. Complete enterprise case states, expiring risk acceptance, owner editing, notes, attachment handling, notifications, deadlines and SLA enforcement.
7. Add Windows Docker runtime validation, Trivy/container scanning, dedicated Gitleaks scanning and broader SAST. Linux Compose smoke validation passed. CI also has Bandit, Ruff, dependency scans and a supplemental history-pattern scanner.

## Explicit boundaries

- NVD/CISA/EPSS and OSV have successful read-only live smoke checks. GitHub advisories, generic vendor advisory connectors, Defender, Tenable, Qualys, CrowdStrike, Entra, Okta and cloud security connectors are **planned**, not implemented.
- Manual public CVE synchronization is implemented; background schedules, durable incremental cursors and persistent connector caching are not. OSV pagination is bounded; NVD is single-CVE lookup.
- Inventory reconciliation uses stable IDs, not fuzzy hostname matching. Existing observations are retained as conflicts rather than automatically modifying simulator authority. CycloneDX imports only top-level component name/version/purl; SPDX and nested dependency import are absent.
- Graph UI focuses on the seeded ingress/identity/data path. It is not a general drag-and-drop graph editor. Reachability does not establish exploitability, valid credentials or network packet reachability.
- Eight deterministic tool identities exist. Five have optional read-oriented live workflows; zero-day, remediation and verification remain deterministic. No agent delegation, arbitrary tool network access or live asset mutation exists.
- Structured model output and citation existence are checked; semantic truth is not. The live CLI uses a fresh synthetic state and does not persist failed model traces. Its per-call network timeout is not a hard global wall-clock deadline.
- Model cost reservation relies on conservative user-supplied rates; inaccurate rates can make the dollar estimate wrong. Organization-level billing controls remain external.
- The kill switch applies to the web gateway state. The standalone live CLI has its own isolated state, so it cannot be stopped by the UI kill switch.
- The evaluation page reports policy events and points to reproducible files. There is no historical model comparison service, model regression dashboard or benchmark suite proving general robustness.
- Dark/light modes exist; some secondary surfaces retain dark styling. No formal accessibility audit, browser matrix or performance benchmark was performed.
- SQLAlchemy creates the initial schema; there are no migrations. SQLite snapshot storage and process-local sessions intentionally target one local worker.
- The application accepts no production credentials for target systems. Demo passwords must never be exposed publicly. There is no TLS terminator, SSO, MFA, password rotation interface or production deployment claim.
- Python 3.10 was selected because it was available on the host. Its lifecycle and a supported-runtime migration must be assessed before real deployment.
- Containers use version tags rather than immutable image digests. Dependency direct versions and a full development lock are pinned; vulnerability databases can change after this report.

No personal employment, production incident response, independent human review or real-world vulnerability discovery is claimed.
