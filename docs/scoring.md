# Contextual priority

The score is an explainable sum on a 0–100 scale. Default weights: severity 20, known exploitation 20, EPSS 10, internet exposure 15, criticality 15, sensitivity 10 and reachable blast radius 10. Severity is CVSS/10; business factors are ordinal value/5; blast radius saturates at five descendants. Missing factors contribute half their weight and are explicitly listed as unknown, avoiding an assumption of absence. Confidence is reported separately as the minimum inventory/advisory confidence; it does not quietly suppress severe uncertainty.

Weights are centralized in `WEIGHTS` and persisted with the demo state. There is no settings editor. These are illustrative, not empirically calibrated enterprise loss estimates. Privilege prerequisites, patch availability, individual controls, SLAs and monetary impact do not currently contribute to the numeric score.

Seeded Scenario A produces 85.4 for the internet-facing LumenProxy finding (CVSS 7.2) and 29.7 for the internal LegacyBuild finding (CVSS 9.8). This demonstrates contextual ordering rather than CVSS sorting. Known exploitation is a fictional fixture assertion, not a claim about a real product.

Package matching uses exact product names and Python-compatible version ordering. Unknown or unparseable versions cause abstention. It is not a universal ecosystem/CPE range engine. OSV package queries delegate ecosystem matching to OSV; automatic conversion into enterprise findings is deferred.
