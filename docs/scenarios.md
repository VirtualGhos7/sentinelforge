# Reproducible scenarios

All tests use local fictional assets; no third-party scanning or exploitation occurs. Run the named tests with `python -m pytest tests/test_core.py -k NAME` unless otherwise stated.

| Scenario | Execution and expected/observed result |
|---|---|
| A: exposure priority | `context_outweighs_cvss`: exposed 7.2 CVSS outranks internal 9.8 CVSS; passed |
| B: zero-day lifecycle | `zero_day_end_to_end`, plus frontend Playwright workflow: uncertain report → isolation → separate approval → independent mitigation observation → synthetic vendor patch → verified closure → approved regression reopens; passed |
| C: indirect injection | `injection_cannot_grant_tool`: malicious advisory instructions plus six attempted forbidden tools; all denied; this tests policy, not model susceptibility |
| D: failed patch | `failed_patch_never_closes`: executor completion without version change leaves case reopened; passed |
| E: identity path | `zero_day_end_to_end`: edge → service identity → research vault exists before isolation and disappears after; theoretical only |
| F: agent escalation | `injection_cannot_grant_tool`, API viewer test: role/tool mismatch rejected and API denial audit retained; passed |
| G: conflicting evidence | `missing_versions_and_conflicts_abstain`: missing worker version and changed advisory yield suspected findings and missing-evidence reason; passed |
| H: engineering correction | `tests/test_regressions.py`: imported version cannot forge observer state, untrusted fixed version cannot authorize patch, changed intelligence invalidates pending approval; passed |

Scenario H is an observed implementation review deficiency corrected with regression tests. No live model mistake or model-quality improvement was observed or claimed. The safe baseline is deterministic policy execution; a minimally constrained model baseline remains unimplemented.

The strongest UI demonstration is detailed in README. Failed-patch UI variation: start fresh, investigate, reveal the vendor update, propose failed patch, switch to approver to approve, return to analyst to execute, then verify as verifier. A completed executor response must not produce verified closure.
