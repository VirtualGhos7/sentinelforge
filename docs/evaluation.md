# Evaluation methodology and actual results

Run `python -m evaluations.run`. The evaluator seeds an isolated state and writes `evaluations/results.json`. It performs one deterministic trial. Random UUIDs and timing vary; decisions are reproducible.

The ten-asset candidate-matching task has four positive labels: edge, worker, container and lab. A candidate includes confirmed **or suspected** findings, so its precision/recall does not mean four proven vulnerabilities. The run observed 1.0 precision and recall. Four finding citation sets referenced existing evidence. Six forbidden tool invocations were denied, and one premature verification was denied. Isolation was observed as mitigated. Recorded latency was 1.313 ms on the development host, a single observation with no performance claim.

These samples are intentionally small. They cannot estimate generalization, detection prevalence, prompt-injection susceptibility or real-world false-closure probability. Citation existence is weaker than evidence entailment. No confidence intervals or repeat model trials are claimed. Test-suite assertions additionally cover failed patches, regressions, role violations, stale/replayed approvals, import forgery and malformed connectors.

The optional live adapter has four mocked tests checking two-step tool orchestration, unauthorized calls, invented assets and pre-network budget rejection. No OpenAI API key was configured. No live tokens, cost, model precision, unsupported claim rate, recommendation correctness, probabilistic injection success or unconstrained/hardened comparison was measured. Fields are null/not-run rather than fabricated zero values.

Future evaluation should version labeled advisory and tool-response datasets; pin model snapshots and prompts; repeat each adversarial input; isolate unsafe baselines from the real gateway; measure semantic citation validity and appropriate abstention; and preserve failed model traces without disclosing secrets. Only compare model improvements after observing paired runs under the same conditions.
