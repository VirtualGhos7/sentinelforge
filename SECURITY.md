# Security policy

This is a synthetic local security engineering demonstration, not a production security service. Do not expose demo credentials or deploy it on a public interface. Compose publishes only to loopback. Login is disabled unless demo mode or role passwords are explicitly configured.

Report vulnerabilities through the repository's private vulnerability reporting feature if enabled. Otherwise open a minimal issue requesting a private contact; do not publish credentials or exploit details. No response SLA is promised.

Authorization is outside the model. External data cannot execute commands. All mutations affect synthetic state. Database administrators can rewrite both evidence and audit history; append-only is an application property, not cryptographic integrity. See docs/threat-model.md and docs/limitations.md.
