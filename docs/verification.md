# Verified closure

The implemented lifecycle is under investigation → awaiting approval → verification pending → mitigated / verified closed / reopened. There is no arbitrary status-update endpoint. Risk acceptance, false-positive disposition and the remainder of the requested enterprise lifecycle are deferred.

Isolation can produce mitigated, never verified closed. A patch action only changes synthetic state. A separate human principal invokes the verifier, which captures timestamped asset state, current advisory evidence ID, assessment and observer identity. A trusted synthetic vendor update and a version at or above its fixed version are required for closure. Public advisory imports cannot authorize patch execution or closure on their own. The failed-patch operation deliberately returns executor completion without changing software; verification reopens the finding.

Approvals expire after ten minutes and bind canonical action JSON, requesting identity, asset snapshot and advisory snapshot. A changed version, new advisory, changed arguments, different executor, expired or consumed approval fails closed. Database compare-and-swap prevents concurrent consumption. Regression requires a fresh approval and subsequent verification.

Independence here means separate identity and observation code, not an independent physical scanner or trust domain. All demo passwords are public and usable by one person for demonstration; this is not real-world separation of duties. Real deployment requires identity federation, role administration, signed observations and independent scanners.
