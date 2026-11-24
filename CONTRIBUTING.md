# Contributing

Use Python 3.10 and Node 24. Install requirements-lock.txt and run npm ci in frontend. Follow AGENTS.md. Add regression tests for changed security decisions. Keep sample data fictional and avoid adding credentials to fixtures.

Run pytest, Ruff, Bandit, pip-audit, the frontend production build, and Playwright against a fresh local demo database. Document unexecuted checks honestly. A contribution that adds a connector must exercise failure behavior and label fixture-only versus live-tested coverage.

AI-assisted contributions are welcome. Describe what was generated, what was tested and what human review actually occurred. Do not invent provenance or benchmark improvements.
