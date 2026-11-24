import pytest
from backend.core import Advisory, Asset, Denied, ingest_advisory, reconcile
from tests.test_core import call, change, reveal, verify

pytest_plugins = ["tests.test_core"]


def test_import_cannot_forge_observer_state(state):
    reveal(state)
    change(state, "failed_patch", "1.5")
    reconcile(state, [Asset(**{**state["assets"]["edge"], "version": "1.5"})], "analyst")
    assert verify(state)["status"] == "reopened"


def test_untrusted_fixed_version_cannot_authorize_patch(state):
    a = {k: v for k, v in state["advisories"]["SF-ZERO-001"].items() if k not in ("evidence", "trusted_patch")}
    a["fixed"] = "1.5"
    ingest_advisory(state, Advisory(**a), "analyst")
    with pytest.raises(Denied):
        change(state, "patch", "1.5")


def test_changed_intelligence_invalidates_approval(state):
    from backend.core import approve
    pid = call(state, "responder", "propose", {"case": "edge:SF-ZERO-001", "operation": "isolate"})["approval"]
    approve(state, pid, "approver", "approver")
    reveal(state)
    with pytest.raises(Denied, match="Intelligence changed"):
        call(state, "remediator", "execute", {"approval": pid})
