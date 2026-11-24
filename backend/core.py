"""Deterministic security decisions. No shell, arbitrary URL or model authority."""
import copy
import hashlib
import json
import time
import uuid
from contextlib import contextmanager
from typing import Literal

import networkx as nx
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Column, Integer, MetaData, Table, Text, create_engine, insert, select, update


class Denied(ValueError):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Asset(Strict):
    id: str = Field(pattern=r"^[a-zA-Z0-9._-]{1,80}$")
    hostname: str = Field(min_length=1, max_length=120)
    kind: Literal["endpoint", "server", "container", "network", "cloud", "saas", "identity", "agent", "data"]
    os: str = Field(default="unknown", max_length=100)
    package: str = Field(default="", max_length=150)
    version: str | None = Field(default=None, max_length=80)
    purl: str | None = Field(default=None, max_length=300)
    internet: bool | None = None
    segment: str = Field(default="unknown", max_length=80)
    criticality: int = Field(default=3, ge=1, le=5)
    sensitivity: int = Field(default=3, ge=1, le=5)
    owner: str | None = Field(default=None, max_length=100)
    source: str = Field(default="inventory-import", max_length=100)
    last_seen: float = Field(default_factory=time.time)
    confidence: float = Field(default=0.8, ge=0, le=1)
    isolated: bool = False


class Advisory(Strict):
    id: str = Field(pattern=r"^[a-zA-Z0-9._-]{1,100}$")
    source: str = Field(min_length=1, max_length=100)
    description: str = Field(max_length=10000)
    package: str = Field(max_length=150)
    fixed: str | None = Field(default=None, max_length=80)
    affected: list[str] = Field(default_factory=list, max_length=500)
    cvss: float | None = Field(default=None, ge=0, le=10)
    epss: float | None = Field(default=None, ge=0, le=1)
    kev: bool | None = None
    confidence: float = Field(default=0.7, ge=0, le=1)
    observed: float = Field(default_factory=time.time)


class Action(Strict):
    case: str = Field(max_length=100)
    operation: Literal["isolate", "patch", "failed_patch", "regress"]
    version: str | None = Field(default=None, max_length=80)


PERMISSIONS = {
    "investigator": ["investigate"], "intelligence": ["intelligence"],
    "path-analyst": ["paths"], "planner": ["plan"],
    "responder": ["propose"], "remediator": ["execute"],
    "verifier": ["verify"], "reporter": ["report"],
}
WEIGHTS = {"severity": 20, "exploitation": 20, "probability": 10, "internet": 15,
           "criticality": 15, "sensitivity": 10, "blast_radius": 10}


def risk(asset, advisory, blast=0, weights=None):
    weights = weights or WEIGHTS
    values = {"severity": None if advisory["cvss"] is None else advisory["cvss"] / 10,
              "exploitation": advisory["kev"], "probability": advisory["epss"],
              "internet": False if asset["isolated"] else asset["internet"],
              "criticality": asset["criticality"] / 5, "sensitivity": asset["sensitivity"] / 5,
              "blast_radius": min(blast / 5, 1)}
    parts = {k: round(weights[k] * (0.5 if v is None else float(v)), 2) for k, v in values.items()}
    return {"score": round(sum(parts.values()), 2), "breakdown": parts,
            "unknown": [k for k, v in values.items() if v is None],
            "confidence": min(asset["confidence"], advisory["confidence"])}


def match(asset, advisory):
    if asset["package"] != advisory["package"]:
        return "unaffected"
    if not asset["version"]:
        return "suspected"
    if asset["version"] in advisory["affected"]:
        return "confirmed"
    if advisory["fixed"]:
        try:
            return "unaffected" if Version(asset["version"]) >= Version(advisory["fixed"]) else "confirmed"
        except InvalidVersion:
            return "suspected"
    return "suspected"


def graph(state):
    g = nx.DiGraph()
    g.add_nodes_from(state["assets"])
    for edge in state["edges"]:
        if not state["assets"][edge["from"]]["isolated"] and not state["assets"][edge["to"]]["isolated"]:
            g.add_edge(edge["from"], edge["to"], kind=edge["kind"])
    return g


def paths(state):
    g = graph(state)
    result = []
    for source, a in state["assets"].items():
        if a["internet"] and not a["isolated"]:
            for target, b in state["assets"].items():
                if source != target and b["sensitivity"] == 5 and nx.has_path(g, source, target):
                    result.append(nx.shortest_path(g, source, target))
    return result


def audit(state, actor, event, details):
    state["audit"].append({"id": len(state["audit"]) + 1, "at": time.time(),
                           "actor": actor, "event": event, "details": details})


def seed():
    specs = [
        ("edge", "meridian-gateway", "server", "LumenProxy", "1.4", True, "Platform", 5),
        ("lab", "isolated-build", "server", "LegacyBuild", "2.0", False, "Engineering", 2),
        ("service", "deploy-service", "identity", "", None, False, "Platform", 4),
        ("vault", "research-vault", "data", "", None, False, "Research", 5),
        ("worker", "regional-worker", "cloud", "LumenProxy", None, False, None, 4),
        ("agent", "inventory-assistant", "agent", "", None, False, "Security", 3),
        ("saas", "fictional-ticketing", "saas", "", None, False, "IT", 3),
        ("desktop", "analyst-workstation", "endpoint", "", None, False, "IT", 2),
        ("firewall", "segment-firewall", "network", "", None, False, "Network", 4),
        ("container", "api-container", "container", "LumenProxy", "1.4", False, "Platform", 3),
    ]
    assets = {i: Asset(id=i, hostname=h, kind=k, package=p, version=v, internet=n,
                       owner=o, sensitivity=s, criticality=s, source="synthetic-fixture",
                       segment="edge" if n else "internal").model_dump()
              for i, h, k, p, v, n, o, s in specs}
    advisories = [Advisory(id="SF-ZERO-001", source="fictional-researcher", package="LumenProxy",
                          description="Unconfirmed request routing weakness. Versions and exploitation disputed. No patch.",
                          cvss=7.2, kev=True, epss=0.7),
                  Advisory(id="SF-LAB-002", source="fictional-vendor", package="LegacyBuild",
                           description="Local build issue on disconnected fixture.", fixed="2.1", cvss=9.8, kev=False, epss=0.01)]
    state = {"assets": assets, "advisories": {}, "evidence": {}, "cases": {}, "approvals": {},
             "audit": [], "kill": False, "weights": WEIGHTS.copy(), "calls": {}, "conflicts": [],
             "edges": [{"from": "edge", "to": "service", "kind": "service-credential"},
                       {"from": "service", "to": "vault", "kind": "administrative-trust"},
                       {"from": "agent", "to": "saas", "kind": "read-tool-permission"}]}
    for a in advisories:
        ingest_advisory(state, a, "seed")
    return state


def ingest_advisory(state, advisory, actor, trusted_patch=False):
    a = advisory.model_dump()
    eid = str(uuid.uuid4())
    state["evidence"][eid] = {"type": "advisory", "at": time.time(), "source": a["source"], "raw": a}
    old = state["advisories"].get(a["id"])
    if old and any(old[k] != a[k] for k in ("fixed", "affected", "kev")):
        state["conflicts"].append({"advisory": a["id"], "previous": old["evidence"], "incoming": eid})
    a["evidence"] = eid
    a["trusted_patch"] = trusted_patch
    state["advisories"][a["id"]] = a
    audit(state, actor, "advisory-ingested", {"evidence": eid})
    return eid


def reconcile(state, assets, actor):
    for asset in assets:
        a = asset.model_dump()
        old = state["assets"].get(a["id"])
        if old and old != a:
            state["conflicts"].append({"asset": a["id"], "previous": copy.deepcopy(old), "incoming": a})
        if old:
            continue  # imports are observations, never authoritative changes to simulator state
        state["assets"][a["id"]] = a
    audit(state, actor, "inventory-import", {"count": len(assets)})


class Store:
    """Optimistic compare-and-swap makes approval consumption atomic across workers."""
    def __init__(self, url):
        self.engine = create_engine(url)
        self.table = Table("state", MetaData(), Column("id", Integer, primary_key=True),
                           Column("revision", Integer, nullable=False), Column("data", Text, nullable=False))
        self.table.metadata.create_all(self.engine)
        with self.engine.begin() as c:
            if c.execute(select(self.table)).first() is None:
                c.execute(insert(self.table).values(id=1, revision=0, data=json.dumps(seed())))

    def read(self):
        with self.engine.connect() as c:
            return json.loads(c.execute(select(self.table.c.data)).scalar_one())

    @contextmanager
    def transaction(self):
        with self.engine.begin() as c:
            row = c.execute(select(self.table)).one()
            state = json.loads(row.data)
            yield state
            changed = c.execute(update(self.table).where(self.table.c.revision == row.revision)
                                .values(revision=row.revision + 1, data=json.dumps(state)))
            if changed.rowcount != 1:
                raise Denied("Concurrent update; reload and retry")


def digest(action):
    return hashlib.sha256(json.dumps(action, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def approve(state, approval_id, actor, role):
    p = state["approvals"].get(approval_id)
    if role != "approver" or not p or p["requester"] == actor:
        raise Denied("Independent approver required")
    if p["used"] or p["expires"] <= time.time() or p["approved_by"]:
        raise Denied("Approval expired, consumed or already granted")
    p["approved_by"] = actor
    audit(state, actor, "approved", {"approval": approval_id, "digest": p["digest"]})


def gateway(state, actor, role, agent, tool, arguments, scope):
    """Scope and agent are assigned by the authenticated server, never by a model."""
    if state["kill"]:
        raise Denied("Agent kill switch enabled")
    if tool not in PERMISSIONS.get(agent, []):
        raise Denied("Agent tool permission denied")
    if role not in ("analyst", "admin"):
        raise Denied("Role cannot run agents")
    key = actor + ":" + str(int(time.time() // 60))
    state["calls"][key] = state["calls"].get(key, 0) + 1
    if state["calls"][key] > 60:
        raise Denied("Execution budget exceeded")
    if len(state["calls"]) > 200:
        state["calls"] = {key: state["calls"][key]}
    if tool in ("investigate", "intelligence", "paths", "plan", "report"):
        if arguments:
            raise Denied("Read tools accept no arguments")
        result = read_tool(state, tool, scope)
    elif tool == "propose":
        action = Action.model_validate(arguments).model_dump()
        case = state["cases"].get(action["case"])
        if not case or case["asset"] not in scope:
            raise Denied("Unknown or unauthorized case")
        if case["status"] == "verified closed" and action["operation"] != "regress":
            raise Denied("Closed case cannot be remediated")
        if action["operation"] in ("patch", "failed_patch"):
            fixed = state["advisories"][case["advisory"]]["fixed"]
            if not fixed or action["version"] != fixed or not state["advisories"][case["advisory"]].get("trusted_patch"):
                raise Denied("Patch must match currently documented fixed version")
        elif action["version"] is not None:
            raise Denied("Unexpected version argument")
        pid = str(uuid.uuid4())
        state["approvals"][pid] = {"action": action, "digest": digest(action), "requester": actor,
                                   "approved_by": None, "expires": time.time() + 600, "used": False,
                                   "advisory_before": digest(state["advisories"][case["advisory"]]),
                                   "asset_before": digest(state["assets"][case["asset"]])}
        case["status"] = "awaiting approval"
        result = {"approval": pid, "action": action}
    elif tool == "execute":
        if set(arguments) != {"approval"}:
            raise Denied("Only an approval identifier is accepted")
        p = state["approvals"].get(arguments["approval"])
        if not p or not p["approved_by"] or p["used"] or p["expires"] <= time.time():
            raise Denied("Valid unused human approval required")
        if p["requester"] != actor or p["digest"] != digest(p["action"]):
            raise Denied("Approval binding mismatch")
        action = p["action"]
        case = state["cases"][action["case"]]
        asset = state["assets"][case["asset"]]
        if asset["id"] not in scope or digest(asset) != p["asset_before"]:
            raise Denied("Scope or stale asset state mismatch")
        if digest(state["advisories"][case["advisory"]]) != p["advisory_before"]:
            raise Denied("Intelligence changed after proposal; re-plan")
        p["used"] = True
        operation = action["operation"]
        if operation == "isolate":
            asset["isolated"] = True
        elif operation == "patch":
            asset["version"] = action["version"]
        elif operation == "regress":
            asset["version"] = "1.4"
            asset["isolated"] = False
        case.update(status="verification pending", executor=actor, changed=time.time())
        result = {"executor_report": "simulated action completed", "closure": False}
    elif tool == "verify":
        if set(arguments) != {"case"}:
            raise Denied("Verification requires only a case identifier")
        case = state["cases"].get(arguments["case"])
        if not case or case["asset"] not in scope:
            raise Denied("Unknown or unauthorized case")
        if case.get("executor") == actor:
            raise Denied("Verifier must be a different human principal")
        if case["status"] not in ("verification pending", "verified closed", "mitigated", "reopened"):
            raise Denied("No change available for verification")
        asset = state["assets"][case["asset"]]
        advisory = state["advisories"][case["advisory"]]
        assessment = match(asset, advisory)
        closed = assessment == "unaffected" and bool(advisory["fixed"]) and advisory.get("trusted_patch", False)
        case["status"] = "verified closed" if closed else "mitigated" if asset["isolated"] else "reopened"
        eid = str(uuid.uuid4())
        result = {"type": "verification", "source": "independent-synthetic-observer", "observer": actor,
                  "at": time.time(), "asset": copy.deepcopy(asset), "advisory_evidence": advisory["evidence"],
                  "assessment": assessment, "validated": True, "status": case["status"]}
        state["evidence"][eid] = result
        case["verification"] = eid
        result = {**result, "evidence": eid}
    else:
        raise Denied("Unknown tool")
    audit(state, actor, "tool-executed", {"agent": agent, "tool": tool, "arguments": arguments})
    return {"agent": agent, "mode": "deterministic-offline", "result": result}


def read_tool(state, tool, scope):
    if tool == "paths":
        return {"paths": [p for p in paths(state) if all(a in scope for a in p)], "claim": "theoretical reachability, not exploitability"}
    if tool == "intelligence":
        return {"conflicts": state["conflicts"], "stale": [a["id"] for a in state["advisories"].values() if time.time() - a["observed"] > 86400 * 7]}
    if tool == "plan":
        return [{"case": c["id"], "owner": state["assets"][c["asset"]]["owner"],
                 "recommendation": "patch" if state["advisories"][c["advisory"]]["fixed"] else "isolate",
                 "impact": "Isolation interrupts service; patch requires restart testing.",
                 "rollback": "Restore synthetic version only with new approval; verify again."}
                for c in state["cases"].values() if c["asset"] in scope]
    if tool == "report":
        return {"cases": [c for c in state["cases"].values() if c["asset"] in scope],
                "unowned": [a["id"] for a in state["assets"].values() if a["id"] in scope and not a["owner"]]}
    g = graph(state)
    findings = []
    for a in state["assets"].values():
        if a["id"] not in scope:
            continue
        for v in state["advisories"].values():
            status = match(a, v)
            if status == "unaffected":
                continue
            cid = a["id"] + ":" + v["id"]
            conflict = any(c.get("advisory") == v["id"] for c in state["conflicts"])
            finding = {"id": cid, "asset": a["id"], "advisory": v["id"], "assessment": "suspected" if conflict else status,
                       "risk": risk(a, v, len(nx.descendants(g, a["id"])), state["weights"]),
                       "citations": [v["evidence"]], "missing": ["resolve advisory conflict"] if conflict else ["version evidence"] if status == "suspected" else []}
            if cid not in state["cases"]:
                state["cases"][cid] = {**finding, "status": "under investigation", "created": time.time(), "due": time.time() + 86400 * 7}
            else:
                state["cases"][cid].update({k: val for k, val in finding.items() if k != "id"})
            findings.append(finding)
    return sorted(findings, key=lambda f: f["risk"]["score"], reverse=True)
