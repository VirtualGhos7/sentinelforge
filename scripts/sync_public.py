"""Fetch one public CVE and retain original responses in the local evidence store."""
import argparse
import os
import httpx
from backend.core import Advisory, Store, ingest_advisory
from connectors.public import PublicIntelligence

parser = argparse.ArgumentParser()
parser.add_argument("cve")
args = parser.parse_args()
with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as client:
    result = PublicIntelligence(client).cve(args.cve)
with Store(os.getenv("SF_DATABASE", "sqlite:///sentinelforge.db")).transaction() as state:
    eid = ingest_advisory(state, Advisory.model_validate(result["normalized"]), "manual-public-sync")
    state["evidence"][eid]["original_responses"] = result["raw"]
print("Imported public evidence:", eid)
print(result["limitation"])
