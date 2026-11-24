"""Fixed-destination public intelligence clients. No user-supplied URLs or redirects."""
import time

import httpx

from backend.core import Advisory, Strict
from pydantic import Field


class CVE(Strict):
    id: str = Field(pattern=r"^CVE-\d{4}-\d{4,12}$")


URLS = {
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://api.first.org/data/v1/epss",
    "osv": "https://api.osv.dev/v1/query",
}


class PublicIntelligence:
    def __init__(self, client=None, sleep=time.sleep):
        self.client = client or httpx.Client(timeout=15, follow_redirects=False, trust_env=False)
        self.sleep = sleep
        self.cache = {}

    def fetch(self, source, params=None, body=None):
        if source not in URLS:
            raise ValueError("Unknown source")
        key = (source, repr(params), repr(body))
        cached = self.cache.get(key)
        if cached and time.time() - cached[0] < 300:
            return cached[1]
        for attempt in range(3):
            try:
                with self.client.stream("POST" if body is not None else "GET", URLS[source], params=params, json=body) as r:
                    if r.status_code in (429, 500, 502, 503, 504):
                        if attempt == 2:
                            r.raise_for_status()
                        self.sleep(min(float(r.headers.get("Retry-After", 2 ** attempt)), 10))
                        continue
                    r.raise_for_status()
                    raw = bytearray()
                    for chunk in r.iter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 8_000_000:
                            raise ValueError("Source response exceeds byte budget")
                    import json
                    data = json.loads(raw)
                    if not isinstance(data, dict):
                        raise ValueError("Expected source object")
                    self.cache[key] = (time.time(), data)
                    return data
            except httpx.TransportError:
                if attempt == 2:
                    raise
                self.sleep(2 ** attempt)
        raise ValueError("Source retry exhausted")

    def cve(self, identifier):
        CVE(id=identifier)
        nvd = self.fetch("nvd", {"cveId": identifier})
        kev = self.fetch("kev")
        epss = self.fetch("epss", {"cve": identifier})
        record = nvd["vulnerabilities"][0]["cve"]
        metrics = record.get("metrics", {})
        candidates = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        description = next((d["value"] for d in record["descriptions"] if d["lang"] == "en"), "No English description")
        advisory = Advisory(id=identifier, source="NVD+CISA+FIRST", description=description[:10000],
                            package="", cvss=candidates[0]["cvssData"]["baseScore"] if candidates else None,
                            kev=any(v["cveID"] == identifier for v in kev["vulnerabilities"]),
                            epss=float(epss["data"][0]["epss"]) if epss["data"] else None)
        return {"normalized": advisory.model_dump(), "raw": {"nvd": nvd, "kev": kev, "epss": epss},
                "fetched": time.time(), "limitation": "CPE matching is not implemented; analyst must correlate product."}

    def package(self, ecosystem, name, version):
        if ecosystem not in ("PyPI", "npm") or not name or len(name) > 150 or len(version) > 80:
            raise ValueError("Supported ecosystems: PyPI and npm; bounded package coordinates required")
        body = {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
        records = []
        pages = []
        for _ in range(10):
            data = self.fetch("osv", body=body)
            pages.append(data)
            records.extend(data.get("vulns", []))
            if not data.get("next_page_token"):
                return {"raw": pages, "records": list({r["id"]: r for r in records}.values()), "fetched": time.time()}
            body = {**body, "page_token": data["next_page_token"]}
        raise ValueError("OSV page budget exceeded; result is incomplete")
