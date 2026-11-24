import httpx
import pytest
from connectors.public import PublicIntelligence


def test_retry_cache_provenance():
    calls = []
    def respond(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        if "nist.gov" in request.url.host:
            return httpx.Response(200, json={"vulnerabilities": [{"cve": {"descriptions": [{"lang": "en", "value": "Fixture"}], "metrics": {}}}]})
        if "cisa.gov" in request.url.host:
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2024-1234"}]})
        return httpx.Response(200, json={"data": [{"epss": "0.8"}]})
    c = PublicIntelligence(httpx.Client(transport=httpx.MockTransport(respond)), sleep=lambda _: None)
    result = c.cve("CVE-2024-1234")
    assert result["normalized"]["kev"] is True
    assert result["normalized"]["epss"] == 0.8
    c.cve("CVE-2024-1234")
    assert len(calls) == 4
    assert set(result["raw"]) == {"nvd", "kev", "epss"}


def test_osv_pagination_dedup():
    count = 0
    def respond(request):
        nonlocal count
        count += 1
        return httpx.Response(200, json={"vulns": [{"id": "OSV-FIXTURE"}], **({"next_page_token": "two"} if count == 1 else {})})
    result = PublicIntelligence(httpx.Client(transport=httpx.MockTransport(respond))).package("PyPI", "fixture", "1.0")
    assert len(result["records"]) == 1
    assert len(result["raw"]) == 2


@pytest.mark.parametrize("status", [302, 401, 503])
def test_errors_and_redirects_fail_closed(status):
    c = PublicIntelligence(httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(status))), sleep=lambda _: None)
    with pytest.raises(httpx.HTTPStatusError):
        c.fetch("kev")


def test_malformed_and_ssrf():
    c = PublicIntelligence(httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[]))))
    with pytest.raises(ValueError):
        c.fetch("kev")
    with pytest.raises(ValueError):
        c.fetch("http://127.0.0.1")
