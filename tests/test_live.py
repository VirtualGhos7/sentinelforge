import json
import httpx
import pytest
from backend.core import Denied
from agents.live import run


def client_for(tool="investigate", assets=None):
    calls = []
    def handler(request):
        payload = json.loads(request.content)
        calls.append(payload)
        if len(calls) == 1:
            return httpx.Response(200, json={"output": [{"type": "function_call", "name": tool, "arguments": "{}", "call_id": "c1"}]})
        assert payload["input"][-1]["type"] == "function_call_output"
        result = {"summary": "Uncertain synthetic exposure", "asset_ids": assets or ["edge"], "evidence_ids": [],
                  "confidence": "low", "missing_evidence": ["Version corroboration"]}
        return httpx.Response(200, json={"output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps(result)}]}],
                                        "usage": {"input_tokens": 100, "output_tokens": 50}})
    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_live_tool_protocol_mock_only():
    client, calls = client_for()
    result = run(client, "test-placeholder", "test-model", "investigator", 1, 4)
    assert len(calls) == 2
    assert result["usage"]["output_tokens"] == 50
    assert result["assessment"]["asset_ids"] == ["edge"]


@pytest.mark.parametrize("tool,assets", [("execute", None), ("investigate", ["invented-asset"])])
def test_live_model_cannot_override_gateway(tool, assets):
    client, _ = client_for(tool, assets)
    with pytest.raises(Denied):
        run(client, "test-placeholder", "test-model", "investigator", 1, 4)


def test_live_budget_denied_before_network():
    client, calls = client_for()
    with pytest.raises(Denied):
        run(client, "test-placeholder", "test-model", "investigator", 100, 100)
    assert not calls
