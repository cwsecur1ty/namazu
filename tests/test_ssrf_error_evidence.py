"""Response text is not independent evidence of a server-side network request."""
from types import SimpleNamespace

import pytest

from namazu.audit.inputs import _ssrf
from namazu.audit.model import Exchange


class ErrorTextExecutor:
    def __init__(self, response_text, *, control_error="", budget=2):
        self.signature = SimpleNamespace(host="fixture.invalid")
        self.response_text = response_text
        self.control_error = control_error
        self.budget = budget
        self.sent = []

    def affordable(self, count):
        return self.budget >= count

    def send(self, method, url, **kwargs):
        self.sent.append(url)
        return Exchange(label=kwargs["label"], method=method, url=url,
                        status=502, body=self.response_text,
                        error=self.control_error if len(self.sent) == 2 else "")


def baseline(body='{"ok":true}'):
    return Exchange(label="baseline", method="GET", url="https://api.fixture.test/read?url=image",
                    status=200, body=body)


@pytest.mark.parametrize("text", [
    "getaddrinfo ENOTFOUND fixture.invalid",
    "Validation fixture: pretend ECONNREFUSED without making any request",
    "Documentation explains that Max retries exceeded is a possible error",
])
def test_error_wording_cannot_confirm_fetch_or_loopback_access(text):
    executor = ErrorTextExecutor(text)
    item, = _ssrf(executor, baseline(), "GET /read", "url", {})
    result = item.to_dict()
    assert len(executor.sent) == 2
    assert result["severity"] == "low" and result["confidence"] == "possible"
    assert result["assessment"]["verification"] == "observed"
    assert not result["assessment"].get("confirmed_claim")
    assert result["evidence"]["loopback_error_observed"] is True
    assert result["evidence"]["server_side_fetch_confirmed"] is False
    assert result["evidence"]["reached_loopback"] is False
    assert len(result["proof"]) == 3
    assert "No callback was observed" in result["limitations"]
    assert "proves the parameter" not in str(result)


def test_failed_control_keeps_partial_evidence_without_confirming_fetch():
    executor = ErrorTextExecutor("ENOTFOUND", control_error="fixture transport failure")
    item, = _ssrf(executor, baseline(), "GET /read", "url", {})
    assert item.evidence["loopback_error_observed"] is False
    assert len(item.exchanges) == 3 and item.exchanges[-1].error
    assert item.confidence == "possible"


def test_existing_error_or_insufficient_budget_does_not_dispatch():
    executor = ErrorTextExecutor("ENOTFOUND")
    assert _ssrf(executor, baseline("ENOTFOUND"), "GET /read", "url", {}) == []
    executor.budget = 1
    assert _ssrf(executor, baseline(), "GET /read", "url", {}) == []
    assert executor.sent == []
