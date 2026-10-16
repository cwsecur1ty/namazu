"""Read captured exchanges without replaying them or replacing their evidence."""
from __future__ import annotations

from .model import Exchange


def captured_records(exchanges, evidence_root="/log"):
    """Yield (exchange, reference) pairs, retaining full bodies when available."""
    for index, item in enumerate(exchanges or []):
        reference = {"pointer": f"{evidence_root}/{index}", "index": index}
        if isinstance(item, Exchange):
            yield item, reference
            continue
        if not isinstance(item, dict):
            continue
        body = item.get("response_body")
        full_body = isinstance(body, str)
        if not full_body:
            body = str(item.get("body_excerpt") or "")
        status = item.get("status")
        status = status if isinstance(status, int) and not isinstance(status, bool) else 0
        length = item.get("body_length")
        # body_length describes the original body, while redaction can shorten
        # a fully retained response_body. Only infer missing bytes for excerpts.
        truncated = bool(item.get("truncated")) or (not full_body and isinstance(length, int) and length > len(body))
        exchange = Exchange(
            label=str(item.get("label") or "captured response"),
            method=str(item.get("method") or "GET").upper(), url=str(item.get("url") or ""),
            request_headers=item.get("request_headers") or {}, request_body=item.get("request_body"),
            status=status, headers=item.get("response_headers") or item.get("headers") or {},
            body=body, error=str(item.get("error") or ""), truncated=truncated,
            identity=str(item.get("identity") or "unknown"), mutating=bool(item.get("mutating")),
        )
        for key in ("seq", "seqGlobal", "endpoint"):
            if key in item:
                reference[key] = item[key]
        if isinstance(item.get("evidence_ref"), dict):
            reference = {**reference, **item["evidence_ref"]}
        yield exchange, reference
