"""Per-probe execution receipts; a returned empty list is never a passing check."""
from __future__ import annotations

from contextlib import contextmanager

from .response_compare import compare_responses, safe_comparison
from .transport import BudgetExhausted, MutationRefused, RateLimited


def pointer(field) -> str:
    """Render a point as an escaped JSON pointer without including its value."""
    if field is None:
        return ""
    parts = getattr(field, "pointer", None)
    if parts is None:
        parts = [getattr(field, "location", "query"), str(field)]
    return "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1")
                            for part in parts)


def successful(baseline) -> bool:
    """An expected denial is still not a positive control."""
    return bool(baseline and baseline.ok and 200 <= baseline.status < 300
                and getattr(baseline, "positive_control", True))


@contextmanager
def track(executor, check: str, *, family: str, baseline=None, endpoint: str = "",
          field=None, prerequisite: str = "HTTP response; profile permits this request",
          missing=(), offline: bool = False, applicable: bool = True):
    """Track a single independently gated probe, including early returns.

    Callers can set ``reason_code``/``reason`` for a more specific early exit.
    Records contain redacted exchanges, never live credentials or field values.
    """
    if not hasattr(executor, "probe_results"):
        executor.probe_results = []
    start = len(getattr(executor, "exchanges", []))
    declined = getattr(executor, "budget_declines", 0)
    receipt = {
        "family": family, "check": check, "operation": endpoint,
        "field_pointer": pointer(field), "prerequisite": prerequisite,
        "location": getattr(field, "location", "query") if field is not None else "",
        "status": "blocked-prerequisite" if applicable else "not-applicable",
        "reason_code": "prerequisite-not-met" if applicable else "not-applicable",
        "request_sent": False, "requests": 0,
        "missing_prerequisites": list(missing), "exchanges": [],
    }
    failed = False
    try:
        yield receipt
    except BudgetExhausted:
        receipt.update(status="budget-exhausted", reason_code="request-budget-exhausted")
        failed = True
        raise
    except MutationRefused as exc:
        receipt.update(status="blocked-prerequisite", reason_code=(
            "rate-limit-observed" if isinstance(exc, RateLimited) else "request-not-permitted"))
        failed = True
        raise
    except Exception as exc:
        # The exception text can contain credentials or a whole request.
        receipt.update(status="execution-error", reason_code="probe-exception",
                       error_type=type(exc).__name__)
        failed = True
        raise
    finally:
        exchanges = getattr(executor, "exchanges", [])[start:]
        receipt.update(request_sent=bool(exchanges), requests=len(exchanges),
                       exchanges=[exchange.to_dict() for exchange in exchanges])
        if not failed and applicable and not receipt["missing_prerequisites"]:
            if any(exchange.error for exchange in exchanges):
                receipt.update(status="execution-error", reason_code="request-error",
                               reason="Incomplete test: a request failed or timed out; downstream handling is unknown.")
            elif getattr(executor, "budget_declines", 0) > declined:
                receipt.update(status="budget-exhausted", reason_code="request-budget-exhausted")
            elif exchanges:
                field_name = pointer(field).rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")
                comparisons = [compare_responses(exchange, baseline, protected_keys=(field_name,),
                                                policy=getattr(executor, "comparison_policy", None), field_name=field_name)
                               for exchange in exchanges] if baseline is not None else []
                receipt["comparisons"] = [safe_comparison(comparison, exchange, baseline)
                                          for comparison, exchange in zip(comparisons, exchanges, strict=False)]
                categories = {item["classification"] for item in comparisons}
                receipt["observation_categories"] = sorted(categories)
                same_denial = (baseline is not None and baseline.status in (401, 403)
                               and categories == {"same-denial"})
                differs = any(comparison["equivalent"] is False for comparison in comparisons)
                if same_denial:
                    receipt.update(status="same-denial", reason_code="same-denial-as-baseline",
                                   reason="Same denial as baseline; downstream handling is unknown.")
                elif categories == {"edge-block"}:
                    receipt.update(status="edge-block-observed", reason_code="edge-block-page",
                                   reason="Explicit Incapsula HTML block-page markers were observed; downstream application handling is unknown.")
                elif "validation-observation" in categories and categories <= {"validation-observation", "same-response", "same-denial"}:
                    receipt.update(status="field-response-observed", reason_code="field-validation-observed",
                                   reason="A response explicitly rejects the mutated field with a validation error. This is a validation observation; the processing layer and security impact remain unproven.")
                elif categories and categories <= {"validation-observation", "edge-block", "same-response", "same-denial"}:
                    receipt.update(status="request-sent", reason_code="mixed-response-observations",
                                   reason="The recorded exchanges contain different response categories; inspect each exchange. Edge blocks and matching denials leave downstream handling unknown.")
                elif field is not None and differs:
                    receipt.update(status="field-response-observed", reason_code="response-difference",
                                   reason="A field-specific response difference is a lead; it does not identify the processing layer.")
                elif any(not comparison["comparable"] for comparison in comparisons):
                    receipt.update(status="request-sent", reason_code="response-comparison-unavailable",
                                   reason="The captured response is incomplete; comparison with the baseline and downstream handling remain unknown.")
                else:
                    receipt.update(status="request-sent", reason_code="request-sent")
            elif offline:
                receipt.update(status="observed", reason_code="offline-inspection")
            elif receipt["reason_code"] == "prerequisite-not-met":
                receipt.update(status="not-applicable", reason_code="probe-not-applicable",
                               reason="No request was sent; this probe had no applicable input or oracle.")
        executor.probe_results.append(receipt)


def run(executor, check, callback, **kwargs):
    """Execute and record one probe, or record every supplied missing prerequisite."""
    with track(executor, check, **kwargs) as receipt:
        if receipt["missing_prerequisites"] or receipt["status"] == "not-applicable":
            receipt["reason"] = "; ".join(receipt["missing_prerequisites"])
            return []
        result = callback()
        return result
