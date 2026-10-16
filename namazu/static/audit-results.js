/* Derived audit observations. This module never sends requests or creates findings. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.NamazuAuditResults = api;
})(typeof window !== "undefined" ? window : null, function () {
  "use strict";

  const own = (value, key) => Object.prototype.hasOwnProperty.call(value || {}, key);
  const list = (value) => Array.isArray(value) ? value : [];
  const object = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const text = (value) => typeof value === "string" ? value : value == null ? "" : JSON.stringify(value);
  const keyName = (name) => name.toLowerCase().replace(/[-_]/g, "");
  const VOLATILE_BODY = new Set(["timestamp", "requesttimestamp", "responsetimestamp",
    "requestid", "correlationid", "traceid", "spanid"]);
  const DEFAULT_METADATA_HEADERS = ["date", "request-id", "x-request-id", "correlation-id",
    "x-correlation-id", "trace-id", "x-trace-id", "span-id", "x-span-id", "traceparent",
    "tracestate", "x-amzn-trace-id", "x-cloud-trace-context", "cf-ray", "x-b3-traceid", "x-b3-spanid",
    "fm-correlation-id", "x-iinfo"];
  const metadataHeaderCatalog = Object.freeze(Object.fromEntries(DEFAULT_METADATA_HEADERS.map((name) =>
    [name, name === "date" ? "transport" : name === "x-iinfo" ? "diagnostic" : "correlation"])));
  const SKIPPED = new Set(["blocked", "blocked-prerequisite", "budget-exhausted", "not-applicable", "not-sent", "skipped"]);
  const ERRORS = new Set(["error", "execution-error", "failed"]);

  function normalizePolicy(policy) {
    if (policy != null && (typeof policy !== "object" || Array.isArray(policy)
      || Object.keys(policy).some((name) => name !== "metadata_headers"))) {
      throw new Error("Response comparison requires only a metadata_headers list.");
    }
    const headers = own(policy, "metadata_headers") ? policy.metadata_headers : DEFAULT_METADATA_HEADERS;
    if (!Array.isArray(headers) || headers.some((name) => typeof name !== "string" || !own(metadataHeaderCatalog, name.trim().toLowerCase()))) {
      throw new Error("Response comparison metadata_headers must contain only exact supported metadata header names.");
    }
    return { metadata_headers: [...new Set(headers.map((name) => name.trim().toLowerCase()))].sort() };
  }

  // A small lossless JSON reader: JSON.parse would conflate distinct 64-bit IDs.
  // Duplicate object keys remain raw text rather than silently losing evidence.
  function jsonTree(source) {
    let at = 0;
    const whitespace = () => { while (/[ \t\r\n]/.test(source[at] || "") && at < source.length) at++; };
    function string() {
      const start = at++;
      while (at < source.length) {
        const char = source[at++];
        if (char === "\\") at++;
        else if (char === '"') return JSON.parse(source.slice(start, at));
      }
      throw new Error("Unclosed JSON string");
    }
    function value() {
      whitespace();
      const char = source[at];
      if (char === '"') return ["string", string()];
      if (char === "{") {
        at++;
        whitespace();
        const pairs = [], names = new Set();
        if (source[at] === "}") { at++; return ["object", pairs]; }
        while (at < source.length) {
          whitespace();
          if (source[at] !== '"') throw new Error("Expected JSON key");
          const name = string();
          if (names.has(name)) throw new Error("Duplicate JSON key");
          names.add(name);
          whitespace();
          if (source[at++] !== ":") throw new Error("Expected JSON colon");
          pairs.push([name, value()]);
          whitespace();
          const separator = source[at++];
          if (separator === "}") return ["object", pairs.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)];
          if (separator !== ",") throw new Error("Expected JSON separator");
        }
      } else if (char === "[") {
        at++;
        whitespace();
        const items = [];
        if (source[at] === "]") { at++; return ["array", items]; }
        while (at < source.length) {
          items.push(value());
          whitespace();
          const separator = source[at++];
          if (separator === "]") return ["array", items];
          if (separator !== ",") throw new Error("Expected JSON separator");
        }
      } else {
        const token = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(source.slice(at));
        if (token) { at += token[0].length; return ["literal", token[0]]; }
      }
      throw new Error("Invalid JSON");
    }
    const tree = value();
    whitespace();
    if (at !== source.length) throw new Error("Trailing JSON data");
    return tree;
  }

  function normalizeEnvelope(tree, ignored, protectedKeys, path = "", rootEnvelope = true) {
    if (tree[0] !== "object") return tree;
    return ["object", tree[1].filter(([name, child]) => {
      const scalarMetadata = child[0] === "string" || (child[0] === "literal" && /^-?\d/.test(child[1]));
      if (VOLATILE_BODY.has(keyName(name)) && !protectedKeys.has(keyName(name)) && scalarMetadata) {
        ignored.push(`body${path}/${name}`);
        return false;
      }
      return true;
    }).map(([name, child]) => [name, rootEnvelope && ["meta", "metadata", "context"].includes(keyName(name))
      ? normalizeEnvelope(child, ignored, protectedKeys, `/${name}`, false) : child])];
  }

  function responseParts(exchange) {
    const nested = object(exchange?.response);
    return {
      status: exchange?.status ?? nested.status,
      headers: exchange?.response_headers ?? nested.headers,
      body: own(exchange, "response_body") ? exchange.response_body : nested.body,
      hasBody: own(exchange, "response_body") || own(nested, "body"),
      truncated: Boolean(exchange?.truncated || nested.truncated),
      error: exchange?.error || nested.error || "",
    };
  }

  function canonicalResponse(exchange, protectedKeys = [], policy = null) {
    const response = responseParts(exchange), ignored = [];
    const metadataHeaders = new Set(normalizePolicy(policy).metadata_headers), metadata = [];
    const status = Number.isInteger(response.status) && response.status > 0 ? response.status : null;
    let reason = "";
    if (response.error) reason = "Response unavailable after execution error";
    else if (status === null) reason = "Response status not recorded";
    else if (response.truncated) reason = "Response evidence is truncated";
    else if (!response.hasBody || typeof response.body !== "string") reason = "Complete response body not recorded";
    else if (!response.headers || typeof response.headers !== "object") reason = "Response headers not recorded";
    if (reason) return { comparable: false, key: null, status, ignored, reason };
    let body = ["text", response.body];
    try { body = normalizeEnvelope(jsonTree(response.body), ignored, new Set(protectedKeys.map(keyName))); }
    catch { /* Preserve non-JSON or ambiguous JSON exactly. */ }
    const bytes = typeof TextEncoder !== "undefined" ? new TextEncoder().encode(response.body).length
      : unescape(encodeURIComponent(response.body)).length;
    const headers = Object.entries(response.headers).map(([name, value]) => [name.toLowerCase(), String(value).trim()])
      .filter(([name, value]) => {
        if (metadataHeaders.has(name)) { ignored.push(`header/${name}`); metadata.push([name, value]); return false; }
        if (name === "content-length" && /^\d+$/.test(String(value)) && Number(value) === bytes) {
          ignored.push("header/content-length (verified body length)");
          return false;
        }
        return true;
      }).sort(([a, av], [b, bv]) => a < b ? -1 : a > b ? 1 : text(av).localeCompare(text(bv)));
    return { comparable: true, key: JSON.stringify([status, headers, body]), applicationKey: JSON.stringify([status, body]),
      status, headers, metadata, ignored, reason: "" };
  }

  function headerDifferences(left, right) {
    const before = new Map(left || []), after = new Map(right || []);
    return [...new Set([...before.keys(), ...after.keys()])].sort().filter((name) => before.get(name) !== after.get(name))
      .map((name) => ({ name, baseline: before.get(name) ?? null, response: after.get(name) ?? null,
        category: metadataHeaderCatalog[name] || "response" }));
  }

  function edgeBlockMarkers(exchange) {
    const body = responseParts(exchange).body;
    if (typeof body !== "string" || !/<(?:html|body|iframe)\b/i.test(body) || !/\/_Incapsula_Resource\b/i.test(body)) return [];
    if (/Incapsula\s+incident\s+ID\s*:/i.test(body)) return ["/_Incapsula_Resource", "Incapsula incident ID"];
    return /Request\s+unsuccessful/i.test(body) ? ["/_Incapsula_Resource", "Request unsuccessful"] : [];
  }

  function validationEvidence(exchange, fieldPointer = "") {
    const response = responseParts(exchange);
    if (![400, 422].includes(response.status) || typeof response.body !== "string") return false;
    const field = fieldPointer.split("/").pop().replace(/~1/g, "/").replace(/~0/g, "~").toLowerCase();
    let body;
    try { body = JSON.parse(response.body); } catch { return false; }
    if (!body || typeof body !== "object" || Array.isArray(body) || /^\d+$/.test(field)) return false;
    const matches = (value) => typeof value === "string" && value.toLowerCase().split(/[.\[\]\/]/).filter(Boolean).pop() === field;
    if (body.errors && typeof body.errors === "object" && !Array.isArray(body.errors)) {
      if (Object.entries(body.errors).some(([name, value]) => (!field || matches(name))
        && value && ["string", "object"].includes(typeof value) && Object.keys(value).length)) return true;
    }
    const named = body.field ?? body.parameter ?? body.input;
    const detail = [body.detail, body.message, body.error, body.title].filter((value) => typeof value === "string").join(" ");
    return Boolean(field && matches(named) && /\b(?:validat\w*|invalid|required|must|expected|minimum|maximum|too (?:long|short)|not allowed)\b/i.test(detail));
  }

  function compareResponses(baseline, exchange, options = {}) {
    const left = canonicalResponse(baseline, options.protectedKeys || [], options.policy);
    const right = canonicalResponse(exchange, options.protectedKeys || [], options.policy);
    const markers = edgeBlockMarkers(exchange), comparable = left.comparable && right.comparable;
    const metadataDifferences = comparable ? headerDifferences(left.metadata, right.metadata) : [];
    const meaningfulHeaderDifferences = comparable ? headerDifferences(left.headers, right.headers) : [];
    const beforeRedaction = options.beforeRedaction || exchange?.comparison_before_import_redaction;
    const policyMetadata = new Set(normalizePolicy(options.policy).metadata_headers);
    const retainedNames = list(beforeRedaction?.meaningful_header_names)
      .filter(name => typeof name === "string" && /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$/.test(name))
      .map(name => name.toLowerCase()).filter(name => !policyMetadata.has(name));
    const responseHasRedaction = [baseline, exchange].some(entry => /(?:<redacted>|<credential>|\[redacted\])/i.test(
      JSON.stringify([responseParts(entry).body, responseParts(entry).headers])));
    const redactionDifference = comparable && left.key === right.key && beforeRedaction?.equivalent === false
      && responseHasRedaction && (beforeRedaction.body_status_equivalent === false || retainedNames.length > 0);
    if (redactionDifference) for (const name of [...new Set(retainedNames)]) {
      if (!meaningfulHeaderDifferences.some(item => item.name === name)) meaningfulHeaderDifferences.push({
        name, baseline: null, response: null, category: "response", valuesRedacted: true, source: "before-import-redaction"});
    }
    let classification = "unknown";
    if (right.comparable && markers.length) classification = "edge-block";
    else if (comparable && left.key === right.key && !redactionDifference) classification = [401, 403].includes(right.status) ? "same-denial" : "same-response";
    else if (right.comparable && validationEvidence(exchange, options.fieldPointer)) classification = "validation-observation";
    else if (comparable) classification = "different";
    return { comparable, equivalent: comparable ? left.key === right.key && !redactionDifference : null,
      applicationEquivalent: comparable ? left.applicationKey === right.applicationKey
        && !(redactionDifference && beforeRedaction.body_status_equivalent === false) : null,
      metadataDifferences, meaningfulHeaderDifferences, classification, edgeMarkers: markers,
      redactionDifference, responseStatus: right.status, reason: right.reason || left.reason || (redactionDifference
        ? "A meaningful difference was recorded before import redaction; concealed values cannot be reconstructed." : "") };
  }

  function evidenceOf(receipt) {
    const entries = [...list(receipt?.exchanges)];
    if (receipt?.exchange && !entries.includes(receipt.exchange)) entries.unshift(receipt.exchange);
    return entries.filter((entry) => entry && typeof entry === "object");
  }

  function operationLabel(value) {
    return text(value?.endpoint || value?.operation || value?.operation_id);
  }

  function locationOf(value) {
    if (value?.location) return text(value.location);
    if (value?.family === "body-injection") return "body";
    const pointer = text(value?.field_pointer);
    const first = pointer.split("/")[1];
    return ["query", "header", "cookie", "path"].includes(first) ? first : pointer ? "body" : "";
  }

  function descriptor(value) {
    return JSON.stringify([locationOf(value), text(value?.field_pointer), text(value?.mutation || value?.check)]);
  }

  function protectedNames(value) {
    const pointer = text(value?.field_pointer ?? value?.pointer);
    return pointer ? [pointer.split("/").pop().replace(/~1/g, "/").replace(/~0/g, "~")] : [];
  }

  function totals(cases) {
    const summary = { totalCases: cases.length, plannedCases: 0, executedCases: 0, skippedCases: 0, observedCases: 0,
      pendingCases: 0, errorCases: 0, unknownCases: 0, requestSentCases: 0, evidenceCount: 0,
      sameDenialCases: 0, responseDifferenceCases: 0, validationObservationCases: 0, edgeBlockCases: 0,
      metadataOnlyCases: 0, incompleteCases: 0, blockedCases: 0, budgetExhaustedCases: 0 };
    for (const item of cases) {
      if (item.planned) summary.plannedCases++;
      summary[`${item.state}Cases`]++;
      if (item.requestSent) summary.requestSentCases++;
      summary.evidenceCount += item.exchanges.length;
      if (item.comparison === "same-denial") summary.sameDenialCases++;
      if (item.comparison === "different") summary.responseDifferenceCases++;
      if (item.comparison === "validation-observation") summary.validationObservationCases++;
      if (item.comparison === "edge-block") summary.edgeBlockCases++;
      if (["same-denial", "same-response"].includes(item.comparison) && item.metadataDifferences.length) summary.metadataOnlyCases++;
      if (item.state === "error") summary.incompleteCases++;
      if (item.missingPrerequisites.length || ["blocked", "blocked-prerequisite"].includes(item.status)) summary.blockedCases++;
      if (item.status === "budget-exhausted") summary.budgetExhaustedCases++;
    }
    return summary;
  }

  function buildResults(input) {
    const audit = object(input), plans = list(audit.plans || audit.test_plans);
    const policy = normalizePolicy(audit.response_comparison || audit.responseComparisonPolicy);
    const receipts = list(audit.probes || audit.coverage?.probes);
    const fieldCoverage = list(audit.fieldCoverage || audit.coverage?.fields);
    const baselines = list(audit.baselines || audit.coverage?.baselines);
    const logs = list(audit.log || audit.requests), aliases = new Map(), operationMap = new Map();
    const operations = [], allFields = [], allChecks = [], blockers = new Map();
    let nextCase = 0, nextField = 0;

    function operationFor(value, fallback = "") {
      const raw = operationLabel(value) || fallback || "Operation not recorded";
      const label = aliases.get(raw) || raw;
      if (!operationMap.has(label)) {
        const match = /^([A-Z]+)\s+(.+)$/.exec(label);
        const operation = { id: `operation-${operations.length + 1}`, label, operation: label, operationId: value?.operation_id || "",
          method: match?.[1] || "", path: match?.[2] || "", fields: [], checks: [], checkPlans: [],
          baselineExchange: null, baseline: null, plans: [], summary: null };
        operationMap.set(label, operation);
        operations.push(operation);
      }
      return operationMap.get(label);
    }

    // All aliases must exist before receipts are matched: schema receipts use the
    // operation ID while supplemental receipts and traffic use METHOD /path.
    for (const entry of [...plans, ...baselines]) {
      const plan = entry.test_plan || entry;
      const label = text(entry.endpoint || entry.operation || plan.operation || entry.operation_id);
      if (!label) continue;
      for (const alias of [entry.endpoint, entry.operation, entry.operation_id, plan.operation]) {
        if (alias) aliases.set(text(alias), label);
      }
    }
    for (const entry of plans) {
      const operation = operationFor(entry), plan = entry.test_plan || entry;
      operation.plans.push(entry);
      operation.checkPlans.push(...list(plan.supplemental_checks));
    }
    for (const entry of baselines) {
      const operation = operationFor(entry);
      operation.baseline = entry;
      operation.baselineExchange = entry.exchange || entry.baseline || null;
    }
    for (const entry of logs) {
      if (entry.label !== "baseline") continue;
      const operation = operationFor(entry);
      if (!operation.baselineExchange) operation.baselineExchange = entry;
    }

    function addBlocker(reason, item, operation, pointer = "") {
      if (!reason) return;
      const key = text(reason);
      if (!blockers.has(key)) blockers.set(key, { reason: key, caseIds: [], operations: [], fields: [] });
      const held = blockers.get(key);
      if (item && !held.caseIds.includes(item.id)) held.caseIds.push(item.id);
      if (!held.operations.includes(operation.label)) held.operations.push(operation.label);
      if (pointer && !held.fields.includes(pointer)) held.fields.push(pointer);
    }

    function fieldFor(operation, value) {
      const location = locationOf(value), pointer = text(value.field_pointer);
      let field = operation.fields.find((item) => item.location === location && item.pointer === pointer);
      if (!field) {
        field = { id: `field-${++nextField}`, location, pointer, label: pointer || "(request body)",
          category: value.category || "", cases: [], groups: [], summary: null, coverage: [] };
        operation.fields.push(field);
        allFields.push(field);
      }
      return field;
    }

    function exactEvidenceKey(exchange) {
      return JSON.stringify([exchange.label, exchange.method, exchange.url, exchange.request_body,
        exchange.request_headers, responseParts(exchange)]);
    }
    const logKeys = new Map();
    for (const [index, entry] of logs.entries()) {
      const key = exactEvidenceKey(entry);
      if (!logKeys.has(key)) logKeys.set(key, []);
      logKeys.get(key).push({ logKey: entry.key ?? null, logIndex: index });
    }

    function makeCase(operation, plan, receipt) {
      const record = receipt || plan || {}, exchanges = evidenceOf(receipt);
      const status = text(record.status || record.outcome || record.state || (receipt ? "unknown" : "planned"));
      const missing = [...new Set([...list(record.missing_prerequisites)].map(text).filter(Boolean))];
      const responseModels = exchanges.map((exchange) => canonicalResponse(exchange, protectedNames(record), policy));
      const requestSent = receipt ? Boolean(receipt.request_sent === true || receipt.requests_sent > 0
        || receipt.requests > 0 || exchanges.length) : false;
      const offline = receipt?.reason_code === "offline-inspection";
      const baseline = operation.baselineExchange, baselineModel = canonicalResponse(baseline, protectedNames(record), policy);
      const responseObservations = exchanges.map((exchange) => compareResponses(baseline, exchange,
        { policy, protectedKeys: protectedNames(record), fieldPointer: text(record.field_pointer),
          beforeRedaction: exchange.comparison_before_import_redaction
            || (logKeys.get(exactEvidenceKey(exchange)) || []).map(row => logs[row.logIndex]?.comparison_before_import_redaction)
              .find(marker => marker?.equivalent === false) }));
      const metadataDifferences = responseObservations.flatMap((entry, index) => entry.metadataDifferences.map((difference) => ({ ...difference, exchangeIndex: index })));
      const meaningfulHeaderDifferences = responseObservations.flatMap((entry, index) => entry.meaningfulHeaderDifferences.map((difference) => ({ ...difference, exchangeIndex: index })));
      // These named receipts describe reviews that do not issue their own HTTP
      // request. A generic "completed" label is deliberately insufficient.
      const reviewOnly = Boolean(receipt && !requestSent && !record.field_pointer && !record.location
        && !missing.length && ["completed", "observed"].includes(status));
      let observationKind = "";
      if (reviewOnly) {
        if (record.check === "contract-review") observationKind = "specification";
        else if (record.check === "transport") observationKind = "transport-review";
        else if (record.check === "jwt-offline") observationKind = "offline-token";
        else if (["response-contract", "passive-review", "redirect-downgrade", "framing"].includes(record.check)) {
          if (baseline && responseParts(baseline).status && !responseParts(baseline).error) observationKind = "baseline-review";
        } else if (offline) observationKind = "offline-review";
      }
      if (record.check === "response-contract" && receipt?.reason_code === "all-captured-response-review"
          && !requestSent && !record.field_pointer && ["completed", "inconclusive"].includes(status)) {
        observationKind = "captured-response-review";
      }
      let state = "unknown";
      if (ERRORS.has(status) || exchanges.some((entry) => responseParts(entry).error)) state = "error";
      else if (observationKind) state = "observed";
      else if (requestSent) state = "executed";
      else if (SKIPPED.has(status) || (!receipt && missing.length)) state = "skipped";
      else if (!receipt && audit.running) state = "pending";
      let comparison = "unknown", interpretation = "Execution or response evidence was not recorded.",
        uncertainty = "Coverage cannot be inferred from an aggregate completion label.";
      if (state === "skipped" || state === "pending") {
        comparison = "not-sent";
        interpretation = state === "pending" ? "Planned; awaiting execution." : "No request was sent for this case.";
        uncertainty = state === "pending" ? "No response is available yet." : "Input handling was not observed.";
      } else if (state === "error") {
        interpretation = "An execution error prevented this case from completing.";
        uncertainty = "Input handling and security impact remain unestablished.";
      } else if (observationKind === "specification") {
        comparison = "specification";
        interpretation = "Specification observation: the receipt records completed contract review, with no request sent.";
        uncertainty = "Static declarations do not establish server behaviour or security impact.";
      } else if (observationKind === "captured-response-review") {
        comparison = "captured-response-review";
        interpretation = "The receipt records offline review of retained responses; no additional requests were sent.";
        uncertainty = "Individual response review records distinguish contract mismatches, unavailable contracts, edge blocks and incomplete captures. Review execution does not establish complete application coverage or security impact.";
      } else if (observationKind === "baseline-review") {
        comparison = "baseline-review";
        interpretation = "The receipt records review of the captured baseline response; this check sent no additional request.";
        uncertainty = "This is baseline analysis, not a mutation or replay. It does not establish downstream validation or security impact.";
        if (!baselineModel.comparable) uncertainty += ` ${baselineModel.reason}.`;
      } else if (observationKind === "transport-review") {
        comparison = "transport-review";
        interpretation = "The receipt records completed transport review, with no additional HTTP request counted.";
        uncertainty = "This receipt alone does not establish certificate or protocol verification, or demonstrated security impact.";
      } else if (observationKind === "offline-token") {
        comparison = "offline";
        interpretation = "Offline inspection recorded; no token replay or endpoint request is implied.";
        uncertainty = "Server acceptance and security impact require separate evidence.";
      } else if (observationKind === "offline-review") {
        comparison = "offline";
        interpretation = "The receipt records offline review; no endpoint request was sent by this check.";
        uncertainty = "This review does not by itself establish observed endpoint behaviour or security impact.";
      } else if (responseObservations.length && responseObservations.every((entry) => entry.classification === "edge-block")) {
        comparison = "edge-block";
        interpretation = "Edge block page observed: explicit Incapsula body markers identify this response separately from an application denial.";
        uncertainty = "Downstream handling is unknown. HTTP 403 alone does not identify an edge block, and the page does not establish application validation or security impact.";
      } else if (responseObservations.length && responseObservations.every((entry) => entry.classification === "validation-observation")) {
        comparison = "validation-observation";
        interpretation = "Field-specific validation response observed: the rejection identifies this input and its validation requirement.";
        uncertainty = "This validation rejection is an observation, not automatically a security lead. The processing layer and security impact are not established.";
      } else if (exchanges.length && baselineModel.comparable && responseModels.every((model) => model.comparable)) {
        if (responseObservations.every((entry) => entry.equivalent === true)) {
          comparison = [401, 403].includes(baselineModel.status) ? "same-denial" : "same-response";
          interpretation = comparison === "same-denial"
            ? "Same denial as baseline; downstream handling unknown."
            : "The application response and meaningful response headers match the baseline.";
          if (metadataDifferences.length) interpretation += " Transport or diagnostic metadata differs; originals are retained.";
          uncertainty = "This does not establish downstream validation, a validation pass, or security impact.";
        } else {
          comparison = "different";
          interpretation = "Response difference observed; this is a lead for review.";
          uncertainty = "The processing layer, causality, and security impact are not established by this difference.";
        }
      } else if (exchanges.length || requestSent) {
        interpretation = "Request execution was recorded; complete baseline comparison is unavailable.";
        uncertainty = !baselineModel.comparable ? `Baseline: ${baselineModel.reason}.`
          : responseModels.find((model) => !model.comparable)?.reason || "Exact response evidence was not recorded.";
        uncertainty += " Downstream validation and security impact remain unknown.";
      }
      // The engine compares before credential redaction. Different cookies or
      // reflected credentials may therefore look identical in retained evidence.
      const recordedDifference = ["field-specific-response-observed", "field-response-observed", "field-specific-response"].includes(status)
        || ["response-difference", "response-difference-lead", "field-response-difference-lead", "unexpected-error-response-lead"].includes(receipt?.reason_code);
      const recordedDenial = ["same-denial", "same-denial-as-baseline"].includes(status)
        || ["same-denial-as-baseline", "downstream-handling-unknown"].includes(receipt?.reason_code);
      let comparisonDiscrepancy = false;
      const responseHasRedaction = [baseline, ...exchanges].some((entry) => /(?:<redacted>|<credential>|\[redacted\])/i.test(
        JSON.stringify([responseParts(entry).body, responseParts(entry).headers])));
      const metadataExplainsDifference = metadataDifferences.length > 0 && !responseHasRedaction;
      if (recordedDifference && ["same-denial", "same-response"].includes(comparison) && !metadataExplainsDifference) {
        comparison = "different";
        comparisonDiscrepancy = true;
        interpretation = "The probe receipt records a response difference; this remains a lead for review.";
        uncertainty = "Retained redacted exchanges look equivalent. Redaction or the recorded comparison policy may hide the difference; its exact nature, processing layer and security impact remain unknown.";
      } else if (recordedDenial && comparison === "different") {
        comparisonDiscrepancy = true;
        interpretation = "Retained exchanges differ, while the probe receipt classified the response as the same denial. Review this discrepancy.";
        uncertainty = "Redaction or an older comparison policy may explain the disagreement. A difference in retained evidence does not establish downstream validation, the processing layer, or security impact.";
      }
      if (responseObservations.some(entry => entry.redactionDifference)) {
        comparisonDiscrepancy = true;
        if (comparison === "different") interpretation = "The import review recorded a meaningful response difference before display redaction; review the retained comparison evidence.";
        uncertainty += " Retained redacted exchanges look equivalent, but a pre-redaction difference was recorded. Concealed values cannot be reconstructed; no processing layer or security impact is established.";
      }
      const partial = requestSent && (SKIPPED.has(status) || missing.length > 0);
      if (partial) {
        interpretation += " The probe stopped before all of its work completed.";
        uncertainty += " Remaining requests or prerequisites were not satisfied.";
      }
      const item = { id: `case-${++nextCase}`, probeId: text(record.id), operation: operation.label,
        location: locationOf(record), pointer: text(record.field_pointer), mutation: text(record.mutation || record.check || "Case not named"),
        family: text(record.family), category: text(record.category), status, state, planned: Boolean(plan || own(receipt, "planned_requests")),
        conditional: Boolean(plan?.conditional), plannedRequests: plan?.planned_requests ?? receipt?.planned_requests ?? null,
        requestSent, partial, reasonCode: text(record.reason_code), reason: text(record.reason),
        prerequisite: text(record.prerequisite || plan?.prerequisite), missingPrerequisites: missing,
        comparison, comparisonDiscrepancy, observationKind, interpretation, uncertainty, recordedObservation: text(record.observation || record.reason),
        responseObservations, metadataDifferences, meaningfulHeaderDifferences,
        derivedReasonCode: comparison === "validation-observation" ? "field-validation-observed"
          : comparison === "edge-block" ? "explicit-edge-block-page" : comparison === "same-denial" ? "same-denial-as-baseline"
          : state === "error" ? "incomplete-execution-error" : comparison === "different" ? "response-difference-observed" : comparison,
        reclassifiedMetadataDifference: recordedDifference && metadataExplainsDifference && ["same-denial", "same-response"].includes(comparison),
        responseStatuses: [...new Set(responseModels.map((model) => model.status).filter((value) => value !== null))],
        ignoredMetadata: [...new Set(responseModels.flatMap((model) => model.ignored))],
        exchanges, evidence: exchanges.map((exchange) => ({ exchange, ...(logKeys.get(exactEvidenceKey(exchange))?.[0]
          || { logKey: null, logIndex: null }) })), baselineExchange: baseline, plan: plan || null, receipt: receipt || null };
      const fieldCase = Boolean(item.pointer || item.location);
      if (fieldCase) fieldFor(operation, record).cases.push(item);
      else { operation.checks.push(item); allChecks.push(item); }
      for (const reason of missing) addBlocker(reason, item, operation, item.pointer);
      if (["blocked", "blocked-prerequisite", "budget-exhausted", "skipped"].includes(status) || state === "error") {
        addBlocker(item.reasonCode || status, item, operation, item.pointer);
      }
      if (state === "unknown") addBlocker("execution-receipt-or-evidence-not-recorded", item, operation, item.pointer);
      return item;
    }

    const candidates = [];
    for (const entry of plans) {
      const operation = operationFor(entry), plan = entry.test_plan || entry;
      for (const probe of [...list(plan.probes), ...list(plan.supplemental_probes)]) {
        if (candidates.some((held) => held.operation === operation && (probe.id
          ? held.plan.id === probe.id : !held.plan.id && descriptor(held.plan) === descriptor(probe)))) continue;
        candidates.push({ operation, plan: probe, receipt: null });
      }
      for (const check of list(plan.supplemental_checks)) {
        for (const reason of list(check.missing_prerequisites)) addBlocker(reason, null, operation);
      }
      if (entry.error) addBlocker(`planning-error: ${text(entry.error)}`, null, operation);
    }
    for (const receipt of receipts) {
      const operation = operationFor(receipt);
      const candidate = candidates.find((held) => !held.receipt && held.operation === operation
        && (receipt.id ? held.plan.id === receipt.id : descriptor(held.plan) === descriptor(receipt)));
      if (candidate) candidate.receipt = receipt;
      else candidates.push({ operation, plan: null, receipt });
    }
    for (const candidate of candidates) makeCase(candidate.operation, candidate.plan, candidate.receipt);
    for (const coverage of fieldCoverage) {
      const operation = operationFor(coverage), field = fieldFor(operation, coverage);
      field.coverage.push(coverage);
      for (const reason of list(coverage.missing_prerequisites)) addBlocker(reason, null, operation, field.pointer);
      if (!field.cases.length) addBlocker("individual-case-records-not-recorded", null, operation, field.pointer);
    }
    for (const operation of operations) {
      for (const field of operation.fields) {
        const groups = new Map();
        for (const item of field.cases) {
          const responses = item.exchanges.map((exchange) => canonicalResponse(exchange, protectedNames(item), policy));
          const key = !item.comparisonDiscrepancy && responses.length && responses.every((model) => model.comparable)
            ? JSON.stringify([item.state, item.comparison, responses.map((model) => model.key)])
            : `individual:${item.id}`;
          if (!groups.has(key)) groups.set(key, { id: `${field.id}-group-${groups.size + 1}`, state: item.state,
            status: item.status, comparison: item.comparison, interpretation: item.interpretation,
            uncertainty: item.uncertainty, responseStatuses: item.responseStatuses, caseIds: [], cases: [] });
          const group = groups.get(key);
          group.caseIds.push(item.id);
          group.cases.push(item);
        }
        field.groups = [...groups.values()];
        field.summary = totals(field.cases);
        field.summary.individualRecordsMissing = !field.cases.length && field.coverage.length > 0;
      }
      operation.summary = totals(operation.fields.flatMap((field) => field.cases));
      operation.checkSummary = totals(operation.checks);
    }
    const summary = totals(allFields.flatMap((field) => field.cases));
    summary.operationCount = operations.length;
    summary.fieldCount = allFields.length;
    summary.operationCheckCases = allChecks.length;
    summary.operationChecks = totals(allChecks);
    summary.blockers = [...blockers.values()].map((entry) => ({ ...entry, caseCount: entry.caseIds.length }));
    summary.requestBreakdown = { ...object(audit.requestBreakdown || audit.scope?.request_breakdown) };
    summary.totalRequests = typeof audit.requests === "number" ? audit.requests : audit.scope?.requests_sent ?? null;
    summary.logEntries = logs.length;
    summary.logTruncated = Boolean(audit.logTruncated || audit.requests_truncated);
    summary.fieldRecordsMissing = summary.unknownCases > 0 || allFields.some((field) => field.summary.individualRecordsMissing);
    summary.operationCheckRecordsMissing = summary.operationChecks.unknownCases > 0
      || (!receipts.length && Object.values(object(audit.coverage)).some((entry) => entry?.check
        || (Array.isArray(entry) && entry.some((item) => item?.check))));
    summary.individualRecordsMissing = summary.fieldRecordsMissing || summary.operationCheckRecordsMissing;
    // Count the retained request log once. Probe receipts may repeat a captured
    // request across aggregate and individual checks, so summing them is wrong.
    const evidenceFields = new Map(), evidenceDiscrepancies = new Set();
    for (const item of [...allFields.flatMap((field) => field.cases), ...allChecks]) {
      for (const captured of item.exchanges) {
        if (item.pointer) evidenceFields.set(exactEvidenceKey(captured), item.pointer);
        if (item.comparisonDiscrepancy && item.comparison === "different") evidenceDiscrepancies.add(exactEvidenceKey(captured));
      }
    }
    const emptyResponses = () => ({ requests: 0, baselineResponses: 0, applicationDenialResponses: 0,
      sameDenialResponses: 0, validationResponses: 0, edgeBlockResponses: 0, incompleteResponses: 0,
      differentResponses: 0, sameResponseResponses: 0, unknownResponses: 0,
      metadataDifferenceResponses: 0, meaningfulHeaderDifferenceResponses: 0, comparisonDiscrepancyResponses: 0 });
    const responseSummary = { source: "retained-request-log", logComplete: !summary.logTruncated
      && (summary.totalRequests === null || logs.length === summary.totalRequests),
      total: emptyResponses(), endpoint: emptyResponses(), inventory: emptyResponses(), unassigned: emptyResponses() };
    for (const captured of logs) {
      const operation = operationMap.get(aliases.get(operationLabel(captured)) || operationLabel(captured));
      const isInventory = captured.endpoint === "surface sweep" || /^(?:inventory\s|404 calibration)/i.test(text(captured.label));
      const bucket = isInventory ? responseSummary.inventory : operation ? responseSummary.endpoint : responseSummary.unassigned;
      const comparison = compareResponses(operation?.baselineExchange, captured, { policy,
        fieldPointer: evidenceFields.get(exactEvidenceKey(captured)) || "" });
      const isBaseline = captured.label === "baseline";
      const comparisonDiscrepancy = !isBaseline && (comparison.redactionDifference
        || evidenceDiscrepancies.has(exactEvidenceKey(captured)) && ["same-denial", "same-response"].includes(comparison.classification));
      const complete = canonicalResponse(captured, [], policy).comparable;
      for (const held of [responseSummary.total, bucket]) {
        held.requests++;
        if (isBaseline) held.baselineResponses++;
        if (!complete) held.incompleteResponses++;
        else if (comparisonDiscrepancy) {
          held.unknownResponses++;
          held.comparisonDiscrepancyResponses++;
        }
        else if (comparison.classification === "edge-block") held.edgeBlockResponses++;
        else if (comparison.classification === "validation-observation") held.validationResponses++;
        else if (comparison.classification === "same-denial") {
          held.applicationDenialResponses++;
          if (!isBaseline) held.sameDenialResponses++;
        } else if (comparison.classification === "same-response") held.sameResponseResponses++;
        else if (comparison.classification === "different") held.differentResponses++;
        else held.unknownResponses++;
        if (comparison.metadataDifferences.length) held.metadataDifferenceResponses++;
        if (comparison.meaningfulHeaderDifferences.length) held.meaningfulHeaderDifferenceResponses++;
      }
    }
    summary.responseSummary = responseSummary;
    return { version: 2, summary, operations, responseComparisonPolicy: policy,
      comparisonPolicy: "Application status and body are compared separately from transport, correlation and diagnostic metadata. Only exact configured metadata header names, explicit envelope timestamps and request/correlation/trace IDs, and a verified body-derived Content-Length are ignored for equivalence. Security-relevant and all other response headers remain compared; their changes are listed separately. Originals remain in the evidence. Explicit Incapsula body markers identify edge block pages; HTTP 403 alone does not. Incomplete responses are never grouped as equivalent.",
      accountingNote: "Counts are individual input cases, not requests. Each case has one state: executed, skipped, pending, error, observed, or unknown. Observed is reserved for explicitly recorded offline or baseline review. Planned is a separate flag; errors may include attempted requests. Operation-level checks and conditional family plans are separate. Missing receipts never imply completion." };
  }

  function exportResults(audit) {
    const results = buildResults(audit), receipts = list(audit.probes || audit.coverage?.probes);
    const logs = list(audit.log || audit.requests), baselines = list(audit.baselines || audit.coverage?.baselines);
    const plans = list(audit.plans || audit.test_plans);
    function baselineSource(exchange) {
      if (!exchange) return null;
      const baselineIndex = baselines.findIndex((entry) => entry.exchange === exchange || entry.baseline === exchange);
      if (baselineIndex >= 0) return `#/coverage/baselines/${baselineIndex}/${baselines[baselineIndex].exchange === exchange ? "exchange" : "baseline"}`;
      const logIndex = logs.indexOf(exchange);
      return logIndex >= 0 ? `#/requests/${logIndex}` : null;
    }
    function planSource(probe) {
      if (!probe) return null;
      for (const [index, entry] of plans.entries()) {
        const plan = entry.test_plan || entry;
        for (const collection of ["probes", "supplemental_probes"]) {
          const probeIndex = list(plan[collection]).indexOf(probe);
          if (probeIndex >= 0) return `#/test_plans/${index}/${entry.test_plan ? "test_plan/" : ""}${collection}/${probeIndex}`;
        }
      }
      return null;
    }
    function compactCase(item) {
      const { exchanges, evidence, baselineExchange, receipt, plan, ...display } = item;
      const receiptIndex = receipts.indexOf(receipt);
      return { ...display, receiptSource: receiptIndex >= 0 ? `#/coverage/probes/${receiptIndex}` : null,
        planSource: planSource(plan), baselineEvidence: baselineSource(baselineExchange),
        evidence: evidence.map((entry) => {
          let source = null;
          if (receiptIndex >= 0) {
            if (receipt.exchange === entry.exchange) source = `#/coverage/probes/${receiptIndex}/exchange`;
            else {
              const exchangeIndex = list(receipt.exchanges).indexOf(entry.exchange);
              if (exchangeIndex >= 0) source = `#/coverage/probes/${receiptIndex}/exchanges/${exchangeIndex}`;
            }
          }
          if (!source && entry.logIndex !== null) source = `#/requests/${entry.logIndex}`;
          return { source, logIndex: entry.logIndex };
        }) };
    }
    return { version: results.version, summary: results.summary, comparisonPolicy: results.comparisonPolicy,
      responseComparisonPolicy: results.responseComparisonPolicy,
      accountingNote: results.accountingNote, operations: results.operations.map((operation) => ({
        id: operation.id, operation: operation.label, operationId: operation.operationId,
        method: operation.method, path: operation.path, summary: operation.summary,
        baselineEvidence: baselineSource(operation.baselineExchange),
        fields: operation.fields.map((field) => ({ id: field.id, location: field.location, pointer: field.pointer,
          category: field.category, summary: field.summary,
          groups: field.groups.map(({ cases, ...group }) => group), cases: field.cases.map(compactCase) })),
        checkSummary: operation.checkSummary, checks: operation.checks.map(compactCase),
        checkPlans: operation.checkPlans,
      })) };
  }

  return { buildResults, canonicalResponse, compareResponses, exportResults, normalizePolicy,
    metadataHeaderCatalog, defaultMetadataHeaders: [...DEFAULT_METADATA_HEADERS] };
});
