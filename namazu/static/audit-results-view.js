/* Inspection of recorded test cases. This view never sends requests or creates findings. */
(function (root) {
  "use strict";
  const expanded = new Map();
  const loadedPages = new Map();

  function stableKey(value) {
    let hash = 2166136261;
    for (const character of String(value)) hash = Math.imul(hash ^ character.charCodeAt(0), 16777619);
    return (hash >>> 0).toString(36);
  }

  function runKey(audit) {
    const first = (audit.log || audit.requests || [])[0] || {};
    return stableKey(JSON.stringify([audit.context?.run_id, audit.startedAt || audit.generated_at,
      audit.context?.base_url || audit.api?.base_url, first.url || first.request?.url, first.started_at || first.timestamp]));
  }

  function node(tag, className, text) {
    const result = document.createElement(tag);
    if (className) result.className = className;
    if (text !== undefined && text !== null) result.textContent = String(text);
    return result;
  }

  function counts(summary = {}) {
    return `${summary.plannedCases || 0} planned · ${summary.executedCases || 0} executed · `
      + `${summary.skippedCases || 0} skipped`
      + (summary.errorCases ? ` · ${summary.errorCases} execution errors` : "")
      + (summary.pendingCases ? ` · ${summary.pendingCases} pending` : "")
      + (summary.unknownCases ? ` · ${summary.unknownCases} missing receipts` : "");
  }

  function disclosure(key, title, className, open = false) {
    const details = node("details", className);
    const saved = root.NamazuDesktop?.evidenceExpansion?.() || {};
    details.open = expanded.has(key) ? expanded.get(key) : Object.prototype.hasOwnProperty.call(saved, key) ? saved[key] === true : open;
    const summary = node("summary");
    summary.append(title);
    details.append(summary);
    details.addEventListener("toggle", () => { expanded.set(key, details.open); root.NamazuDesktop?.setEvidenceExpansion?.(key, details.open); });
    return details;
  }

  function comparisonLabel(value) {
    return ({"same-denial": "Same application denial", "same-response": "Equivalent to baseline",
      different: "Response changed; review evidence", unknown: "Comparison unavailable",
      "validation-observation": "Validation rejected this input", "edge-block": "Blocked at the edge",
      "not-sent": "Not sent", offline: "Offline observation", specification: "Specification observation",
      "baseline-review": "Baseline evidence reviewed", "captured-response-review": "Captured responses reviewed",
      "transport-review": "Transport observation"})[value] || value || "Comparison unavailable";
  }

  function executionLabel(item) {
    const outcome = ({"blocked-prerequisite": "blocked prerequisite", "budget-exhausted": "budget exhausted",
      "not-applicable": "not applicable", "execution-error": "incomplete test"})[item.status];
    return `${item.state || "unknown"}${outcome ? ` (${outcome})` : ""}`
      + (item.requestSent ? "; request sent" : "");
  }

  function responseLabel(exchange) {
    const error = exchange.error || exchange.response?.error;
    if (error) return /timeout|timed?\s*out/i.test(error) ? "No response before timeout" : "Request did not complete";
    return `HTTP ${exchange.status ?? exchange.response?.status ?? "unknown"}`;
  }

  function blockerAction(reason, {status, operation} = {}) {
    const text = String(reason || "");
    if (status === "not-applicable" || /not-applicable|GET-only|only applies to GET/i.test(text)
      || /^(?:GET method|read-only-method)$/i.test(text.trim())) return null;
    const choices = [
      [/second.identity|permission.matrix|expected.permission|resource.permission|distinct.identity|boundary.definition/i, "configure-permissions", "Configure identities and permissions"],
      [/resource.and.content.assertions|business.assertion|success.assertion|expectation/i, "define-success", "Define what success looks like"],
      [/positive.control|baseline|test.data|saved.request|request.body|placeholder|required.field/i, "supply-test-data", "Prepare a successful baseline"],
      [/identity|credential|authentication|access.token/i, "configure-identity", "Configure an identity"],
      [/budget|timeout|incomplete|request.error|probe.exception|execution.error|rate.limit/i, "prepare-replay", "Prepare a bounded replay"],
    ];
    const choice = choices.find(([pattern]) => pattern.test(text));
    if (!choice) return {kind: "inspect-exchange", label: "Inspect the recorded setup and evidence", reason: text, operation};
    return {kind: choice[1], label: choice[2], reason: text, operation};
  }

  function actionButton(action, onAction) {
    if (!action || typeof onAction !== "function") return null;
    const button = node("button", "btn small result-next-action", action.label);
    button.type = "button";
    button.addEventListener("click", () => onAction(action));
    return button;
  }

  function exchangeText(exchange, response) {
    const record = response ? exchange.response : exchange.request;
    const error = exchange.error || record?.error;
    if (response && error) return `No complete response: ${error}`;
    const headers = (response ? exchange.response_headers : exchange.request_headers) ?? record?.headers;
    const start = response ? `HTTP ${exchange.status ?? record?.status ?? "unknown"}`
      : `${exchange.method ?? record?.method ?? ""} ${exchange.url ?? record?.url ?? ""}`;
    const body = response ? (Object.prototype.hasOwnProperty.call(exchange, "response_body")
      ? exchange.response_body : record?.body ?? exchange.body_excerpt) : exchange.request_body ?? record?.body;
    const content = typeof body === "string" ? body : body == null ? "" : JSON.stringify(body);
    return [start, ...Object.entries(headers || {}).map(([name, value]) => `${name}: ${value}`), "", content].join("\n");
  }

  function evidenceBlock(exchange, id, label) {
    const details = disclosure(id, node("span", "", label), "case-evidence");
    details.id = id;
    let rendered = false;
    const fill = () => {
      if (rendered) return;
      rendered = true;
      details.append(node("p", "hint", "Original captured values, with credentials redacted. HTTP text is reconstructed; header casing and ordering may differ from the wire."));
      const fullBody = Object.prototype.hasOwnProperty.call(exchange, "response_body")
        ? exchange.response_body : exchange.response?.body;
      if (exchange.truncated || exchange.response?.truncated || typeof fullBody !== "string") {
        details.append(node("p", "case-uncertainty", exchange.truncated || exchange.response?.truncated
          ? "Response capture was truncated. Uncaptured bytes cannot be compared."
          : "This record contains an excerpt only; complete response equality cannot be established."));
      }
      const panes = node("div", "case-evidence-panes");
      for (const response of [false, true]) {
        const pane = node("section");
        pane.append(node("h5", "", response ? "Response" : "Request"),
          node("pre", "code-block wrap", exchangeText(exchange, response)));
        panes.append(pane);
      }
      details.append(panes);
      const original = disclosure(`${id}-record`, node("span", "", "Original captured record (JSON)"), "case-original-record");
      let originalRendered = false;
      const showOriginal = () => {
        if (originalRendered) return;
        originalRendered = true;
        original.append(node("pre", "code-block wrap", JSON.stringify(exchange, null, 2)));
      };
      original.addEventListener("toggle", () => {if (original.open) showOriginal();});
      if (original.open) showOriginal();
      details.append(original);
    };
    details.addEventListener("toggle", () => { if (details.open) fill(); });
    if (details.open) fill();
    return { details, open() { fill(); details.open = true; expanded.set(id, true); details.scrollIntoView?.({block: "nearest"}); } };
  }

  function inputValue(exchange, item) {
    const request = exchange?.request || {};
    const parts = String(item.pointer || "").split("/").slice(1).map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
    if (parts[0] === item.location && item.location !== "body") parts.shift();
    let value;
    if (item.location === "header") {
      const headers = exchange?.request_headers || request.headers || {};
      const key = Object.keys(headers).find((name) => name.toLowerCase() === String(parts[0]).toLowerCase());
      return key === undefined ? {present: false} : {present: true, value: headers[key]};
    }
    if (item.location === "query") {
      try {
        const url = new URL(exchange?.url || request.url);
        const values = url.searchParams.getAll(parts[0]);
        return values.length ? {present: true, value: values.length === 1 ? values[0] : values} : {present: false};
      } catch { return {unavailable: true}; }
    }
    if (item.location !== "body") return {unavailable: true};
    try {
      const body = exchange?.request_body ?? request.body;
      value = typeof body === "string" ? JSON.parse(body) : body;
      if (value === undefined) return {unavailable: true};
      for (const part of parts) {
        if (value === null || typeof value !== "object" || !Object.prototype.hasOwnProperty.call(value, part)) return {present: false};
        value = value[part];
      }
      return {present: true, value};
    } catch { return {unavailable: true}; }
  }

  function valueLabel(value) {
    return value.unavailable ? "Not available in this capture" : !value.present ? "Field omitted" : JSON.stringify(value.value, null, 2);
  }

  function changedLines(before, after) {
    const left = before.split("\n"), right = after.split("\n");
    const sameLeft = new Set(), sameRight = new Set();
    // Bound display work for large captures. Originals remain available below.
    if (left.length * right.length <= 250000) {
      const lengths = Array.from({length: left.length + 1}, () => new Uint32Array(right.length + 1));
      for (let i = left.length - 1; i >= 0; i--) for (let j = right.length - 1; j >= 0; j--) {
        lengths[i][j] = left[i] === right[j] ? lengths[i + 1][j + 1] + 1 : Math.max(lengths[i + 1][j], lengths[i][j + 1]);
      }
      let i = 0, j = 0;
      while (i < left.length && j < right.length) {
        if (left[i] === right[j]) {sameLeft.add(i++); sameRight.add(j++);}
        else if (lengths[i + 1][j] >= lengths[i][j + 1]) i++;
        else j++;
      }
    } else {
      const leftValues = new Set(left), rightValues = new Set(right);
      left.forEach((line, i) => {if (rightValues.has(line)) sameLeft.add(i);});
      right.forEach((line, i) => {if (leftValues.has(line)) sameRight.add(i);});
    }
    return [left.map((text, i) => ({text, changed: !sameLeft.has(i)})), right.map((text, i) => ({text, changed: !sameRight.has(i)}))];
  }

  function requestComparison(item, exchange, id) {
    const details = disclosure(id, node("span", "", "Compare baseline and changed request"), "case-evidence request-comparison");
    details.id = id;
    let rendered = false;
    const fill = () => {
      if (rendered) return;
      rendered = true;
      details.append(node("p", "hint", `Mutation: ${item.mutation}. Selected input: ${item.location || "request"} ${item.pointer || "(root)"}. Highlighted lines differ in the retained, redacted captures; unchanged values remain visible.`));
      const lines = changedLines(exchangeText(item.baselineExchange, false), exchangeText(exchange, false));
      const panes = node("div", "case-evidence-panes request-comparison-panes");
      for (const [index, captured] of [item.baselineExchange, exchange].entries()) {
        const pane = node("section");
        pane.append(node("h5", "", index ? "Changed request" : "Saved baseline request"));
        const value = inputValue(captured, item);
        const selected = node("div", "mutation-value");
        selected.append(node("span", "hint", "Selected input value"), node("pre", "", valueLabel(value)));
        const pre = node("pre", "code-block wrap request-diff");
        for (const line of lines[index]) {
          const renderedLine = node(line.changed ? "mark" : "span", "request-diff-line", line.text + "\n");
          if (line.changed) renderedLine.setAttribute("aria-label", `Changed line: ${line.text}`);
          pre.append(renderedLine);
        }
        pane.append(selected, pre); panes.append(pane);
      }
      details.append(panes, node("p", "hint", "Response interpretation and diagnostic metadata are shown with the case. Original captured request and response records are available separately; this comparison sends no requests."));
    };
    details.addEventListener("toggle", () => {if (details.open) fill();});
    if (details.open) fill();
    return {details, open() {fill(); details.open = true; expanded.set(id, true); details.scrollIntoView?.({block: "nearest"});}};
  }

  function caseRow(item, index, prefix, evidence, onAction) {
    const row = node("tr");
    row.dataset.caseId = item.id || `${prefix}-${index}`;
    const statuses = (item.exchanges || []).map(responseLabel);
    row.append(node("td", "case-mutation", item.mutation || item.check || "Recorded check"),
      node("td", "", `${executionLabel(item)}${statuses.length ? ": " + [...new Set(statuses)].join(", ") : ""}`),
      node("td", "", comparisonLabel(item.comparison)));
    const meaning = node("td");
    if (item.interpretation) meaning.append(node("p", "", item.interpretation));
    if (item.uncertainty) meaning.append(node("p", "case-uncertainty", item.uncertainty));
    if (item.derivedReasonCode || item.reasonCode) meaning.append(node("p", "hint", item.derivedReasonCode || item.reasonCode));
    if (item.derivedReasonCode && item.reasonCode && item.derivedReasonCode !== item.reasonCode) {
      meaning.append(node("p", "hint", `Original receipt reason: ${item.reasonCode}. Classification above uses the retained evidence and current comparison policy.`));
    }
    const metadata = item.metadataDifferences || [];
    if (metadata.length) meaning.append(node("p", "hint", "Diagnostic metadata changed: "
      + [...new Set(metadata.map((entry) => typeof entry === "string" ? entry : entry.name || entry.header))].join(", ")
      + ". Original values remain in the evidence."));
    const meaningful = item.meaningfulHeaderDifferences || [];
    if (meaningful.length) meaning.append(node("p", "case-uncertainty", "Meaningful header changes: "
      + [...new Set(meaningful.map((entry) => typeof entry === "string" ? entry : entry.name || entry.header))].join(", ")));
    if (item.prerequisite) meaning.append(node("p", "hint", `Prerequisite: ${item.prerequisite}`));
    const missing = item.missingPrerequisites || item.receipt?.missing_prerequisites || [];
    if (missing.length) meaning.append(node("p", "case-uncertainty", `Missing: ${missing.join("; ")}`));
    if (item.status === "not-applicable") meaning.append(node("p", "hint", "Does not apply to this operation. No setup change is required for this check."));
    if (["skipped", "error", "unknown"].includes(item.state)) {
      const actions = new Set();
      for (const reason of missing.length ? missing : [item.reasonCode || item.status]) {
        const action = blockerAction(reason, item);
        if (!action || actions.has(action.kind)) continue;
        actions.add(action.kind);
        const button = actionButton(action, onAction);
        if (button) meaning.append(button);
      }
    }
    row.append(meaning);
    const links = node("td", "case-evidence-links");
    const exchanges = item.exchanges || [];
    const add = (exchange, suffix, label) => {
      const id = `${prefix}-case-${stableKey(item.probeId || `${item.mutation}-${index}`)}-${suffix}`;
      const block = evidenceBlock(exchange, id, label);
      const link = node("a", "", label);
      link.href = `#${id}`;
      link.addEventListener("click", (event) => { event.preventDefault(); block.open(); });
      links.append(link);
      evidence.append(block.details);
    };
    exchanges.forEach((exchange, at) => add(exchange, at, `Request / response ${at + 1}`));
    if (item.baselineExchange) add(item.baselineExchange, "baseline", "Baseline evidence");
    if (item.baselineExchange && exchanges.length && item.pointer !== undefined) {
      exchanges.forEach((exchange, at) => {
        const block = requestComparison(item, exchange, `${prefix}-compare-${stableKey(item.probeId || `${item.mutation}-${index}`)}-${at}`);
        const link = node("a", "compare-request-link", exchanges.length === 1 ? "Compare changed request" : `Compare changed request ${at + 1}`);
        link.href = `#${block.details.id}`;
        link.addEventListener("click", (event) => {event.preventDefault(); block.open();});
        links.append(link); evidence.append(block.details);
      });
    }
    if (!exchanges.length) links.append(node("span", "hint", "No request / response recorded"));
    row.append(links);
    return row;
  }

  function casesTable(cases, prefix, onAction) {
    const wrap = node("div", "test-case-content");
    const scroll = node("div", "audit-table-scroll");
    const table = node("table", "audit-table test-case-table");
    const head = node("thead");
    const headings = node("tr");
    for (const title of ["Mutation / check", "Execution / response", "Baseline comparison", "Interpretation / uncertainty", "Evidence"]) {
      const th = node("th", "", title);
      th.scope = "col";
      headings.append(th);
    }
    head.append(headings);
    const body = node("tbody");
    const evidence = node("div", "test-case-evidence");
    let shown = 0;
    const progress = node("p", "hint case-page-progress");
    const more = node("button", "btn small case-page-more"); more.type = "button";
    const appendPage = (limit) => {
      const end = Math.min(cases.length, limit);
      for (; shown < end; shown++) body.append(caseRow(cases[shown], shown, prefix, evidence, onAction));
      loadedPages.set(prefix, shown);
      progress.textContent = `Showing ${shown} of ${cases.length} recorded cases. All cases remain in the saved evidence.`;
      more.textContent = `Show next ${Math.min(100, cases.length - shown)} cases`;
      more.hidden = shown >= cases.length;
    };
    more.addEventListener("click", () => appendPage(shown + 100));
    appendPage(loadedPages.get(prefix) || 100);
    table.append(head, body);
    scroll.append(table);
    wrap.append(scroll, evidence);
    if (cases.length > 100) wrap.append(progress, more);
    return wrap;
  }

  function appendCases(section, cases, prefix, onAction, lazy) {
    let rendered = false;
    const fill = () => { if (rendered || !section.open) return; rendered = true; section.append(casesTable(cases, prefix, onAction)); };
    if (!lazy) { section.append(casesTable(cases, prefix, onAction)); return; }
    section.addEventListener("toggle", fill);
    fill();
  }

  function policyControls(model, onPolicyChange) {
    const section = disclosure("response-comparison-policy", node("span", "", "Response comparison policy"), "results-comparison-policy");
    const policy = model.responseComparisonPolicy;
    section.append(node("p", "hint", "Only exact, supported correlation, timestamp and diagnostic header names can be separated from application-response comparison. Security headers, cookies, authentication, caching and rate-limit headers remain meaningful. Original evidence is never rewritten."));
    section.append(node("p", "hint", `Metadata headers currently separated: ${policy.metadata_headers.join(", ") || "none (strict comparison)"}.`));
    if (typeof onPolicyChange !== "function") return section;
    const label = node("label", "", "Exact metadata header names (comma separated)");
    const input = node("textarea", "comparison-header-input");
    input.rows = 3;
    input.value = policy.metadata_headers.join(", ");
    input.setAttribute("aria-label", "Exact metadata header names");
    label.append(input);
    const supported = node("p", "hint", "Supported names: " + Object.keys(root.NamazuAuditResults.metadataHeaderCatalog).join(", ") + ". Leave empty for strict comparison.");
    const error = node("p", "case-uncertainty");
    error.setAttribute("role", "alert");
    const apply = node("button", "btn", "Reclassify saved evidence");
    apply.type = "button";
    apply.addEventListener("click", () => {
      try {
        const metadata_headers = input.value.split(",").map((name) => name.trim()).filter(Boolean);
        onPolicyChange(root.NamazuAuditResults.normalizePolicy({metadata_headers}));
      } catch (failure) { error.textContent = failure.message; }
    });
    section.append(label, supported, apply, error, node("p", "hint", "This changes offline comparison only and sends no target requests. The selected policy is included in the next export."));
    return section;
  }

  function render(audit, {onPolicyChange, onAction} = {}) {
    const model = root.NamazuAuditResults.buildResults(audit);
    const lazyCases = model.operations.reduce((count, operation) => count + (operation.checks?.length || 0)
      + (operation.fields || []).reduce((total, field) => total + (field.cases?.length || 0), 0), 0) > 300;
    const run = runKey(audit);
    const view = node("section", "test-results");
    view.setAttribute("aria-label", "Recorded test results");
    const summary = node("section", "test-coverage-summary");
    summary.append(node("h3", "", "Coverage and blockers"), node("p", "test-counts", counts(model.summary)),
      node("p", "hint", "Counts describe field cases, not requests or vulnerabilities. Planned cases overlap their recorded outcomes; execution errors and missing receipts are shown separately."));
    const requests = model.summary.requestBreakdown || {};
    const requestLabels = {inventory: "inventory / calibration", baseline: "baselines", schema_inputs: "schema input tests",
      other_endpoint_tests: "other endpoint tests"};
    if (model.summary.totalRequests !== null && model.summary.totalRequests !== undefined) {
      summary.append(node("p", "test-request-counts", `${model.summary.totalRequests} recorded requests`
        + Object.entries(requests).filter(([, value]) => Number.isFinite(value))
          .map(([key, value]) => ` · ${value} ${requestLabels[key] || key.replaceAll("_", " ")}`).join("")));
    }
    const checks = model.summary.operationChecks;
    const responses = model.summary.responseSummary;
    if (responses) {
      const group = responses.endpoint;
      if (group.requests) {
        summary.append(node("p", "test-response-counts", `Endpoint response observations: ${group.applicationDenialResponses} application denials`
          + ` (${group.sameDenialResponses} same denial after baseline) · ${group.validationResponses} field validation responses`
          + ` · ${group.edgeBlockResponses} explicit edge block pages · ${group.incompleteResponses} incomplete tests`
          + (group.comparisonDiscrepancyResponses ? ` · ${group.comparisonDiscrepancyResponses} unresolved receipt / evidence comparisons` : "") + "."));
        summary.append(node("p", "hint", `These counts use ${group.requests} distinct recorded endpoint requests, including ${group.baselineResponses} baseline response(s); they are separate from case counts and inventory.`));
      }
      if (responses.inventory.requests) summary.append(node("p", "hint",
        `Inventory: ${responses.inventory.requests} recorded requests, including ${responses.inventory.edgeBlockResponses} explicit edge block pages. These are not field mutation results.`));
      if (!responses.logComplete) summary.append(node("p", "case-uncertainty", "The retained request log is incomplete; response totals cover recorded evidence only."));
    }
    if (checks?.totalCases) summary.append(node("p", "hint", `Separate operation checks: ${checks.executedCases || 0} executed`
      + ` · ${checks.observedCases || 0} offline / baseline observations · ${checks.skippedCases || 0} skipped`
      + (checks.errorCases ? ` · ${checks.errorCases} execution errors` : "")
      + (checks.unknownCases ? ` · ${checks.unknownCases} missing evidence` : "")));
    const blockers = model.summary.blockers || [];
    if (blockers.length) {
      const list = node("ul", "test-blockers");
      for (const blocker of blockers) {
        const label = typeof blocker === "string" ? blocker : blocker.reason || blocker.reasonCode || blocker.code || "Missing prerequisite";
        const count = blocker.caseCount ?? blocker.count;
        const entry = node("li", "", `${label}${count ? ` (${count} case${count === 1 ? "" : "s"})` : ""}`);
        const button = actionButton(blockerAction(label), onAction);
        if (button) entry.append(button);
        list.append(entry);
      }
      const shortReasons = blockers.map((item) => typeof item === "string" ? item : item.reason)
        .filter((reason) => reason && reason.length < 80 && reason !== "prerequisite-not-met").slice(0, 3);
      if (shortReasons.length) summary.append(node("p", "case-uncertainty", `Recorded blockers include: ${shortReasons.join("; ")}.`));
      summary.append(disclosure("test-blockers", node("span", "", `${blockers.length} recorded blocker reasons`), "results-blockers", blockers.length <= 6));
      summary.lastElementChild.append(list);
    } else {
      summary.append(node("p", "hint", "No blocker reasons were recorded. This does not establish complete coverage."));
    }
    if (model.summary.fieldRecordsMissing ?? model.summary.individualRecordsMissing) {
      summary.append(node("p", "case-uncertainty", "Some individual case receipts are missing. Aggregate completion labels and traffic totals cannot establish which field mutations ran."));
    }
    if (model.summary.operationCheckRecordsMissing) summary.append(node("p", "case-uncertainty",
      "Some operation-level checks lack execution or observation evidence. Their completion cannot be established."));
    summary.append(node("p", "case-uncertainty", "Uniform application denials and explicit edge block pages leave downstream handling unknown. Field-specific validation rejections are observations; a status or response difference alone establishes neither a vulnerability nor the processing layer."));
    view.append(summary);
    if (model.responseComparisonPolicy) view.append(policyControls(model, onPolicyChange));
    const heading = node("div", "test-results-heading");
    heading.append(node("h3", "", "Test observations by operation and field"),
      node("p", "hint", "Equivalent application responses are grouped. Selected diagnostic metadata differences are shown separately; every original header and body remains in each case's evidence."));
    view.append(heading);
    if (!model.operations.length) {
      view.append(node("p", "pane-empty", "No field-level receipts were recorded for this run. Findings and traffic do not imply that input fields were tested."));
    }
    model.operations.forEach((operation, operationIndex) => {
      const prefix = `test-${run}-operation-${stableKey(operation.label || operation.id || operationIndex)}`;
      const title = node("span", "results-disclosure-title");
      title.append(node("strong", "", operation.label || operation.operation || operation.operationId || operation.id),
        node("span", "hint", counts(operation.summary)));
      const section = disclosure(prefix, title, "test-operation", operationIndex === 0);
      for (const [fieldIndex, field] of (operation.fields || []).entries()) {
        const fieldId = `${prefix}-field-${stableKey(`${field.location}-${field.pointer}-${fieldIndex}`)}`;
        const fieldTitle = node("span", "results-disclosure-title");
        fieldTitle.append(node("strong", "", `${field.location || "input"} ${field.pointer === "" ? '(root JSON pointer "")' : field.pointer}`),
          node("span", "hint", counts(field.summary)));
        if (field.category === "read-only-negative") {
          fieldTitle.append(node("span", "hint", "Read-only submission (negative test)"));
        }
        const fieldSection = disclosure(fieldId, fieldTitle, "test-field", false);
        for (const [groupIndex, group] of (field.groups || []).entries()) {
          const groupId = `${fieldId}-response-${stableKey(`${group.comparison}-${group.cases?.[0]?.probeId || groupIndex}`)}`;
          const cases = group.cases || [];
          const responseCodes = [...new Set(cases.flatMap((item) => (item.exchanges || []).map((exchange) => exchange.status ?? exchange.response?.status).filter(Boolean)))];
          const groupTitle = node("span", "results-disclosure-title");
          groupTitle.append(node("strong", "", `${responseCodes.length ? responseCodes.map((code) => `HTTP ${code}`).join(", ") : "No comparable response"} · ${cases.length} case${cases.length === 1 ? "" : "s"}`),
            node("span", "", comparisonLabel(group.comparison || cases[0]?.comparison)));
          const groupSection = disclosure(groupId, groupTitle, "test-response-group", false);
          if (group.interpretation) groupSection.append(node("p", "group-interpretation", group.interpretation));
          if (group.uncertainty) groupSection.append(node("p", "case-uncertainty", group.uncertainty));
          appendCases(groupSection, cases, groupId, onAction, lazyCases);
          fieldSection.append(groupSection);
        }
        section.append(fieldSection);
      }
      if (operation.checks?.length) {
        const checks = disclosure(`${prefix}-checks`, node("span", "", `${operation.checks.length} operation-level check receipts`), "test-operation-checks");
        checks.append(node("p", "hint", "These checks are separate from the field-case counts above."));
        appendCases(checks, operation.checks, `${prefix}-check`, onAction, lazyCases);
        section.append(checks);
      }
      view.append(section);
    });
    return view;
  }

  root.NamazuAuditResultsView = { render, counts, comparisonLabel, exchangeText, responseLabel,
    blockerAction, actionButton, inputValue, changedLines, stableKey, runKey };
})(typeof window === "undefined" ? globalThis : window);
