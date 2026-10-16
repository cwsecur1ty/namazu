/* Offline assessment presentation. Rendering never replays a target request. */
(function (root) {
  "use strict";
  const expanded = new Map();
  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text != null) element.textContent = String(text);
    return element;
  }
  function section(title, values) {
    const part = node("section", "assessment-section");
    part.append(node("h4", "", title));
    const list = node("ul", "note-list");
    for (const value of values) list.append(node("li", "", value));
    part.append(list);
    return part;
  }
  function disclosure(key, title, className = "disclosure", open = false) {
    const details = node("details", className);
    details.open = expanded.has(key) ? expanded.get(key) : open;
    details.append(node("summary", "", title));
    details.addEventListener("toggle", () => expanded.set(key, details.open));
    return details;
  }
  function prerequisiteText(value) {
    return ({"successful-positive-control": "A request that successfully performs the intended operation is missing.",
      "resource-and-content-assertions": "Define the resource and response content that would establish business success.",
      "distinct-second-identity": "A second identity is needed to test access between users.",
      "second-identity-positive-control": "Establish which request succeeds for the second identity before comparing its access.",
      "explicit-permission-matrix": "Record which identity should be allowed or denied each resource; shared access may be intentional."})[value] || value;
  }
  function isSecurityLead(item) {
    const assessment = item.assessment || {};
    return assessment.category === "security" && assessment.origin !== "static-declaration"
      && ["runtime-observation", "external-report"].includes(assessment.origin)
      && !(assessment.origin === "runtime-observation" && assessment.verification === "impact-demonstrated");
  }
  function render(audit, {onReview, onAction} = {}) {
    const panel = node("section", "report-card evidence-assessment");
    panel.append(node("h3", "", "What this audit established"));
    const assessment = audit.assessment;
    const run = root.NamazuAuditResultsView?.runKey(audit) || String(audit.startedAt || audit.generated_at || audit.context?.base_url || "recorded");
    const evidence = node("div", "assessment-evidence");
    const evidenceIndex = disclosure(`${run}-evidence-index`, "Exact retained evidence", "disclosure assessment-evidence-index");
    evidenceIndex.append(evidence);
    const evidenceBlocks = new Map();
    function evidenceLinks(parent, references) {
      const links = node("div", "case-evidence-links");
      for (const reference of references || []) {
        const pointer = typeof reference === "string" ? reference : reference?.pointer;
        const match = /^#?\/(requests|findings|coverage\/probes)\/(\d+)$/.exec(pointer || "");
        if (!match) continue;
        const record = (match[1] === "requests" ? audit.log : match[1] === "coverage/probes" ? audit.probes : audit.findings)?.[Number(match[2])];
        if (!record) continue;
        const key = `${match[1].replace(/\//g, "-")}-${match[2]}`;
        if (!evidenceBlocks.has(key)) {
          const block = disclosure(`${run}-evidence-${key}`, `Retained ${match[1] === "requests" ? "request / response" : match[1] === "coverage/probes" ? "probe receipt" : "observation"} ${Number(match[2]) + 1}`, "case-evidence");
          block.id = `assessment-evidence-${key}`;
          let filled = false;
          const fill = () => {
            if (filled) return;
            filled = true;
            block.append(node("pre", "code-block wrap", JSON.stringify(record, null, 2)));
          };
          block.addEventListener("toggle", () => { if (block.open) fill(); });
          if (block.open) fill();
          evidenceBlocks.set(key, {block, fill}); evidence.append(block);
        }
        const {block, fill} = evidenceBlocks.get(key);
        const link = node("a", "", `Evidence ${Number(match[2]) + 1}`);
        link.href = `#${block.id}`;
        link.addEventListener("click", (event) => {
          event.preventDefault();
          evidenceIndex.open = true; expanded.set(`${run}-evidence-index`, true);
          fill(); block.open = true; expanded.set(`${run}-evidence-${key}`, true);
          block.scrollIntoView?.({block: "nearest"});
        });
        links.append(link);
      }
      parent.append(links);
    }
    function observation(item) {
      const entry = disclosure(`${run}-observation-${item.id}-${item.endpoint}-${item.title}`, `${item.title}${(item.occurrence_count ?? item.evidence?.occurrence_count) != null ? `: ${item.occurrence_count ?? item.evidence?.occurrence_count} occurrences` : ""}`);
      const count = item.occurrence_count ?? item.evidence?.occurrence_count;
      if (count != null) entry.dataset.occurrences = String(count);
      entry.append(node("p", "", item.detail), node("p", "case-uncertainty", item.limitations || item.impact));
      const refs = item.evidence_refs || (item.evidence?.occurrences || []).map((row) => row.evidence_ref || row);
      if (!refs.length) for (const mismatch of item.evidence?.mismatches || []) refs.push(...(mismatch.occurrences || []));
      evidenceLinks(entry, refs);
      entry.append(node("pre", "code-block wrap", JSON.stringify(item.evidence, null, 2)));
      return entry;
    }
    if (!assessment) {
      panel.append(node("p", "hint", audit.running
        ? "The run is in progress. Case receipts below show current evidence; the assessment is prepared when the current work finishes."
        : "Review retained responses to see what was tested, what remains unknown and the next useful actions. This local analysis sends no requests to the target."));
    } else {
      const security = assessment.security || {};
      const tested = node("section", "assessment-question");
      tested.append(node("h4", "", "What was tested?"));
      const operations = [...new Set((assessment.operations || []).map((operation) => operation.endpoint).filter(Boolean))];
      tested.append(node("p", "", operations.length ? `${operations.length} operation${operations.length === 1 ? "" : "s"} represented in the retained response evidence.` : "No operation list was retained. Request totals alone do not establish operation coverage."));
      if (operations.length) tested.append(section("Operations", operations));
      const counts = assessment.request_accounting || {};
      const table = node("table", "audit-table");
      table.append(node("caption", "visually-hidden", "Recorded request attempts and responses by purpose"));
      const head = node("tr");
      for (const label of ["Purpose", "Attempts", "Responses", "Same denial", "Validation", "Edge block", "Incomplete"]) {
        const heading = node("th", "", label); heading.scope = "col"; head.append(heading);
      }
      table.append(head);
      for (const purpose of ["endpoint", "inventory", "total"]) {
        const count = counts[purpose] || {};
        const row = node("tr");
        for (const value of [{endpoint: "Endpoint testing", inventory: "Inventory and calibration", total: "Total"}[purpose], count.request_attempts || 0, count.responses_received || 0,
          count["same-denial"] || 0, count["validation-observation"] || 0, count["edge-block"] || 0,
          count["incomplete-test"] || 0]) row.append(node("td", "", value));
        table.append(row);
      }
      const scroll = node("div", "audit-table-scroll"); scroll.append(table); tested.append(scroll);
      tested.append(node("p", "hint", "Same-denial counts exclude the baseline. Response counts include received errors; timeouts are attempts without a completed response. Counts describe retained evidence only. More requests do not establish wider coverage."));
      panel.append(tested);

      const established = node("section", "assessment-question");
      established.append(node("h4", "", "What did we establish?"), node("p", "assessment-outcome", security.interpretation),
        node("p", "hint", `${security.demonstrated_vulnerabilities || 0} distinct demonstrated vulnerabilities across ${security.affected_operations || 0} affected operations. Repeated occurrences are counted separately below.`));
      const impact = disclosure(`${run}-demonstrated`, `Demonstrated vulnerabilities: ${security.demonstrated_vulnerabilities || 0}`, "disclosure assessment-impact");
      impact.append(node("p", "", security.demonstrated_vulnerabilities ? "These records contain evidence of a demonstrated security consequence. Inspect the evidence and its limitations." : "No captured record demonstrates exploitable security impact. This does not establish that the API is secure."));
      evidenceLinks(impact, security.finding_refs); established.append(impact);
      const leads = (assessment.original_observations || []).filter(isSecurityLead);
      const leadSection = disclosure(`${run}-leads`, `Security leads requiring investigation: ${leads.length} recorded observations`, "disclosure assessment-leads");
      leadSection.append(node("p", "hint", leads.length ? "These security observations need further evidence of mechanism and impact. Expected field validation is listed separately." : "No security lead is inferred from expected input rejections, uniform denials, edge blocks or timeouts."));
      for (const item of leads) {leadSection.append(node("p", "", item.title)); evidenceLinks(leadSection, [item.evidence_ref]);}
      established.append(leadSection);
      const outcomes = [
        ["validation-observation", "Validation rejected this input", "These responses contain field-specific validation messages. They establish observed rejection, not a vulnerability or the layer that processed the value."],
        ["same-denial", "Same application denial", "These later responses match the baseline application denial. Downstream input handling remains unknown."],
        ["edge-block", "Blocked at the edge", "Explicit block-page body markers were retained. These responses are separate from application denials; downstream handling remains unknown."],
        ["incomplete-test", "Timeouts and execution failures", "These request attempts did not produce a completed response. They remain incomplete tests and have not been replayed."],
      ];
      for (const [classification, label, explanation] of outcomes) {
        const cases = (assessment.response_cases || []).filter((item) => item.purpose === "endpoint" && item.classification === classification);
        const outcome = disclosure(`${run}-outcome-${classification}`, `${label}: ${counts.endpoint?.[classification] || 0} endpoint responses${classification === "incomplete-test" ? " missing" : ""}`, "disclosure assessment-observed-outcome");
        outcome.append(node("p", "", explanation));
        for (const item of cases) {
          const row = node("div", "assessment-outcome-case");
          const recordIndex = /^#\/requests\/(\d+)$/.exec(item.evidence_ref || "")?.[1];
          const record = recordIndex === undefined ? {} : (audit.log || [])[Number(recordIndex)] || {};
          const status = classification === "incomplete-test" ? root.NamazuAuditResultsView?.responseLabel(record) || "No completed response" : `HTTP ${item.status}`;
          row.append(node("span", "", `${item.operation || "Operation not recorded"}: ${status}`));
          evidenceLinks(row, [item.evidence_ref]); outcome.append(row);
        }
        established.append(outcome);
      }
      panel.append(established);

      const unknown = node("section", "assessment-question");
      unknown.append(node("h4", "", "What remains unknown?"), section("Coverage limitations", assessment.coverage_limitations || []));
      const missing = section(`Missing prerequisites (${assessment.blocked_families?.count || 0} blocked check families)`, []);
      const missingList = missing.lastElementChild;
      for (const reason of assessment.missing_prerequisites || []) {
        const row = node("li", "", prerequisiteText(reason));
        if (prerequisiteText(reason) !== reason) row.append(node("span", "hint prerequisite-code", `Recorded reason: ${reason}`));
        missingList.append(row);
      }
      unknown.append(missing);
      for (const [key, label] of [["not_applicable", "Does not apply to the recorded operation or input"], ["applicability_unknown", "Applicability needs evidence review"]]) {
        const entries = assessment[key] || [];
        if (!entries.length) continue;
        const detail = disclosure(`${run}-${key}`, `${label}: ${entries.length} recorded cases`);
        detail.append(node("p", "hint", key === "not_applicable"
          ? "These reasons describe the operation or input this probe can test. They are separate from missing setup and are not instructions to change credentials. Different inputs can change which probes apply."
          : "Older family summaries may not retain enough detail to distinguish missing data from a probe that does not apply. Inspect the evidence before changing setup."));
        const groups = new Map();
        for (const entry of entries) {
          const groupKey = JSON.stringify([entry.operation, entry.check, entry.recorded_prerequisites]);
          if (!groups.has(groupKey)) groups.set(groupKey, {entry, members: []});
          groups.get(groupKey).members.push(entry);
        }
        for (const {entry, members} of groups.values()) {
          const row = node("div", "assessment-outcome-case");
          row.append(node("p", "", `${entry.operation || "Recorded operation"}: ${entry.check || entry.family || "probe"}. ${(entry.recorded_prerequisites || []).join("; ") || "No applicable input or comparison was recorded"}${members.length > 1 ? ` (${members.length} occurrences)` : ""}.`),
            node("p", "hint", entry.detail));
          evidenceLinks(row, members.map(item => item.evidence_ref));
          detail.append(row);
        }
        unknown.append(detail);
      }
      panel.append(unknown);

      const next = node("section", "assessment-question assessment-next");
      next.append(node("h4", "", "What should I do next?"));
      const actions = new Set();
      const reasons = [...(assessment.missing_prerequisites || []), ...(counts.endpoint?.["incomplete-test"] ? ["incomplete-test"] : [])];
      for (const reason of reasons) {
        const action = root.NamazuAuditResultsView?.blockerAction(reason);
        if (!action || actions.has(action.kind)) continue;
        actions.add(action.kind);
        const button = root.NamazuAuditResultsView?.actionButton(action, onAction);
        if (button) next.append(button);
      }
      next.append(section("Next test phase", assessment.next_phase || []), node("p", "hint", "These actions prepare setup or a reviewable plan. They do not change scope, grant write permission, increase a budget or send requests."));
      for (const preparation of assessment.baseline_preparation || []) {
        const part = disclosure(`${run}-prepare-${preparation.operation}`, `Baseline preparation: ${preparation.operation || "operation"}`);
        for (const warning of preparation.warnings || []) part.append(node("p", "readiness-warning", `${warning.pointer}: ${warning.detail}`));
        part.append(section("Unresolved baseline prerequisites", (preparation.missing_prerequisites || []).map((item) => item.detail)));
        if (preparation.owner_request) {
          const owner = node("textarea", "owner-request-copy"); owner.value = preparation.owner_request; owner.readOnly = true; owner.rows = 6;
          owner.setAttribute("aria-label", `Request to the API owner for ${preparation.operation || "this operation"}`);
          part.append(node("h4", "", "Copy this request to the API owner"), node("p", "hint", "Select and copy the text below. It describes the missing data and permissions without inventing resource identifiers."), owner);
        }
        next.append(part);
      }
      panel.append(next);
      const observations = disclosure(`${run}-observations`, "Hardening, documentation and implementation observations");
      for (const item of (assessment.original_observations || []).filter((entry) => !isSecurityLead(entry))) {
        observations.append(node("p", "", `${item.title} (${item.endpoint || "specification"})`),
          node("p", "hint", `${item.assessment?.origin === "static-declaration" ? "Specification observation" : "Recorded observation"}. Evidence: ${item.evidence_ref}`));
        evidenceLinks(observations, [item.evidence_ref]);
      }
      for (const item of assessment.header_observations || []) {
        observations.append(observation(item));
      }
      for (const [index, operation] of (assessment.operations || []).entries()) {
        const detail = disclosure(`${run}-operation-${operation.endpoint || index}`, operation.endpoint || "Operation", "disclosure assessment-operation");
        const review = operation.response_review || operation;
        const contract = review.contract || {};
        detail.append(node("p", "", `Contract review: ${contract.state || "not recorded"}. ${contract.reviewed_responses || 0} application responses reviewed; ${contract.mismatch_occurrences || 0} mismatch occurrences.`));
        if (contract.state === "unavailable-contract" || contract.state === "unavailable") {
          detail.append(node("p", "case-uncertainty", "This export did not retain the response contract. Historical contract observations remain evidence, but additional mismatches cannot be established from status or media type alone."));
        }
        detail.append(node("p", "hint", "Recognised edge block pages are separate from application responses. Neither contract disagreements nor limited implementation detail establish security impact."));
        for (const item of contract.findings || []) detail.append(observation(item));
        const disclosures = review.disclosures || {};
        detail.append(node("p", "hint", `${disclosures.distinct_observations || 0} distinct implementation observations; ${disclosures.occurrences || 0} repeated occurrences. ${disclosures.ordinary_validation_responses || 0} responses contain ordinary field validation messages.`));
        for (const item of disclosures.observations || []) detail.append(observation(item));
        const retained = disclosure(`${run}-operation-evidence-${operation.endpoint || index}`, "All occurrences and exact redacted evidence", "case-evidence");
        retained.id = `assessment-operation-${index}`;
        retained.append(node("pre", "code-block wrap", JSON.stringify(review, null, 2)));
        detail.append(retained); observations.append(detail);
      }
      panel.append(observations);
    }
    if (typeof onReview === "function") {
      const button = node("button", "btn", assessment ? "Refresh offline assessment" : "Review retained responses");
      button.type = "button";
      button.addEventListener("click", async () => {
        button.disabled = true;
        try { await onReview(); }
        catch (error) { panel.append(node("p", "case-uncertainty", `Offline review failed: ${error.message || error}`)); }
        finally { button.disabled = false; }
      });
      panel.append(button);
    }
    if (evidenceBlocks.size) {
      evidenceIndex.firstElementChild.textContent = `Exact retained evidence (${evidenceBlocks.size} records)`;
      panel.append(evidenceIndex);
    }
    return panel;
  }
  root.NamazuAssessmentView = {render, prerequisiteText, isSecurityLead};
})(typeof window === "undefined" ? globalThis : window);
