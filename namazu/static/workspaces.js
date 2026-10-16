/* Contract-scoped setup and evidence. Rendering and planning never dispatch to targets. */
(function (root) {
  "use strict";

  const list = value => Array.isArray(value) ? value : [];
  const pretty = value => JSON.stringify(value, null, 2);
  const operationKey = operation => operation.id || operation.local_id;
  const localKey = operation => operation.local_id || `${operation.method} ${operation.path}`;
  const identityLabel = contract => contract.identity?.profile_id
    ? `${contract.identity.name || contract.identity.profile_name || contract.identity.profile_id} · ${contract.identity.source || "shared profile"}`
    : "No identity configured";
  const contractTitle = contract => `${contract.title || "Untitled contract"}${contract.version ? ` ${contract.version}` : ""}`;
  const shortHash = hash => hash ? String(hash).slice(0, 12) : "not recorded";
  const node = (tag, text, className) => {
    const result = document.createElement(tag);
    if (text !== undefined && text !== null) result.textContent = String(text);
    if (className) result.className = className;
    return result;
  };
  function field(label, value = "", type = "text", hint = "") {
    const wrapper = node("label", "", "workspace-field");
    const input = node(type === "textarea" ? "textarea" : "input");
    if (type !== "textarea") input.type = type;
    input.value = value;
    input.setAttribute("aria-label", label);
    input.autocomplete = "off";
    input.spellcheck = false;
    wrapper.append(node("span", label), input);
    if (hint) wrapper.append(node("small", hint));
    return {wrapper, input};
  }
  function selectField(label, entries, selected = "") {
    const wrapper = node("label", "", "workspace-field"), input = node("select");
    input.setAttribute("aria-label", label);
    entries.forEach(([value, text]) => { const option = node("option", text); option.value = value; input.append(option); });
    input.value = selected;
    wrapper.append(node("span", label), input);
    return {wrapper, input};
  }
  function check(label, selected = false, hint = "") {
    const wrapper = node("label", "", "workspace-check"), input = node("input"), text = node("span", label);
    input.type = "checkbox"; input.checked = selected;
    if (hint) text.append(node("small", hint));
    wrapper.append(input, text);
    return {wrapper, input};
  }
  function facts(entries) {
    const result = node("dl", "", "workspace-facts");
    for (const [label, value] of entries) result.append(node("dt", label), node("dd", value ?? "Not recorded", label.includes("hash") ? "workspace-hash" : ""));
    return result;
  }
  function detail(label, value) {
    const result = node("details", "", "workspace-disclosure");
    result.append(node("summary", label), node("pre", typeof value === "string" ? value : pretty(value), "workspace-code"));
    return result;
  }
  function section(title, description) {
    const result = node("section", "", "workspace-section");
    result.append(node("h3", title));
    if (description) result.append(node("p", description));
    return result;
  }
  function callout(text, warning = false) { return node("p", text, `workspace-callout${warning ? " warning" : ""}`); }
  function metrics(entries) {
    const result = node("div", "", "workspace-metrics");
    for (const [label, value] of entries) {
      const metric = node("div", "", "workspace-metric");
      metric.append(node("strong", value ?? "Unknown"), node("span", label)); result.append(metric);
    }
    return result;
  }
  function table(headers, rows) {
    const wrapper = node("div", "", "workspace-table-wrap"), result = node("table", "", "workspace-table");
    const head = node("thead"), header = node("tr"), body = node("tbody");
    headers.forEach(text => header.append(node("th", text))); head.append(header);
    for (const row of rows) { const tr = node("tr"); row.forEach(text => tr.append(node("td", text ?? "Not recorded"))); body.append(tr); }
    result.append(head, body); wrapper.append(result); return wrapper;
  }
  function operationTraffic(operation) {
    const engine = operation.engine_plan || {}, plan = engine.test_plan || operation.test_plan || {};
    const probes = list(plan.supplemental_probes), checks = list(plan.supplemental_checks);
    return {baseline: operation.traffic_review?.baseline_requests ?? engine.request_breakdown?.baseline ?? plan.baseline_requests ?? 0,
      schema: operation.traffic_review?.schema_input_cases ?? engine.request_breakdown?.schema_inputs ?? plan.planned_requests ?? 0,
      conditionalFamilies: operation.traffic_review?.conditional_families ?? checks.filter(item => item.conditional).length,
      ceiling: operation.traffic_review?.operation_request_ceiling ?? operation.request_budget ?? engine.request_budget ?? plan.request_budget,
      probes, checks, cases: list(plan.probes)};
  }
  function planCaseReview(operation, label) {
    const traffic = operationTraffic(operation), details = node("details", "", "workspace-disclosure");
    details.append(node("summary", `Fields, cases and conditional families: ${label}`)); let loaded = false;
    details.ontoggle = () => {
      if (!details.open || loaded) return; loaded = true;
      details.append(node("p", `Baseline ${traffic.baseline}; schema cases ${traffic.schema}; hard operation ceiling ${traffic.ceiling ?? "shared limit"}. Conditional probe/check requests share that ceiling and the run budget. Upper bounds below are not promised requests or additive allocations.`));
      if (traffic.probes.length || traffic.checks.length) {
        const families = [...traffic.probes, ...traffic.checks];
        const area = node("div"); let shown = 0;
        const more = node("button", "Show next 100 conditional cases", "btn sm"); more.type = "button";
        const append = () => { const batch = families.slice(shown, shown + 100); shown += batch.length;
          area.append(table(["Family / field", "Conditional request bound", "Prerequisites"], batch.map(item => [`${item.title || item.check || item.family}${item.field_pointer ? `\n${item.location || "input"} ${item.field_pointer}` : ""}`, item.planned_requests == null ? `Conditional; remaining ceiling ${item.request_ceiling ?? traffic.ceiling ?? "shared"}` : `${item.planned_requests} ${item.request_count_kind === "upper-bound" ? "upper bound" : "planned"}`, `${item.prerequisite || "Probe-specific controls"}${list(item.missing_prerequisites).length ? `\nMissing: ${item.missing_prerequisites.join(", ")}` : ""}`]))); more.hidden = shown >= families.length; };
        more.onclick = append; append(); details.append(node("h4", "Conditional probe and check families"), area, more);
      }
      if (traffic.cases.length) {
        const area = node("div"); let shown = 0;
        const more = node("button", "Show next 100 schema cases", "btn sm"); more.type = "button";
        const append = () => { const batch = traffic.cases.slice(shown, shown + 100); shown += batch.length;
          area.append(table(["Field", "Mutation / status", "Prerequisites"], batch.map(item => [`${item.location || "input"} ${item.field_pointer || item.field || "operation"}`, `${item.mutation || item.category || item.id}\n${item.status || "planned"}`, [item.prerequisite, ...list(item.missing_prerequisites)].filter(Boolean).join("; ") || "Operation controls apply"]))); more.hidden = shown >= traffic.cases.length; };
        more.onclick = append; append(); details.append(node("h4", "Declared field mutation cases"), area, more);
      }
    };
    return details;
  }
  function jsonValue(input, label, expected = "object") {
    let value;
    try { value = JSON.parse(input.value.trim() || (expected === "array" ? "[]" : "{}")); }
    catch { throw Error(`${label} must be valid JSON.`); }
    if ((expected === "array" && !Array.isArray(value)) || (expected === "object" && (!value || Array.isArray(value) || typeof value !== "object"))) throw Error(`${label} must be a JSON ${expected}.`);
    return value;
  }
  function download(value, filename) {
    const url = URL.createObjectURL(new Blob([pretty(value)], {type: "application/json"}));
    const link = node("a"); link.href = url; link.download = filename; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function mount() {
    const opener = document.getElementById("workspaces-open");
    if (!opener) return;
    const state = {workspace: null, view: "contracts", selected: null, plan: null, run: null, evidence: null,
      pendingFiles: [], pendingUrls: "", documents: {}, workspaces: [], polling: null, pollingVersion: 0, reportExpanded: new Map(), saving: false};
    const dialog = node("dialog", "", "workspace-dialog"); dialog.id = "workspace-dialog"; dialog.setAttribute("aria-labelledby", "workspace-title");
    const frame = node("div", "", "workspace-frame"), header = node("header", "", "workspace-header");
    const heading = node("div", "", "workspace-heading"), title = node("h2", "Contract workspace"); title.id = "workspace-title";
    const subtitle = node("p", "Keep contracts, identities and evidence in their own scope."); heading.append(title, subtitle);
    const close = node("button", "Close review", "btn"); close.type = "button"; close.setAttribute("aria-label", "Close workspace review, keep Namazu open");
    close.onclick = () => { if (state.inline) root.dispatchEvent(new CustomEvent("namazu:workspace-close")); else dialog.close(); };
    const headerActions = node("div", "", "workspace-header-actions"), tabs = node("nav", "", "workspace-tabs"); tabs.setAttribute("aria-label", "Workspace sections");
    const body = node("div", "", "workspace-body"); body.id = "workspace-body";
    const footer = node("footer", "", "workspace-footer"), status = node("p", "Setup only. No endpoint requests sent."); status.id = "workspace-status"; status.setAttribute("role", "status");
    const error = node("p", "", "workspace-error"); error.id = "workspace-error"; error.setAttribute("role", "alert");
    footer.append(status, error); header.append(heading, close, headerActions); frame.append(header, tabs, body, footer); dialog.append(frame); document.body.append(dialog);
    function button(text, action, primary = false) {
      const result = node("button", text, `btn${primary ? " primary" : ""}`); result.type = "button";
      result.onclick = () => guarded(action, result); return result;
    }
    async function api(path, payload, method = "POST") {
      const response = await fetch(path, {method, headers: {"Content-Type": "application/json"}, credentials: "same-origin", ...(method === "GET" ? {} : {body: JSON.stringify(payload || {})})});
      let result;
      try { result = await response.json(); } catch { throw Error(`The local server returned an unreadable response (HTTP ${response.status}).`); }
      if (!response.ok) throw Error(typeof result.detail === "string" ? result.detail : pretty(result.detail || result.error || `HTTP ${response.status}`));
      return result;
    }
    async function guarded(action, source) {
      error.textContent = "";
      if (source) source.disabled = true;
      try { await action(); }
      catch (failure) { error.textContent = failure.message || String(failure); }
      finally { if (source?.isConnected) source.disabled = false; }
    }
    const route = suffix => `/api/workspaces/${encodeURIComponent(state.workspace.id)}${suffix}`;
    function clearRun() {
      clearTimeout(state.polling); state.pollingVersion++; state.run = null; state.evidence = null; state.plan = null;
    }
    function updateWorkspace(result, invalidate = true) {
      const workspace = result.workspace || result;
      if (workspace.id && Array.isArray(workspace.contracts)) state.workspace = workspace;
      if (!state.workspace.contracts.some(contract => contract.id === state.selected)) state.selected = state.workspace.contracts[0]?.id;
      if (invalidate) state.plan = null;
      render();
      root.dispatchEvent?.(new CustomEvent("namazu:workspace-updated", {detail: {workspace: state.workspace}}));
    }
    async function refresh(invalidate = false) { updateWorkspace(await api(route(""), null, "GET"), invalidate); }
    async function withWorkspaceMutation(action) {
      if (state.saving) throw Error("Wait for the current workspace change to finish.");
      state.saving = true;
      root.dispatchEvent?.(new CustomEvent("namazu:workspace-busy", {detail: {saving: true}}));
      body.inert = tabs.inert = headerActions.inert = true;
      dialog.setAttribute("aria-busy", "true");
      status.textContent = "Saving workspace configuration…";
      try { return await action(); }
      finally {
        root.dispatchEvent?.(new CustomEvent("namazu:workspace-busy", {detail: {saving: false}}));
        state.saving = false;
        body.inert = tabs.inert = headerActions.inert = false;
        dialog.setAttribute("aria-busy", "false");
        if (status.textContent === "Saving workspace configuration…") status.textContent = "The change was not saved. Your editor is still available.";
      }
    }
    async function mutate(suffix, payload, method = "POST", message = "Saved. Review a new plan before execution.") {
      return withWorkspaceMutation(async () => {
        const result = await api(route(suffix), payload, method);
        if (Array.isArray((result.workspace || result).contracts)) updateWorkspace(result);
        else await refresh(true);
        status.textContent = message;
        return result;
      });
    }
    function activate(view) { if (state.saving) return; state.view = view; error.textContent = ""; render(); body.scrollTop = 0; }
    function renderHeader() {
      title.textContent = state.workspace?.title || "Contract workspace";
      const contracts = list(state.workspace?.contracts), operations = contracts.reduce((sum, contract) => sum + list(contract.operations).length, 0);
      subtitle.textContent = `${contracts.length} contracts · ${operations} operations · Separate configuration and evidence for each contract`;
      tabs.replaceChildren();
      for (const [value, label, count] of [["contracts", "Contracts", contracts.length], ["identities", "Identities", list(state.workspace?.profiles).length], ["overlap", "Overlap review", list(state.workspace?.overlaps).filter(item => item.requires_review && !item.decision).length], ["plan", "Audit plan"], ["evidence", "Saved evidence", list(state.workspace?.runs).length]]) {
        const tab = node("button", label, "workspace-tab"); tab.type = "button"; tab.setAttribute("aria-selected", String(state.view === value));
        if (count) tab.append(node("span", count, "workspace-count")); tab.onclick = () => activate(value); tabs.append(tab);
      }
      headerActions.replaceChildren(button("Switch / new workspace", () => renderWorkspacePicker()), button("Save workspace JSON", saveWorkspace));
      const saved = node("input"); saved.type = "file"; saved.accept = ".json"; saved.hidden = true; saved.id = "workspace-saved-file";
      saved.onchange = () => guarded(async () => {
        const file = saved.files[0]; if (!file) return;
        if (file.size > 32 * 1024 * 1024) throw Error("Saved workspaces are limited to 32 MiB.");
        const imported = await api("/api/workspaces/import", JSON.parse(await file.text()));
        clearRun(); updateWorkspace(imported); state.view = "evidence"; render();
        status.textContent = "Saved workspace opened. Credentials must be reconfigured before execution; no requests replayed.";
      });
      headerActions.append(button("Open workspace JSON", () => saved.click()), saved);
      tabs.querySelector('[aria-selected="true"]')?.scrollIntoView({block: "nearest", inline: "nearest"});
    }
    function render() {
      renderHeader(); body.replaceChildren(); if (!state.workspace) return;
      ({contracts: renderContracts, identities: renderIdentities, overlap: renderOverlaps, plan: renderPlan, evidence: renderEvidence})[state.view]();
    }
    async function renderWorkspacePicker() {
      const response = await api("/api/workspaces", null, "GET"); state.workspaces = list(response.workspaces || response);
      body.replaceChildren();
      const panel = section("Choose a workspace", "Open existing contract configuration and retained evidence without replaying requests.");
      const name = field("New workspace name", "API workspace"); name.input.id = "workspace-new-name";
      panel.append(name.wrapper, button("Create workspace", async () => {
        const created = await api("/api/workspaces", {title: name.input.value.trim() || "API workspace"});
        clearRun(); state.pendingFiles = []; state.pendingUrls = ""; state.documents = {}; updateWorkspace(created); state.view = "contracts"; render();
        status.textContent = "Workspace created. Import contracts to start setup.";
      }, true));
      for (const workspace of state.workspaces) panel.append(button(workspace.title || workspace.id, async () => {
        const selected = await api(`/api/workspaces/${encodeURIComponent(workspace.id)}`, null, "GET");
        clearRun(); state.pendingFiles = []; state.pendingUrls = ""; state.documents = {}; updateWorkspace(selected);
        status.textContent = "Workspace opened. No target requests sent.";
      }));
      body.append(panel);
    }
    async function saveWorkspace() {
      if (!state.workspace) throw Error("Create a workspace first.");
      const data = await api(route("/export"), null, "GET");
      download(data, `namazu-workspace-${state.workspace.id}.json`);
      status.textContent = "Workspace export saved with contract snapshots and identity references. No credentials exported.";
    }
    async function readFiles(files, companions = false, directory = false) {
      const source = [...files].filter(file => !directory || /\.(json|ya?ml)$/i.test(file.name));
      if (!source.length || source.length > 200 || source.some(file => file.size > 8 * 1024 * 1024) || source.reduce((sum, file) => sum + file.size, 0) > 32 * 1024 * 1024) throw Error("Choose up to 200 JSON/YAML files, at most 8 MiB each and 32 MiB total.");
      const items = await Promise.all(source.map(async file => ({filename: file.webkitRelativePath || file.name, raw_spec: await file.text()})));
      const paths = new Set();
      for (const item of items) { if (paths.has(item.filename)) throw Error("Files with the same name need their source directories. Use Choose source folder to preserve relative references."); paths.add(item.filename); }
      if (companions || directory) for (const item of items) state.documents[item.filename] = item.raw_spec;
      if (directory) state.pendingFiles = items.filter(item => /(?:^|[\n{,])\s*["']?(?:openapi|swagger)["']?\s*:/m.test(item.raw_spec));
      else if (!companions) state.pendingFiles = items;
      renderContracts(true);
      status.textContent = `${state.pendingFiles.length} contract files selected; ${Object.keys(state.documents).length} companion documents available. No requests sent.`;
    }
    function renderContracts(replace = false) {
      if (replace) body.replaceChildren();
      const introduction = section("Import and review contracts", "Add OpenAPI contracts together. Review each resolved target before planning; documentation sources never become targets automatically.");
      const importBox = node("div", "", "workspace-import"), fileBox = node("div"), urlBox = node("div");
      fileBox.append(node("h4", "Local contract files"));
      const fileInput = node("input"); fileInput.type = "file"; fileInput.multiple = true; fileInput.accept = ".json,.yaml,.yml"; fileInput.id = "workspace-contract-files";
      fileInput.setAttribute("aria-label", "OpenAPI contract files"); fileInput.onchange = () => guarded(() => readFiles(fileInput.files));
      const companions = node("input"); companions.type = "file"; companions.multiple = true; companions.accept = ".json,.yaml,.yml"; companions.hidden = true; companions.id = "workspace-reference-files";
      companions.onchange = () => guarded(() => readFiles(companions.files, true));
      const folder = node("input"); folder.type = "file"; folder.multiple = true; folder.setAttribute("webkitdirectory", ""); folder.hidden = true; folder.id = "workspace-source-folder";
      folder.onchange = () => guarded(() => readFiles(folder.files, false, true));
      fileBox.append(fileInput, companions, folder, node("p", "Use a source folder to preserve separate directories for relative references. Companion documents are resolved only within their source paths."));
      const fileActions = node("div", "", "workspace-actions"); fileActions.append(button("Add reference files", () => companions.click()), button("Choose source folder", () => folder.click())); fileBox.append(fileActions);
      if (state.pendingFiles.length) { const names = node("ul", "", "workspace-file-list"); state.pendingFiles.forEach(item => names.append(node("li", item.filename))); fileBox.append(names); }
      const urls = field("Specification or documentation URLs, one per line", state.pendingUrls, "textarea", "Only document discovery runs on import. No identity is attached to specification or reference fetches."); urls.input.id = "workspace-spec-urls"; urls.input.placeholder = "http://127.0.0.1:9001/openapi.json\nhttp://127.0.0.1:9002/docs";
      urls.input.oninput = () => { state.pendingUrls = urls.input.value; };
      urlBox.append(node("h4", "Specification URL list"), urls.wrapper);
      importBox.append(fileBox, urlBox); introduction.append(importBox);
      const actions = node("div", "", "workspace-actions");
      actions.append(button("Import and review", async () => {
        const urlList = urls.input.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
        const items = [...state.pendingFiles.map(item => ({...item, documents: state.documents})), ...urlList.map(url => ({url}))];
        if (!items.length) throw Error("Choose OpenAPI files or paste specification URLs first.");
        await mutate("/contracts/import", {items}, "POST", "Import review ready. Successful contracts remain available even when another import fails.");
        state.pendingFiles = []; state.pendingUrls = ""; state.documents = {}; render();
      }, true)); actions.style.marginTop = "12px"; introduction.append(actions); body.append(introduction);
      if (list(state.workspace.import_errors).length) {
        const failures = section("Imports needing attention");
        for (const failure of state.workspace.import_errors) failures.append(callout(`${failure.source || failure.filename || failure.url || "Contract"}: ${failure.error || failure.message || pretty(failure)}`, true));
        body.append(failures);
      }
      if (!state.workspace.contracts.length) { body.append(node("p", "Your contracts will appear here with separate targets, operations and test data.", "workspace-empty")); return; }
      const review = section("Contract review"), layout = node("div", "", "workspace-layout"), choices = node("nav", "", "workspace-contract-list"); choices.setAttribute("aria-label", "Contracts");
      for (const contract of state.workspace.contracts) {
        const choice = node("button", "", "workspace-contract-choice"); choice.type = "button"; choice.dataset.contractId = contract.id; choice.setAttribute("aria-current", String(contract.id === state.selected));
        choice.append(node("strong", contractTitle(contract)), node("span", `${list(contract.operations).length} operations · ${shortHash(contract.hash)}`), node("span", contract.target || "Choose an API target", contract.target_review_required ? "workspace-review-needed" : ""));
        if (contract.scope_review_required) choice.append(node("span", "Identity scope review required", "workspace-review-needed"));
        choice.onclick = () => { if (state.saving) return; state.selected = contract.id; render(); }; choices.append(choice);
      }
      const selected = state.workspace.contracts.find(contract => contract.id === state.selected) || state.workspace.contracts[0];
      layout.append(choices, contractDetail(selected)); review.append(layout); body.append(review);
    }
    function contractDetail(contract) {
      const panel = node("div", "", "workspace-detail"); panel.id = "workspace-contract-detail";
      const head = node("div", "", "workspace-section-heading"); head.append(node("h3", contractTitle(contract)), node("span", `${list(contract.operations).length} operations`, "workspace-count")); panel.append(head);
      panel.append(facts([["Source", typeof contract.source === "object" ? pretty(contract.source) : contract.source], ["Content hash", contract.hash], ["Contract ID", contract.id], ["Active identity", identityLabel(contract)], ["Resolved servers", list(contract.servers).map(server => typeof server === "string" ? server : server.url).join("\n") || "No usable server declared"]]));
      if (contract.proposed_target && !contract.target) panel.append(facts([["Proposed target", contract.proposed_target]]));
      const overlaps = list(state.workspace.overlaps).filter(overlap => list(overlap.contract_ids).includes(contract.id) || list(overlap.operations).some(key => String(key).startsWith(`${contract.id}::`)));
      if (overlaps.length) {
        const pending = overlaps.filter(overlap => overlap.requires_review && !overlap.decision).length;
        panel.append(callout(`${overlaps.length} overlapping or similar operation declaration${overlaps.length === 1 ? "" : "s"} detected for this contract. ${pending ? `${pending} ${pending === 1 ? "requires" : "require"} a decision before execution.` : "Declarations remain separate under the recorded overlap decisions."}`, pending > 0), button("Review this contract's overlaps", () => activate("overlap")));
      }
      for (const issue of [...list(contract.errors), ...list(contract.unresolved_references), ...list(contract.warnings)]) panel.append(callout(typeof issue === "string" ? issue : pretty(issue), true));
      const target = field("API target including its base path", contract.target || contract.proposed_target || "", "url", "A changed target requires a fresh scope review. Choose the API server, not the documentation URL."); target.input.id = "workspace-contract-target";
      const serverList = node("datalist"); serverList.id = `workspace-servers-${contract.id}`;
      for (const server of list(contract.servers)) { const item = node("option"); item.value = typeof server === "string" ? server : server.url; serverList.append(item); }
      target.input.setAttribute("list", serverList.id); panel.append(target.wrapper, serverList);
      const targetActions = node("div", "", "workspace-actions"); targetActions.append(button("Confirm target", async () => {
        if (!target.input.value.trim()) throw Error("Enter an explicit API target.");
        await mutate(`/contracts/${encodeURIComponent(contract.id)}`, {target: target.input.value.trim()}, "PATCH", "Target saved. Reassign or confirm identity scopes before a new run.");
      })); panel.append(targetActions);
      if (contract.target_review_required || contract.scope_review_required) panel.append(callout(contract.target_review_required ? "An explicit target choice is required before execution." : "The target changed. Confirm the allowed identity scopes in Identities before execution.", true));
      const config = contract.config || {}, settings = node("div", "", "workspace-grid");
      const budget = field("Contract request limit (optional)", config.budget ?? "", "number", "All contracts also share the run budget and rate limit."); budget.input.min = "1";
      const writes = check("Authorise writes for this contract", Boolean(config.allow_mutating), "This permission is specific to this contract. A shared identity never grants write authorisation.");
      settings.append(budget.wrapper, writes.wrapper); settings.style.marginTop = "18px"; panel.append(settings);
      panel.append(button("Save contract limits", async () => {
        const limit = budget.input.value.trim() ? Number(budget.input.value) : null;
        if (limit !== null && (!Number.isInteger(limit) || limit < 1)) throw Error("Contract request limit must be a positive whole number.");
        await mutate(`/contracts/${encodeURIComponent(contract.id)}`, {config: {budget: limit, allow_mutating: writes.input.checked}}, "PATCH");
      }));
      const operationsHeading = node("div", "", "workspace-section-heading"); operationsHeading.style.marginTop = "24px"; operationsHeading.append(node("h3", "Operations and test data")); panel.append(operationsHeading);
      const selectedIds = new Set(Array.isArray(config.operation_ids) ? config.operation_ids : list(contract.operations).map(operationKey));
      const selection = node("div", "", "workspace-actions");
      for (const [label, values] of [["Select all", list(contract.operations).map(operationKey)], ["Exclude all", []]]) selection.append(button(label, () => mutate(`/contracts/${encodeURIComponent(contract.id)}`, {config: {operation_ids: values}}, "PATCH")));
      panel.append(selection);
      for (const operation of list(contract.operations)) {
        const key = operationKey(operation), local = localKey(operation), row = node("details", "", "workspace-operation"); row.dataset.operationId = key;
        const summary = node("summary"); summary.append(node("strong", `${operation.method} ${operation.path}`), node("span", operation.operation_id || operation.operationId || "No operationId"));
        const selected = check("Include this operation in the next plan", selectedIds.has(key) || selectedIds.has(local));
        selected.input.onchange = () => guarded(async () => {
          const ids = new Set(selectedIds); ids.delete(local); if (selected.input.checked) ids.add(key); else ids.delete(key);
          await mutate(`/contracts/${encodeURIComponent(contract.id)}`, {config: {operation_ids: [...ids]}}, "PATCH");
        });
        const operationBody = node("div", "", "workspace-operation-body"); operationBody.append(selected.wrapper, node("p", `Contract operation key: ${key}`, "workspace-muted"));
        const examples = field("Prepared request example (JSON)", pretty(config.examples?.[local] || {}), "textarea", "Use url, body and parameters as needed. Preparing data does not send a request or establish a successful control."); examples.input.className = "workspace-json";
        const expectation = field("Expected response and permission (JSON)", pretty(config.expectations?.[local] || {}), "textarea", "For example: {\"status\": \"200\"}. Negative expectations and business assertions belong only to this operation and identity."); expectation.input.className = "workspace-json";
        const assertions = field("Business assertions (JSON array)", pretty(config.assertions?.[local] || []), "textarea", "Each assertion may include purpose, pointer, operator and expected. Sharing a token does not verify roles or resource access."); assertions.input.className = "workspace-json";
        const editor = node("details", "", "workspace-disclosure"); editor.append(node("summary", "Prepare test data and assertions"), examples.wrapper, expectation.wrapper, assertions.wrapper, button("Save operation test data", async () => {
          await mutate(`/contracts/${encodeURIComponent(contract.id)}`, {review_operation_ids: [local], config: {
            examples: {...config.examples, [local]: jsonValue(examples.input, "Prepared request example")},
            expectations: {...config.expectations, [local]: jsonValue(expectation.input, "Expected response")},
            assertions: {...config.assertions, [local]: jsonValue(assertions.input, "Business assertions", "array")}}}, "PATCH", "Operation test data saved. No baseline replayed; review a new plan.");
        })); operationBody.append(editor);
        operationBody.append(detail("Inspect this operation's schema and examples", operation)); row.append(summary, operationBody); panel.append(row);
      }
      panel.append(detail("Contract schemas (isolated to this snapshot)", contract.spec?.schemas || contract.spec?.components?.schemas || contract.spec?.definitions || {}));
      panel.append(detail("Retained snapshot hashes", Object.keys(contract.snapshots || {})));
      const maintenance = node("details", "", "workspace-disclosure"); maintenance.append(node("summary", "Replace or remove this contract"), node("p", "Replacement retains the workspace contract identity and historical hashes. Other contracts and existing evidence remain separate.", "workspace-muted"));
      const replacement = node("input"); replacement.type = "file"; replacement.accept = ".json,.yaml,.yml"; replacement.setAttribute("aria-label", "Replacement contract file");
      maintenance.append(replacement, button("Replace contract", async () => {
        const file = replacement.files[0]; if (!file) throw Error("Choose a replacement OpenAPI file first.");
        await mutate(`/contracts/${encodeURIComponent(contract.id)}`, {raw_spec: await file.text(), filename: file.name}, "PATCH", "Contract replaced; review target, identity scope and overlap decisions again.");
      }), button("Remove contract from workspace", () => mutate(`/contracts/${encodeURIComponent(contract.id)}`, {}, "DELETE", "Contract removed from setup. Historical evidence retains its original contract snapshot.")));
      panel.append(maintenance); return panel;
    }
    function renderIdentities() {
      const introduction = section("Named bearer identities", "Create an identity once, then explicitly assign it to contracts and allowed API origins/base paths. Tokens remain masked and are never included in workspace exports.");
      introduction.append(callout("An assignment establishes only where credentials may be sent. It does not verify authentication, roles, resource access or business baselines."));
      const profileForm = node("div", "", "workspace-grid"), name = field("Profile name", "", "text"), token = field("Bearer token", "", "password", "The credential is held by the local server process. Only its reference and revision are exported.");
      name.input.id = "workspace-profile-name"; token.input.id = "workspace-profile-token"; token.input.autocomplete = "new-password";
      const persistence = selectField("Credential storage", [["session", "This session only"], ["windows", "Encrypted for this Windows user"]], "session");
      const windowsChoice = persistence.input.querySelector('option[value="windows"]');
      windowsChoice.disabled = !state.credentialCapabilities?.windows;
      if (!state.credentialCapabilities) api("/api/desktop/credentials", null, "GET").then(capabilities => { state.credentialCapabilities = capabilities; windowsChoice.disabled = !capabilities.windows; }).catch(() => { windowsChoice.disabled = true; });
      profileForm.append(name.wrapper, token.wrapper, persistence.wrapper); introduction.append(profileForm, button("Create identity profile", async () => {
        if (!name.input.value.trim() || !token.input.value.trim()) throw Error("Enter a profile name and bearer token.");
        const secret = token.input.value.trim(); token.input.value = "";
        await mutate("/profiles", {name: name.input.value.trim(), token: secret, persistence: persistence.input.value}, "POST", "Identity profile created. Explicitly assign it to selected contracts; no authentication request sent.");
      }, true)); body.append(introduction);
      const profiles = list(state.workspace.profiles);
      if (!profiles.length) { body.append(node("p", "No identity profiles. Contracts may also run without an identity where appropriate.", "workspace-empty")); return; }
      const share = section("Share across selected contracts", "Choose a profile and check only the contracts that should receive it. Confirm each allowed API base URL; unassigned contracts receive no shared token.");
      const profile = selectField("Identity profile", profiles.map(item => [item.id, `${item.name || item.id} · revision ${item.revision || 1}`]), profiles[0].id); profile.input.id = "workspace-shared-profile"; share.append(profile.wrapper);
      const assignments = [];
      for (const contract of state.workspace.contracts) {
        const row = node("div", "", "workspace-assignment"), chosen = check(contractTitle(contract), false, `${contract.target || "No target chosen"} · ${identityLabel(contract)}`);
        chosen.input.dataset.contractId = contract.id;
        const scopes = field("Allowed API base URLs, one per line", list(contract.identity?.allowed_scopes).join("\n") || contract.target || "", "textarea"); scopes.input.rows = 2; scopes.input.dataset.contractScope = contract.id;
        assignments.push({contract, chosen, scopes}); row.append(chosen.wrapper, scopes.wrapper); share.append(row);
      }
      share.append(button("Assign profile to selected contracts", async () => {
        const chosen = assignments.filter(item => item.chosen.input.checked); if (!chosen.length) throw Error("Select at least one contract for this shared identity.");
        for (const item of chosen) {
          const scopes = item.scopes.input.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
          if (!scopes.length) throw Error(`Set an explicit allowed API base URL for ${contractTitle(item.contract)}.`);
        }
        await withWorkspaceMutation(async () => {
          try {
            for (const item of chosen) await api(route(`/contracts/${encodeURIComponent(item.contract.id)}/identity`), {profile_id: profile.input.value, allowed_scopes: item.scopes.input.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean), override: false}, "PUT");
            status.textContent = "Explicit contract assignments saved. Overrides still take precedence. No requests sent.";
          } finally { await refresh(true); }
        });
      }, true)); body.append(share);
      const overrides = section("Contract identity assignments", "Contract-specific overrides take precedence over shared assignments. Removing an assignment stops future use in that scope.");
      for (const contract of state.workspace.contracts) {
        const row = node("div", "", "workspace-profile"); row.append(node("h4", contractTitle(contract)), node("p", identityLabel(contract)), node("p", `Allowed scopes: ${list(contract.identity?.allowed_scopes).join(", ") || "none"}`, "workspace-muted"));
        if (contract.scope_review_required) row.append(callout("Target changed: the identity scope must be explicitly confirmed again.", true));
        const chooser = selectField("Override profile", profiles.map(item => [item.id, item.name || item.id]), contract.identity?.profile_id || profiles[0].id);
        const scope = field("Allowed API base URLs, one per line", list(contract.identity?.allowed_scopes).join("\n") || contract.target || "", "textarea"); scope.input.rows = 2;
        const edit = node("details", "", "workspace-disclosure"); edit.append(node("summary", "Set a contract-specific override"), chooser.wrapper, scope.wrapper, button("Save contract override", () => mutate(`/contracts/${encodeURIComponent(contract.id)}/identity`, {profile_id: chooser.input.value, allowed_scopes: scope.input.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean), override: true}, "PUT")));
        const actions = node("div", "", "workspace-actions"); actions.append(button("Remove shared assignment", () => mutate(`/contracts/${encodeURIComponent(contract.id)}/identity`, {remove: true, override: false}, "PUT")), button("Remove override", () => mutate(`/contracts/${encodeURIComponent(contract.id)}/identity`, {remove: true, override: true}, "PUT"))); row.append(edit, actions); overrides.append(row);
      }
      body.append(overrides);
      const rotations = section("Rotate a credential", "Rotation invalidates affected reviewed plans and readiness conclusions. Re-review before execution.");
      for (const item of profiles) {
        const row = node("div", "", "workspace-profile"), value = field("Replacement bearer token", "", "password"); value.input.autocomplete = "new-password";
        row.append(node("h4", `${item.name || item.id} · revision ${item.revision || 1}`), node("p", `Identity reference: ${item.id}. Credential: ${item.credential_available === false || item.configured === false || item.available === false ? "not configured" : "••••••••"}`, "workspace-muted"), value.wrapper, button("Rotate credential", async () => {
          if (!value.input.value.trim()) throw Error("Enter a replacement bearer token.");
          const secret = value.input.value.trim(); value.input.value = "";
          await mutate("/profiles", {id: item.id, name: item.name, token: secret}, "POST", "Credential rotated. Affected reviewed plans are stale; no request sent.");
        })); rotations.append(row);
      }
      body.append(rotations);
    }
    function operationLabel(key) {
      for (const contract of state.workspace.contracts) {
        const operation = list(contract.operations).find(item => operationKey(item) === key);
        if (operation) return `${contractTitle(contract)} (${contract.id.slice(0, 8)}): ${operation.method} ${operation.path} · ${contract.target || "target not chosen"}`;
      }
      return typeof key === "string" ? key : pretty(key);
    }
    function renderOverlaps() {
      const panel = section("Review overlaps before execution", "Overlap uses the resolved API target and base path, method and request semantics. Similar operationIds or paths alone never merge contracts.");
      panel.append(callout("Keep separate assessments allows one exchange to support both only when the reviewed identity, inputs, assertions, media type and execution context match exactly. Reused evidence is labelled and counted once as network traffic."));
      if (!list(state.workspace.overlaps).length) panel.append(node("p", "No overlaps detected in the current contract targets. A target or contract change triggers a new review.", "workspace-empty"));
      const labels = {"identical-contract": "Identical contract imported twice", "duplicate-contract": "Identical contract imported twice", "same-operation": "Same operation in different contracts", "identical-operation": "Equivalent operation declarations", "conflicting-endpoint": "Conflicting endpoint declarations", "conflict": "Conflicting endpoint declarations", "potential-template-overlap": "Potentially overlapping path templates", "path-template": "Potentially overlapping path templates", "template-overlap": "Potentially overlapping path templates", "similar-path-different-target": "Similar paths on different targets or versions", "similar-path": "Similar paths on different targets or versions"};
      for (const overlap of list(state.workspace.overlaps)) {
        const row = node("div", "", "workspace-overlap"); row.dataset.overlapId = overlap.id;
        row.append(node("h4", labels[overlap.kind] || String(overlap.kind || "Operation overlap").replaceAll("-", " ")));
        if (overlap.reason || overlap.description) row.append(node("p", overlap.reason || overlap.description));
        const operations = list(overlap.operations), items = node("ul"); operations.forEach(key => items.append(node("li", operationLabel(key)))); row.append(items);
        if (overlap.decision) row.append(node("p", `Reviewed decision: ${typeof overlap.decision === "string" ? overlap.decision : overlap.decision.action}`, "workspace-muted"));
        if (overlap.requires_review === false) row.append(node("p", "Informational: these declarations remain separate.", "workspace-muted"));
        else {
          const controls = node("div", "", "workspace-overlap-controls"), action = selectField("Decision", [["", "Choose a decision"], ["owner", "Choose one owner"], ["exclude", "Exclude an operation"], ["separate", "Keep separate assessments"]], overlap.decision?.action || "");
          const operation = selectField("Owner or excluded operation", operations.map(key => [key, operationLabel(key)]), operations[0]);
          action.input.onchange = () => { operation.input.disabled = action.input.value === "separate"; };
          controls.append(action.wrapper, operation.wrapper, button("Save decision", async () => {
            if (!action.input.value) throw Error("Choose an overlap decision.");
            await mutate("/overlaps", {overlap_id: overlap.id, action: action.input.value, ...(action.input.value === "owner" ? {owner: operation.input.value} : {}), ...(action.input.value === "exclude" ? {excluded: [operation.input.value]} : {})});
          })); row.append(controls);
        }
        if (overlap.details) row.append(detail("Declaration differences", overlap.details)); panel.append(row);
      }
      panel.append(button("Continue to audit plan", () => activate("plan"), true)); body.append(panel);
    }
    function renderPlan() {
      const panel = section("Plan the complete workspace run", "Planning is offline. Review selected contracts, targets, identity assignments, overlap decisions, traffic and write permissions before starting.");
      const options = node("div", "", "workspace-grid"), budget = field("Shared request budget", state.plan?.options?.budget || 100, "number"), rate = field("Shared maximum requests / second", state.plan?.options?.requests_per_second || 2, "number"), concurrency = field("Shared concurrency", state.plan?.traffic?.concurrency || state.plan?.options?.concurrency || 4, "number");
      budget.input.id = "workspace-run-budget"; budget.input.min = "1"; rate.input.id = "workspace-run-rate"; rate.input.min = "0.1"; rate.input.step = "0.1";
      concurrency.input.id = "workspace-run-concurrency"; concurrency.input.min = "1"; concurrency.input.max = "16";
      const profile = selectField("Audit profile", [["passive", "Passive: contract and one response"], ["readonly", "Read-only checks"], ["thorough", "Read-only, thorough"], ["writes", "Write checks (explicit authorisation required)"]], state.plan?.options?.profile || "readonly"); profile.input.id = "workspace-audit-profile";
      const inventory = check("Include inventory traffic", Boolean(state.plan?.options?.inventory), "Inventory runs without credentials, separately from endpoint checks, and consumes the same shared request budget."); inventory.input.id = "workspace-inventory";
      options.append(budget.wrapper, rate.wrapper, concurrency.wrapper, profile.wrapper, inventory.wrapper); panel.append(options);
      const selectedIds = state.plan?.contract_ids || state.plan?.options?.contract_ids;
      const selections = state.workspace.contracts.map(contract => {
        const entry = check(contractTitle(contract), !selectedIds || selectedIds.includes(contract.id), `${contract.target || "Target required"} · ${identityLabel(contract)} · writes ${contract.config?.allow_mutating ? "authorised" : "not authorised"}`);
        entry.input.dataset.planContract = contract.id; panel.append(entry.wrapper); return {contract, entry};
      });
      const invalidate = () => { state.plan = null; status.textContent = "Plan settings changed. Build and review a fresh plan."; const execution = body.querySelector("#workspace-execution-review"); if (execution) execution.remove(); };
      [budget.input, rate.input, concurrency.input, profile.input, inventory.input, ...selections.map(item => item.entry.input)].forEach(input => input.addEventListener("change", invalidate));
      panel.append(button("Build offline plan", async () => {
        const total = Number(budget.input.value), pacing = Number(rate.input.value), workers = Number(concurrency.input.value), ids = selections.filter(item => item.entry.input.checked).map(item => item.contract.id);
        if (!Number.isInteger(total) || total < 1 || !Number.isFinite(pacing) || pacing <= 0) throw Error("Set a positive whole request budget and a positive rate limit.");
        if (!ids.length) throw Error("Select at least one contract.");
        if (!Number.isInteger(workers) || workers < 1 || workers > 16) throw Error("Shared concurrency must be a whole number from 1 to 16.");
        const result = await api(route("/plan"), {budget: total, requests_per_second: pacing, concurrency: workers, profile: profile.input.value, inventory: inventory.input.checked, contract_ids: ids, allow_mutating: profile.input.value === "writes"});
        state.plan = result.plan || result; state.plan.contract_ids ||= ids; render();
        status.textContent = "Offline plan built. Zero endpoint requests sent; review scope and prerequisites before starting.";
      }, true)); body.append(panel);
      if (state.plan) renderPlanReview();
    }
    function renderPlanReview() {
      const plan = state.plan, panel = section("Review this plan"); panel.id = "workspace-execution-review";
      const selectedIds = plan.contract_ids || plan.options?.contract_ids, selectedContracts = state.workspace.contracts.filter(contract => !selectedIds || selectedIds.includes(contract.id));
      panel.append(metrics([["Selected contracts", selectedContracts.length], ["Selected operation assessments", list(plan.operations).filter(operation => !operation.excluded).length], ["Shared network request limit", plan.options?.budget], ["Inventory", plan.options?.inventory ? "Included" : "Off"]]));
      panel.append(node("p", `Shared concurrency ${plan.traffic?.concurrency ?? plan.options?.concurrency ?? "profile default"}; maximum ${plan.options?.requests_per_second ?? "configured"} requests/second. Operations: ${plan.traffic?.operation_scheduling || "sequential, with bounded probes within the current operation"}. Conditional checks run only when their prerequisites and remaining budget permit.`));
      panel.append(table(["Contract / snapshot", "Target", "Identity and scope", "Limits and writes"], selectedContracts.map(contract => [
        `${contractTitle(contract)}\n${contract.hash}`, contract.target || "Target required", `${identityLabel(contract)}\n${list(contract.identity?.allowed_scopes).join("\n") || "No credential scope"}`, `${contract.config?.budget ?? "Shared limit only"}\nWrites ${contract.config?.allow_mutating ? "authorised for this contract" : "not authorised"}`])));
      if (list(plan.operations).length) {
        panel.append(table(["Operation", "Disposition", "Endpoint traffic and ceiling"], plan.operations.map(operation => {
          const traffic = operationTraffic(operation);
          return [operationLabel(operation.id || operation.operation_key || operation.operation_id), operation.reuse_from ? `Reuse evidence from ${operationLabel(operation.reuse_from)}` : operation.excluded ? "Excluded; no independent test" : "Own assessment", operation.excluded ? "0 independent requests" : operation.reuse_from ? "No additional dispatch; linked owner evidence" : `Baseline ${traffic.baseline} + schema cases ${traffic.schema}\n${traffic.conditionalFamilies} conditional probe/check families\nHard operation ceiling ${traffic.ceiling ?? "shared limit"}${list(operation.blockers).length ? `\n${operation.blockers.join("; ")}` : ""}`];
        })));
        for (const operation of plan.operations) if (!operation.excluded && !operation.reuse_from && operation.engine_plan) panel.append(planCaseReview(operation, operationLabel(operation.operation_key || operation.operation_id)));
      }
      if (list(plan.exclusions).length) panel.append(detail("Overlap exclusions (not independently tested)", plan.exclusions));
      panel.append(detail("Reviewed overlap decisions", plan.overlaps || state.workspace.decisions || []));
      const blockers = list(plan.blockers);
      if (blockers.length) { const messages = node("ul", "", "workspace-blockers"); blockers.forEach(item => messages.append(node("li", typeof item === "string" ? item : item.detail || item.reason || item.message || pretty(item)))); panel.append(callout("This plan has prerequisites to resolve before execution.", true), messages); }
      panel.append(callout(`Inventory: ${plan.options?.inventory ? "enabled and counted separately" : "disabled"}. Endpoint requests share one budget and rate limiter across all contracts. A shared identity supplies no additional write permission. ${plan.options?.inventory ? "Inventory runs without credentials." : "No inventory traffic will be sent."}`));
      const consent = check("I authorise this reviewed set of targets and operations", false, "Write requests may run only where this contract's permission and the reviewed audit profile both allow them."); consent.input.id = "workspace-run-consent"; panel.append(consent.wrapper);
      const start = button("Start reviewed workspace audit", async () => {
        if (!consent.input.checked) throw Error("Authorise the reviewed targets and operations first.");
        const result = await api(route("/runs"), {plan_id: plan.id});
        state.run = result; state.view = "evidence"; state.evidence = null; render();
        status.textContent = "Workspace run started. Network attempts are counted once across all contract assessments.";
        pollRun(result.run_id || result.id);
      }, true); start.id = "workspace-start-audit"; start.disabled = plan.ready === false || blockers.length > 0; panel.append(start, detail("Full reviewed plan", plan)); body.append(panel);
    }
    function runId(run) { return typeof run === "string" ? run : run.run_id || run.id; }
    async function openRun(id) {
      clearTimeout(state.polling); state.pollingVersion++;
      state.run = await api(`/api/runs/${encodeURIComponent(id)}`, null, "GET");
      state.evidence = await api(`/api/runs/${encodeURIComponent(id)}/export`, null, "GET"); state.view = "evidence"; render();
      if (state.run.active || ["starting", "running"].includes(state.run.status)) pollRun(id);
      status.textContent = "Retained run opened. Viewing does not replay requests.";
    }
    function pollRun(id) {
      clearTimeout(state.polling);
      const version = ++state.pollingVersion;
      const poll = async () => {
        try {
          const snapshot = await api(`/api/runs/${encodeURIComponent(id)}`, null, "GET");
          const evidence = await api(`/api/runs/${encodeURIComponent(id)}/export`, null, "GET");
          if (version !== state.pollingVersion) return;
          state.run = snapshot; state.evidence = evidence;
          if (state.view === "evidence") { const scroll = body.scrollTop; render(); body.scrollTop = scroll; }
          if (state.run.active || ["starting", "running"].includes(state.run.status)) state.polling = setTimeout(poll, 1000);
          else { status.textContent = `Run ${state.run.status || "finished"}. Retained partial evidence remains available.`; await refresh(false); }
        } catch (failure) { if (version !== state.pollingVersion) return; error.textContent = failure.message; status.textContent = "Run polling stopped. Reopen the retained run to inspect its server state."; }
      };
      state.polling = setTimeout(poll, 350);
    }
    function renderEvidence() {
      const panel = section("Workspace evidence", "Inspect retained contract assessments and their original snapshot. Viewing and exporting never replay requests.");
      const savedFile = node("input"); savedFile.type = "file"; savedFile.accept = ".json"; savedFile.hidden = true; savedFile.id = "workspace-report-file";
      savedFile.onchange = () => guarded(async () => {
        const file = savedFile.files[0]; if (!file) return;
        if (file.size > 32 * 1024 * 1024) throw Error("Saved reports are limited to 32 MiB.");
        const captured = JSON.parse(await file.text());
        if (!captured.workspace || !Array.isArray(captured.assessments)) throw Error("Choose a workspace run JSON. Single-contract exports open through the main workbench's Open saved audit action.");
        const sanitised = await api("/api/audit/import", captured);
        clearRun(); state.evidence = sanitised; state.run = {id: "imported-report", status: sanitised.run?.status || "historical", saved: true}; render();
        status.textContent = "Saved workspace report opened offline with credentials masked. No target requests sent.";
      });
      panel.append(button("Open saved run JSON", () => savedFile.click()), savedFile);
      const runs = list(state.workspace.runs);
      if (runs.length) {
        const controls = node("div", "", "workspace-report-nav");
        for (const run of runs) controls.append(button(`${typeof run === "object" ? run.status || "Run" : "Run"} ${String(runId(run)).slice(0, 10)}`, () => openRun(runId(run)))); panel.append(controls);
      }
      if (list(state.workspace.saved_runs).length) {
        const savedControls = node("div", "", "workspace-report-nav");
        list(state.workspace.saved_runs).forEach((saved, index) => savedControls.append(button(`Saved report ${index + 1}`, () => {
          clearRun(); state.evidence = saved; state.run = {id: `saved-${index + 1}`, status: saved.run?.status || "historical", saved: true}; render();
          status.textContent = "Saved report opened offline. No target requests sent.";
        }))); panel.append(savedControls);
      }
      const run = state.run, evidence = state.evidence;
      if (!run && !evidence) { panel.append(node("p", "No run selected. Open a retained run above, or build an offline audit plan. Older single-contract JSON exports remain available through the workbench's Open saved audit action.", "workspace-empty")); body.append(panel); return; }
      const actions = node("div", "", "workspace-actions");
      if (run?.active || ["starting", "running"].includes(run?.status)) {
        actions.append(button("Cancel workspace run", async () => {
          state.run = await api(`/api/runs/${encodeURIComponent(runId(run))}/stop`, {}); render();
          status.textContent = "Cancellation requested. In-flight requests may complete; partial evidence is retained.";
        }), button("Withdraw all write authorisation", async () => {
          state.run = await api(`/api/runs/${encodeURIComponent(runId(run))}/withdraw-writes`, {}); render(); status.textContent = "Write authorisation withdrawn for the active run.";
        }));
      }
      if (!run?.saved) actions.append(button("Refresh retained evidence", () => openRun(runId(run))));
      actions.append(button("Save run JSON", async () => download(run?.saved ? evidence : await api(`/api/runs/${encodeURIComponent(runId(run))}/export`, null, "GET"), `namazu-workspace-run-${runId(run)}.json`))); panel.append(actions);
      panel.append(node("p", `Run ${runId(run)} · ${run?.status || evidence?.run?.status || "historical"}`, "workspace-muted"));
      if (!evidence) { panel.append(node("p", "Waiting for retained receipts. A planned case is not a completed test.", "workspace-empty")); body.append(panel); return; }
      const workspace = evidence.workspace || {}, accounting = workspace.accounting || evidence.accounting || evidence.scope || {};
      panel.append(node("p", `Evidence workspace: ${workspace.title || state.workspace.title}${workspace.id ? ` (${workspace.id})` : ""}`, "workspace-muted"));
      panel.append(metrics([["Unique network attempts", accounting.unique_network_attempts ?? evidence.scope?.requests_sent ?? run?.requests_sent ?? "Unknown"], ["Contract assessments", accounting.contract_assessments ?? list(evidence.assessments).length], ["Reused assessments", accounting.reused_assessments ?? list(evidence.assessments).filter(item => item.evidence_reused).length], ["Overlap exclusions", accounting.overlap_exclusions ?? list(evidence.overlap_exclusions).length]]));
      panel.append(callout("Network attempts and contract assessments are different counts. Reused evidence is not an independent test. Uniform denials leave downstream behaviour unknown; these results do not establish API security coverage."));
      const groups = evidenceContracts(evidence, state.workspace, run);
      for (const group of groups) {
        const contract = group.contract || {}, contractPanel = node("details", "", "workspace-evidence-contract");
        const contractDisclosure = `${runId(run)}::${contract.id}::${contract.hash}`;
        contractPanel.open = state.reportExpanded.get(contractDisclosure) ?? groups.length === 1;
        contractPanel.addEventListener("toggle", () => state.reportExpanded.set(contractDisclosure, contractPanel.open));
        contractPanel.append(node("summary", `${contractTitle(contract)} · ${group.assessments.length} operation assessment${group.assessments.length === 1 ? "" : "s"}`));
        contractPanel.append(node("p", `${workspace.title || state.workspace.title} / ${contractTitle(contract)} / operation / field / case`, "workspace-breadcrumb"));
        contractPanel.append(facts([["Contract ID", contract.id], ["Snapshot hash", contract.hash || contract.snapshot_hash], ["Target", contract.target || contract.base_url], ["Identity reference", contract.identity_ref || contract.identity?.profile_id || "No identity configured"]]));
        if (group.audit && root.NamazuAuditResultsView) contractPanel.append(root.NamazuAuditResultsView.render(group.audit));
        for (const assessment of group.assessments) {
          const row = node("details", "", "workspace-assessment");
          const assessmentDisclosure = `${contractDisclosure}::${assessment.operation_key || assessment.operation_id}::${assessment.case_id}`;
          row.open = state.reportExpanded.get(assessmentDisclosure) || false;
          row.addEventListener("toggle", () => state.reportExpanded.set(assessmentDisclosure, row.open));
          row.append(node("summary", assessment.operation || assessment.operation_id || assessment.operation_key || assessment.id || "Operation assessment"));
          const context = node("div", "", "workspace-evidence-context"); context.setAttribute("aria-label", "Evidence contract context");
          const contextHash = assessment.snapshot_hash || assessment.contract_hash || contract.hash;
          const contextIdentity = assessment.identity_ref || contract.identity_ref || contract.identity?.profile_id;
          const contextTitle = node("strong", `${contractTitle(contract)} (${String(contract.id || assessment.contract_id || "unknown").slice(0, 8)})`);
          const contextTarget = node("span", assessment.target || contract.target || "Target not recorded", "workspace-evidence-target");
          const contextIdentityText = node("span", contextIdentity ? `Identity ${String(contextIdentity).slice(0, 10)} · revision ${assessment.identity_revision ?? contract.identity?.revision ?? "unknown"}` : "No identity configured");
          contextIdentityText.title = contextIdentity || "No identity configured";
          const contextSnapshot = node("span", `Snapshot ${shortHash(contextHash)}`); contextSnapshot.title = contextHash || "Snapshot hash not recorded";
          context.append(contextTitle, contextTarget, contextIdentityText, contextSnapshot); row.append(context);
          row.append(facts([["Snapshot hash", assessment.snapshot_hash || assessment.contract_hash || contract.hash], ["Target", assessment.target || contract.target], ["Identity reference", assessment.identity_ref || "No identity configured"], ["Evidence", assessment.evidence_reused || assessment.reused_from || assessment.reuse_from ? `Reused from ${assessment.evidence_owner_operation_key || assessment.reused_from || assessment.reuse_from}; zero additional dispatches` : assessment.assessment_status === "excluded" || assessment.excluded ? "Excluded; not independently tested" : assessment.assessment_status === "budget-excluded" ? "Budget exhausted; not independently tested" : "Own recorded exchanges"]]));
          if (assessment.evidence_reused) row.append(callout("This assessment references the owner's captured exchanges. The case labels below describe that original evidence; no additional request was dispatched for this contract assessment."));
          const result = assessment.audit || assessment.result || assessment;
          if (result && root.NamazuAuditResultsView) row.append(root.NamazuAuditResultsView.render(asAudit(result, assessment)));
          if (list(result?.findings || assessment.findings).length) row.append(detail("Recorded findings (contract-scoped)", result?.findings || assessment.findings));
          if (assessment.evidence_refs || assessment.attempt_ids) row.append(detail("Network evidence references", assessment.evidence_refs || assessment.attempt_ids));
          row.append(detail("Assessment record", assessment)); contractPanel.append(row);
        }
        panel.append(contractPanel);
      }
      if (!groups.length) panel.append(node("p", "Contract assessment receipts are not yet retained. No operation coverage is inferred from traffic totals.", "workspace-empty"));
      if (list(evidence.overlap_exclusions || workspace.exclusions).length) panel.append(detail("Excluded overlaps (not independently tested)", evidence.overlap_exclusions || workspace.exclusions));
      panel.append(detail("Run provenance, plan and accounting", {run: evidence.run, scope: evidence.scope, accounting, plan: workspace.reviewed_plan || workspace.plan, snapshots: evidence.contract_snapshots || workspace.snapshots})); body.append(panel);
    }
    opener.onclick = () => guarded(async () => {
      if (!dialog.open) dialog.showModal();
      if (state.saving) return;
      if (state.workspace) { render(); return; }
      const response = await api("/api/workspaces", null, "GET"), workspaces = list(response.workspaces || response);
      if (workspaces.length) updateWorkspace(await api(`/api/workspaces/${encodeURIComponent(workspaces[0].id)}`, null, "GET"));
      else updateWorkspace(await api("/api/workspaces", {title: "API workspace"}));
    });
    return {state, dialog, render, openRun, openWorkspaceFile() { document.getElementById("workspace-saved-file")?.click(); },
      async open({workspace, workspaceId, view = "contracts", contractId, inlineHost} = {}) {
        if (state.saving) throw Error("Wait for the current workspace change to finish.");
        if (inlineHost) { if (dialog.open) dialog.close(); inlineHost.append(frame); state.inline = true; }
        else { if (frame.parentNode !== dialog) dialog.append(frame); state.inline = false; if (!dialog.open) dialog.showModal(); }
        state.view = view;
        if (workspace) updateWorkspace(workspace, state.workspace?.id !== workspace.id);
        else if (workspaceId) updateWorkspace(await api(`/api/workspaces/${encodeURIComponent(workspaceId)}`, null, "GET"));
        else if (!state.workspace) updateWorkspace(await api("/api/workspaces", {title: "API workspace"}));
        if (contractId) state.selected = contractId;
        render(); body.scrollTop = 0;
      },
    };
  }

  function asAudit(result, assessment = {}) {
    // Reuse the existing evidence classification/field-case view without rewriting receipts.
    if (result.test_plans || Array.isArray(result.requests)) return result;
    const operation = assessment.operation || assessment.operation_id || result.operation_id;
    return {...result, log: result.log || result.exchanges || [], probes: result.probes || result.coverage?.probes || [],
      plans: result.plans || (result.test_plan ? [{endpoint: operation, operation_id: result.test_plan.operation, test_plan: result.test_plan}] : []),
      baselines: result.baselines || result.coverage?.baselines || (result.baseline ? [{endpoint: operation, exchange: result.baseline}] : []),
      fieldCoverage: result.field_coverage || result.fieldCoverage || result.coverage?.fields || [],
      context: {...result.context, run_id: [assessment.workspace_id, assessment.contract_id, assessment.operation_key, assessment.snapshot_hash].filter(Boolean).join("::"), base_url: assessment.target}};
  }
  function evidenceContracts(evidence, currentWorkspace = {}, run = {}) {
    const workspace = evidence.workspace || {}, contracts = list(evidence.contracts || workspace.contracts), assessments = list(workspace.assessments || evidence.assessments);
    const groups = new Map();
    for (const contract of contracts) groups.set(contract.id || contract.contract_id, {contract: {...contract, id: contract.id || contract.contract_id}, assessments: [], audit: contract.audit || contract.result});
    const records = assessments.length ? assessments : list(run?.cases).filter(item => item.result?.contract_id || item.result?.workspace?.contract_id).map(item => ({...item.result.workspace, ...item.result, operation: item.operation, result: item.result}));
    for (const assessment of records) {
      const id = assessment.contract_id || assessment.contract?.id;
      if (!id) continue;
      if (!groups.has(id)) {
        const current = list(currentWorkspace.contracts).find(contract => contract.id === id) || {};
        // Historical metadata always wins over mutable setup; do not label old evidence with a new hash.
        groups.set(id, {contract: {id, title: assessment.contract_title || current.title || id,
          version: assessment.contract_version, hash: assessment.snapshot_hash || assessment.contract_hash,
          target: assessment.target, identity_ref: assessment.identity_ref}, assessments: []});
      }
      groups.get(id).assessments.push(assessment);
    }
    return [...groups.values()];
  }

  root.NamazuWorkspaces = {mount, evidenceContracts, asAudit, identityLabel, contractTitle, operationTraffic, planCaseReview};
  if (typeof document !== "undefined") root.NamazuWorkspaces.instance = mount();
})(typeof window === "undefined" ? globalThis : window);
