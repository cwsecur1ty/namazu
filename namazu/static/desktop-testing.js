/* Explicit, bounded native campaigns and case-scoped out-of-band observations. */
(function (root) {
  "use strict";
  const clone = value => JSON.parse(JSON.stringify(value));
  function applyCallback(draft, field, payload) {
    const next = clone(draft), location = field.location;
    if (location === "query") {
      if (!field.name) throw Error("Choose the query parameter name.");
      next.parameters = {...next.parameters, [`query.${field.name}`]: payload};
      if (next.manualUrl) { const url = new URL(next.url); url.searchParams.set(field.name, payload); next.url = url.href; }
    } else if (location === "header") {
      if (!field.name || root.NamazuDesktopModel.secretName(field.name)) throw Error("Choose a noncredential request header.");
      next.headers = {...next.headers, [field.name]: payload};
    } else if (location === "body") {
      if (!field.pointer?.startsWith("/")) throw Error("Use a JSON pointer such as /callbackUrl.");
      let value; try { value = JSON.parse(next.body); } catch { throw Error("Generate or enter a JSON body before inserting the callback."); }
      const parts = field.pointer.slice(1).split("/").map(part => part.replace(/~1/g, "/").replace(/~0/g, "~"));
      if (parts.some(part => ["__proto__", "prototype", "constructor"].includes(part))) throw Error("That field pointer is not supported.");
      let parent = value;
      for (const part of parts.slice(0, -1)) { if (!parent || typeof parent !== "object" || !Object.prototype.hasOwnProperty.call(parent, part)) throw Error("The JSON pointer's parent must exist in this draft."); parent = parent[part]; }
      if (!parent || typeof parent !== "object") throw Error("The JSON pointer must identify a body property.");
      const leaf = parts.at(-1); if (Array.isArray(parent) && (!/^\d+$/.test(leaf) || Number(leaf) >= parent.length)) throw Error("The JSON pointer must identify an existing array item.");
      parent[leaf] = payload; next.body = JSON.stringify(value, null, 2); next.bodyEntered = true;
    } else throw Error("Choose a body, query or header field.");
    return next;
  }
  function create(context) {
    const host = document.getElementById("desktop-testing"), state = {cases: [], selected: null, openRevision: 0, setup: {kind: "url-fetch", location: "body", field: "/callbackUrl", callback: ""}};
    const node = (tag, text, cls) => { const value = document.createElement(tag); if (text != null) value.textContent = String(text); if (cls) value.className = cls; return value; };
    const button = (label, action, cls = "btn sm") => { const value = node("button", label, cls); value.type = "button"; value.onclick = () => context.guard(action); return value; };
    const field = (label, value = "", type = "text") => { const wrapper = node("label", "", "workspace-field"), input = node(type === "textarea" ? "textarea" : "input"); if (type !== "textarea") input.type = type; input.value = value; input.setAttribute("aria-label", label); wrapper.append(node("span", label), input); return {wrapper, input}; };
    const select = (label, options, selected) => { const wrapper = node("label", "", "workspace-field"), input = node("select"); input.setAttribute("aria-label", label); for (const [value, text] of options) { const option = node("option", text); option.value = value; input.append(option); } input.value = selected; wrapper.append(node("span", label), input); return {wrapper, input}; };
    const check = label => { const wrapper = node("label", "", "workspace-check"), input = node("input"); input.type = "checkbox"; input.setAttribute("aria-label", label); wrapper.append(input, node("span", label)); return {wrapper, input}; };
    const code = value => node("pre", JSON.stringify(value, null, 2), "workspace-code");
    const route = suffix => `/api/oob/cases${suffix}`;
    async function load() { const workspace = context.workspace(); if (!workspace) return; const result = await context.api(`${route("")}?workspace_id=${encodeURIComponent(workspace.id)}`, null, "GET"); if (context.workspace()?.id === workspace.id) state.cases = result.cases || result || []; }
    async function open() {
      const revision = ++state.openRevision; context.show();
      const loading = node("p", "Loading recorded cases. Request editors will be ready when loading finishes."); loading.setAttribute("role", "status");
      host.replaceChildren(node("h2", "Fuzzing & OOB"), loading); host.setAttribute("aria-busy", "true");
      try { await load(); } catch (failure) { if (revision === state.openRevision) context.status(`OOB evidence could not be loaded: ${failure.message}`); }
      if (revision === state.openRevision) { host.setAttribute("aria-busy", "false"); render(); }
    }
    function render() {
      host.replaceChildren(node("h2", "Fuzzing & OOB"), node("p", "Native schema mutations use the existing reviewed audit engine. Out-of-band cases use an explicitly supplied callback session and retain their own correlation and evidence provenance."));
      const workspace = context.workspace(); if (!workspace?.contracts?.length) { host.append(button("Import contracts first", () => context.workspaceView("contracts"))); return; }
      const columns = node("div", "", "desktop-testing-columns"), fuzz = node("section", "", "desktop-testing-section"), oob = node("section", "", "desktop-testing-section");
      fuzz.append(node("h3", "Bounded native fuzzing"), node("p", "Review deterministic omission, null, type and boundary cases for declared request fields. These profiles also include the existing security checks; only recorded receipts establish what ran."));
      const profile = select("Native campaign profile", [["readonly", "Read-only: schema mutations and controls"], ["thorough", "Thorough: includes timing and rate probes"], ["writes", "Writes: explicit per-contract authorisation"]], "readonly"), budget = field("Campaign shared request limit", 100, "number"), rate = field("Campaign requests per second", 2, "number"), concurrency = field("Campaign shared concurrency", 4, "number"); budget.input.min = "1"; rate.input.min = "0.1"; rate.input.step = "0.1"; concurrency.input.min = "1"; concurrency.input.max = "16";
      const selected = [];
      fuzz.append(profile.wrapper, budget.wrapper, rate.wrapper, concurrency.wrapper);
      for (const contract of workspace.contracts) {
        const input = check(`${contract.title}: selected operations`); input.input.checked = true;
        const ids = contract.config?.operation_ids || [], count = contract.operations.filter(operation => ids.includes(operation.id) || ids.includes(operation.local_id)).length;
        input.wrapper.append(node("small", `${count} operations · ${contract.target || "target required"} · contract limit ${contract.config?.budget ?? "shared"} · writes ${contract.config?.allow_mutating ? "authorised" : "off"}`)); fuzz.append(input.wrapper); selected.push({contract, input});
      }
      const writes = check("Authorise writes for this campaign run"); writes.input.disabled = true;
      profile.input.onchange = () => { writes.input.checked = false; writes.input.disabled = profile.input.value !== "writes"; };
      fuzz.append(writes.wrapper, button("Choose operations and per-contract limits", () => context.workspaceView("contracts")), button("Review native fuzzing plan", async () => {
        const limit = Number(budget.input.value), rps = Number(rate.input.value), workers = Number(concurrency.input.value), ids = selected.filter(item => item.input.input.checked).map(item => item.contract.id);
        if (!Number.isInteger(limit) || limit < 1 || !Number.isFinite(rps) || rps <= 0 || !ids.length) throw Error("Choose contracts and positive request limits.");
        if (profile.input.value === "writes" && !writes.input.checked) throw Error("Explicitly authorise writes before planning this write campaign.");
        if (!Number.isInteger(workers) || workers < 1 || workers > 16) throw Error("Campaign shared concurrency must be a whole number from 1 to 16.");
        const plan = await context.api(`/api/workspaces/${workspace.id}/plan`, {budget: limit, requests_per_second: rps, concurrency: workers, profile: profile.input.value, inventory: false, contract_ids: ids, allow_mutating: writes.input.checked});
        await context.reviewPlan(plan.plan || plan, workspace.id); context.status("Native campaign planned offline. Review exact fields, cases, prerequisites and traffic before starting.");
      }, "btn primary"));
      oob.append(node("h3", "Out-of-band correlation"), node("p", "Bring a callback base from an Interactsh session you explicitly control, including a self-hosted session. Namazu does not register, poll or contact that callback host. Preparing a case sends no request."));
      const tab = context.activeTab(), contract = workspace.contracts.find(item => item.id === tab?.contractId);
      if (!tab || !contract) oob.append(node("p", "Open a request from the collection to prepare a case for an exact contract, operation and snapshot."));
      else {
        oob.append(node("p", `${contract.title} · ${tab.localOperationId} · snapshot ${tab.snapshotHash.slice(0, 12)} · identity ${contract.identity?.profile_id || "none"}`, "desktop-testing-context"));
        const callback = field("Explicit callback base URL", state.setup.callback), kind = select("OOB case purpose", [["url-fetch", "URL fetch / SSRF hypothesis"], ["blind-injection", "Blind injection hypothesis"], ["xxe", "XML external entity hypothesis"], ["other", "Other callback observation"]], state.setup.kind), location = select("OOB input location", [["body", "JSON body property"], ["query", "Query parameter"], ["header", "Request header"]], state.setup.location), name = field("Field name or JSON pointer", state.setup.field), consent = check("I control this callback session and authorise its use");
        callback.input.placeholder = "https://your-session.your-callback-host";
        callback.input.oninput = () => { state.setup.callback = callback.input.value; }; kind.input.onchange = () => { state.setup.kind = kind.input.value; }; location.input.onchange = () => { state.setup.location = location.input.value; }; name.input.oninput = () => { state.setup.field = name.input.value; };
        oob.append(callback.wrapper, kind.wrapper, location.wrapper, name.wrapper, consent.wrapper, button("Prepare OOB case in this request", async () => {
          if (!consent.input.checked) throw Error("Confirm control of the explicit callback session before preparing a case.");
          const current = context.activeTab(); if (current?.id !== tab.id) throw Error("The selected request changed. Reopen OOB setup for the intended request.");
          const input = location.input.value === "body" ? {location: "body", pointer: name.input.value.trim()} : {location: location.input.value, name: name.input.value.trim()};
          applyCallback(current.draft, input, "https://callback.invalid/preview");
          const draftVersion = JSON.stringify(current.draft), created = await context.api(route(""), {workspace_id: tab.workspaceId, contract_id: tab.contractId, snapshot_hash: tab.snapshotHash, operation_key: tab.operationKey, callback_base: callback.input.value.trim(), callback_scope_confirmed: true, kind: kind.input.value, field: input, ttl_seconds: 86400});
          state.cases.unshift(created); state.selected = created.id;
          if (context.activeTab()?.id !== tab.id || JSON.stringify(context.activeTab().draft) !== draftVersion) { render(); throw Error("The case was prepared, but your request changed. Your edits were retained; use Insert payload after reviewing the case."); }
          context.applyDraft(tab.id, applyCallback(current.draft, input, created.payload), created.id);
          context.status("OOB case prepared and inserted into this draft. Review the request and explicitly Send it; write consent has been cleared.");
          render();
        }, "btn primary"));
      }
      columns.append(fuzz, oob); host.append(columns); renderCases();
    }
    function renderCases() {
      const section = node("section", "", "desktop-testing-evidence"); section.append(node("h3", "Callback evidence"), node("p", "Imported collector events remain external reports with explicit verification state. A callback observation alone does not establish exploitability or successful resource access."));
      const importFile = node("input"); importFile.type = "file"; importFile.accept = ".json,application/json"; importFile.hidden = true;
      importFile.onchange = () => context.guard(async () => { const file = importFile.files[0]; if (!file) return; const payload = JSON.parse(await file.text()); await context.api("/api/oob/import", payload); await load(); render(); context.status("Historical OOB evidence opened without replaying any target or callback request."); });
      section.append(button("Refresh recorded cases", async () => { await load(); render(); }), button("Open OOB evidence JSON", () => importFile.click()), importFile);
      if (!state.cases.length) section.append(node("p", "No out-of-band cases have been prepared in this workspace."));
      for (const item of state.cases) {
        const details = node("details", "", "desktop-oob-case"); details.open = state.selected === item.id; details.ontoggle = () => { if (details.open) state.selected = item.id; };
        details.append(node("summary", `${item.kind || "OOB"} · ${item.context?.operation_key || item.id} · ${item.status || "prepared"}`));
        const inner = node("div", "", "desktop-oob-case-content"); inner.append(node("p", `Contract ${item.context?.contract_id} · snapshot ${item.context?.snapshot_hash} · target ${item.context?.target} · identity ${item.context?.identity_ref || "none"}`, "desktop-testing-context"), node("pre", item.payload || "", "workspace-code"), node("p", `Case ${item.id}. ${item.receipts?.length || 0} linked network receipts; ${item.interactions?.length || 0} imported interactions. Correlation actions send no network requests.`));
        inner.append(node("p", `Payload eligibility: ${item.can_use_payload ? "current, within its correlation window" : "expired, retired, historical or changed context; prepare a new case"}. Expires ${item.expires_at || "not recorded"}. Verification: imported collector records are unverified; security impact is not established.`));
        const insert = button("Insert payload into selected draft", async () => { const fresh = await context.api(`${route("/")}${item.id}`, null, "GET"); if (!fresh.can_use_payload) throw Error("This callback case is no longer eligible. Prepare a new case for the current context."); const tab = context.activeTab(); if (!tab || tab.workspaceId !== item.context?.workspace_id || tab.contractId !== item.context?.contract_id || tab.operationKey !== item.context?.operation_key || tab.snapshotHash !== item.context?.snapshot_hash) throw Error("Select the exact contract operation and snapshot this case belongs to."); context.applyDraft(tab.id, applyCallback(tab.draft, item.field, item.payload), item.id); context.status("Case payload inserted. Review the draft and explicitly send; write consent is off."); }); insert.disabled = !item.can_use_payload;
        inner.append(insert, button("Review current request", () => context.requestView()), button("Export OOB evidence", async () => context.download(await context.api(`${route("/")}${item.id}/export`, null, "GET"), `namazu-oob-${item.id}.json`)), button("Remove case link from selected draft", () => { context.unlinkCase(item.id); context.status("Case association removed from this draft. The request field is unchanged; review it before sending."); }));
        if (!item.retired && !item.historical) inner.append(button("Retire callback case", async () => { updateCase(await context.api(`${route("/")}${item.id}/retire`, {})); render(); context.status("Case retired for future payload use. Already submitted requests or callbacks are not retracted."); }));
        const receipt = field("Existing request receipt ID", context.activeTab()?.lastRequestId || ""); inner.append(receipt.wrapper, button("Link captured request receipt", async () => { const updated = await context.api(`${route("/")}${item.id}/receipts`, {request_id: receipt.input.value.trim()}); updateCase(updated); render(); context.status("Existing network receipt linked. No new request was dispatched or counted."); }));
        const events = field("Interactsh events (JSONL)", "", "textarea"), source = field("Collector source name", "Imported Interactsh JSONL"), file = node("input"); file.type = "file"; file.accept = ".jsonl,.json,.txt,application/json"; file.setAttribute("aria-label", "Import Interactsh JSONL file"); file.onchange = () => context.guard(async () => { const selected = file.files[0]; if (selected) { if (selected.size > 8 * 1024 * 1024) throw Error("Interaction files are limited to 8 MiB."); events.input.value = await selected.text(); source.input.value = selected.name; } });
        inner.append(events.wrapper, file, source.wrapper, button("Correlate imported events", async () => { const response = await context.api(`${route("/")}${item.id}/interactions`, {jsonl: events.input.value, source_name: source.input.value.trim()}); updateCase(response.case || response); render(); const counts = response.import || {}; context.status(`Offline correlation: ${counts.matched || 0} matched, ${counts.unmatched || 0} unmatched, ${counts.duplicates || 0} duplicates. Imported records remain unverified; no security impact inferred.`); }));
        if (item.accounting) inner.append(code(item.accounting));
        for (const [label, entries] of [["Matched interaction records", item.interactions], ["Unmatched interaction records", item.unmatched_interactions], ["Linked network receipts", item.receipts], ["Import provenance and errors", item.imports]]) if (entries?.length) { const evidence = node("details"); evidence.append(node("summary", `${label} (${entries.length})`)); let loaded = false; evidence.ontoggle = () => { if (evidence.open && !loaded) { loaded = true; evidence.append(code(entries.slice(0, 100))); if (entries.length > 100) evidence.append(node("p", "Showing the first 100 records. The exact export retains every record.")); } }; inner.append(evidence); }
        details.append(inner); section.append(details);
      }
      host.append(section);
    }
    function updateCase(item) { item = item.case || item; const index = state.cases.findIndex(value => value.id === item.id); if (index >= 0) state.cases[index] = item; else state.cases.unshift(item); state.selected = item.id; }
    async function linkReceipts(caseIds, requestId) { const errors = []; for (const id of caseIds || []) { try { updateCase(await context.api(`${route("/")}${id}/receipts`, {request_id: requestId})); } catch (failure) { errors.push(failure.message); } } return errors; }
    async function validateCases(caseIds) { for (const id of caseIds || []) { const item = await context.api(`${route("/")}${id}`, null, "GET"); if (!item.can_use_payload) throw Error("A linked OOB case is expired, retired or belongs to a changed context. Review it and prepare a new case before sending."); } }
    return {open, render, linkReceipts, validateCases};
  }
  root.NamazuDesktopTesting = {create, applyCallback};
  if (typeof module !== "undefined" && module.exports) module.exports = root.NamazuDesktopTesting;
})(typeof window === "undefined" ? globalThis : window);
