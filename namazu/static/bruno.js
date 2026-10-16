"use strict";
// Imported code is displayed as text only. All conversion endpoints are offline.
window.NamazuBruno = {
  renderReport(bruno, body, showTraffic) {
    const root = document.createElement("div"); root.className = "bruno-native-report"; body.append(root);
    const add = (tag, text) => { const n = document.createElement(tag); n.textContent = text; root.append(n); return n; };
    add("h2", "Imported Bruno run");
    add("p", `${bruno.recorded_executions} recorded executions · ${bruno.recorded_iterations ?? "unknown"} iterations · ${bruno.observed_responses} recorded HTTP responses. Exact wire attempts and execution time are unknown. Zero requests sent during import or viewing.`);
    for (const [kind, counts] of Object.entries(bruno.assertion_counts || {})) add("p", `${kind}: ${counts.pass} passed, ${counts.fail} failed, ${counts.unknown} unknown.`);
    add("p", "These are historical observations. Bruno assertions are separate from Namazu vulnerabilities. No field mutations, baseline comparisons or successful business controls were inferred. Uniform application denials leave downstream handling unknown.");
    const observations = new Map();
    for (const row of bruno.executions || []) observations.set(row.observation, (observations.get(row.observation) || 0) + 1);
    for (const [kind, count] of observations) add("p", `${kind}: ${count} recorded executions`);
    const button = add("button", "Inspect captured requests and responses"); button.className = "btn"; button.onclick = showTraffic;
    add("p", `Redacted source: ${bruno.source_id}. Reopen Bruno to inspect assertion details and source references. No additional field coverage is implied.`);
  },
  exportEvidencePayload(audit, payload) {
    if (!audit.brunoOriginal) return payload;
    const original = audit.brunoOriginal;
    return {...payload, bruno: original.bruno, started_at: original.started_at,
      requests: payload.requests || original.requests, api: original.api, run: original.run,
      scope: original.scope,
      provenance: {...original.provenance, requests_sent_during_current_action: 0,
        ...(payload.provenance?.kind === "offline-reassessment" ? {kind:"offline-reassessment",source_kind:"imported-bruno-run"} : {})}};
  },
  mount(host) {
    const node = (tag, text, cls) => { const n = document.createElement(tag); if (text) n.textContent = text; if (cls) n.className = cls; return n; };
    const dialog = node("dialog", "", "bruno-dialog");
    dialog.id = "bruno-dialog"; dialog.setAttribute("aria-labelledby", "bruno-title");
    const head = node("div", "", "bruno-heading"), title = node("h2", "Bruno interoperability"); title.id = "bruno-title";
    const close = node("button", "Close", "btn"); close.type = "button"; close.onclick = () => dialog.close(); head.append(title, close);
    const status = node("p", "Import, mapping and export are offline. Zero target requests sent.", "hint"); status.setAttribute("role", "status"); status.id = "bruno-status";
    const error = node("p", "", "msg error"); error.setAttribute("role", "alert"); error.hidden = true;
    const intro = node("p", "CLI 4.2.1 JSON reports and Bruno .bru definitions. Assertions are separate from HTTP responses and security findings. Collections are not response contracts.");
    intro.id = "bruno-input-explanation";
    const namesLabel = node("label", "Additional credential names (comma separated)");
    const names = node("input"); names.id = "bruno-credential-names"; names.placeholder = "X-Workspace-Key, accessCode"; namesLabel.htmlFor = names.id;
    const actions = node("div", "", "bruno-actions");
    const reportInput = node("input"); reportInput.type = "file"; reportInput.accept = ".json"; reportInput.hidden = true;
    reportInput.id = "bruno-report-file";
    const fileInput = node("input"); fileInput.type = "file"; fileInput.accept = ".bru,.json"; fileInput.multiple = true; fileInput.hidden = true;
    fileInput.id = "bruno-definition-files";
    const folderInput = node("input"); folderInput.type = "file"; folderInput.multiple = true; folderInput.setAttribute("webkitdirectory", ""); folderInput.hidden = true;
    folderInput.id = "bruno-collection-folder";
    const button = (text, fn) => { const b = node("button", text, "btn"); b.type = "button"; b.onclick = () => guarded(fn); return b; };
    const reportButton = button("Import Bruno run (JSON)", () => reportInput.click()); reportButton.id = "bruno-import-report";
    actions.append(reportButton, button("Import .bru files", () => fileInput.click()), button("Import collection folder", () => folderInput.click()), button("Choose Namazu requests to export", loadNative));
    const environmentBox = node("div", "", "field"); environmentBox.hidden = true;
    const envLabel = node("label", "Explicit environment selection"); envLabel.htmlFor = "bruno-environment";
    const env = node("select"); env.id = "bruno-environment";
    environmentBox.append(envLabel, env, button("Resolve selected environment", resolveCollection));
    const summary = node("p", "", "bruno-summary"); summary.id = "bruno-summary";
    const list = node("div", "", "bruno-results"); list.id = "bruno-results";
    const outputActions = node("div", "", "bruno-actions");
    const openEvidence = button("Open in Namazu evidence views", async () => { if (!evidence) throw Error("Import a Bruno run first."); await host.openEvidence(evidence); dialog.close(); });
    const saveEvidence = button("Export redacted evidence + source", () => { if (!evidence) throw Error("Import a Bruno run first."); download(JSON.stringify(evidence, null, 2), "namazu-bruno-evidence.json", "application/json"); });
    const addWorkspace = button("Add definitions to current workspace", async () => {
      if (!input?.files || !rows.length) throw Error("Import definitions and resolve their environment first.");
      if (!window.NamazuDesktop?.addBrunoCollection) throw Error("Open the request workspace before adding definitions.");
      const result = await window.NamazuDesktop.addBrunoCollection({...input, credential_names: credentialNames()});
      status.textContent = result.duplicate ? "This definition snapshot already exists in the workspace; no duplicate requests were added." : "Definitions added as a separate request collection. No response contract, successful control or identity assignment was inferred.";
      dialog.close();
    }); addWorkspace.id = "bruno-add-workspace"; addWorkspace.disabled = true;
    outputActions.append(addWorkspace, openEvidence, saveEvidence);
    const mapping = node("details", "", "bruno-mapping"); mapping.append(node("summary", "Prepare one explicitly selected baseline"));
    mapping.append(node("p", "Select one request above and a matching imported OpenAPI operation below. Map its identity and define resource/content assertions. This prepares a template; it does not establish business success or authorise a run."));
    const form = node("div", "", "bruno-fields");
    const field = (label, input, id) => { const wrap = node("div", "", "field"), l = node("label", label); input.id = id; l.htmlFor = id; wrap.append(l, input); form.append(wrap); return input; };
    const operation = field("OpenAPI operation", node("select"), "bruno-operation");
    const identity = field("Mapped Namazu identity", node("select"), "bruno-identity");
    for (const value of ["", "primary"]) { const option = node("option", value || "Choose identity"); option.value = value; identity.append(option); }
    const expected = field("Expected HTTP status", node("input"), "bruno-expected"); expected.placeholder = "200";
    const resourcePointer = field("Resource JSON Pointer", node("input"), "bruno-resource-pointer"); resourcePointer.placeholder = "/id";
    const resourceValue = field("Expected resource value (JSON or text)", node("input"), "bruno-resource-value"); resourceValue.placeholder = "local-widget";
    const contentPointer = field("Content JSON Pointer", node("input"), "bruno-content-pointer"); contentPointer.placeholder = "/owner";
    const contentValue = field("Expected content value (JSON or text)", node("input"), "bruno-content-value"); contentValue.placeholder = "fixture-user";
    const negative = node("input"); negative.type = "checkbox"; negative.id = "bruno-negative";
    const negativeLabel = node("label", "Expected denial (never a successful positive control)"); negativeLabel.prepend(negative);
    const confirm = node("input"); confirm.type = "checkbox"; confirm.id = "bruno-identity-confirmed";
    const confirmLabel = node("label", "I reviewed this request and mapped its credentials to the selected local identity"); confirmLabel.prepend(confirm);
    const prepared = node("p", "", "hint"); prepared.id = "bruno-prepared";
    mapping.append(form, negativeLabel, confirmLabel, button("Prepare and save baseline template", prepare), prepared);
    const conversion = node("section", "", "bruno-conversion");
    const warningList = node("ul"); warningList.id = "bruno-export-warnings";
    const exportPreview = node("pre"); exportPreview.id = "bruno-export-preview"; exportPreview.hidden = true;
    const acknowledged = node("input"); acknowledged.type = "checkbox"; acknowledged.id = "bruno-export-reviewed";
    const acknowledgedLabel = node("label", "I reviewed the conversion warnings and secret-free template"); acknowledgedLabel.prepend(acknowledged);
    const downloadButton = button("Download Bruno collection (.zip)", exportZip); downloadButton.disabled = true;
    conversion.append(node("h3", "Export selected requests to Bruno"), button("Preview conversion", preview), warningList, exportPreview, acknowledgedLabel, downloadButton);
    const legacy = node("section", "", "bruno-advanced"); legacy.id = "bruno-advanced";
    legacy.append(intro, status, namesLabel, names, actions, reportInput, fileInput, folderInput, environmentBox, error, summary, list, outputActions, mapping, conversion);
    const flow = window.NamazuBrunoImport.create({api: host.api, close: () => dialog.close(), legacy: mode => showLegacy(mode), report: async file => { await guarded(() => readReport(file)); showLegacy("bruno-results"); }});
    const advanced = button("Advanced mapping and export", () => showLegacy("advanced")); advanced.id = "bruno-advanced-open";
    const back = button("Back to source import", () => { legacy.hidden = true; flow.open(); advanced.hidden = false; title.textContent = "Import Bruno workspace or collection"; }); back.id = "bruno-back-import"; legacy.prepend(back);
    dialog.append(head, flow.panel, advanced, legacy); legacy.hidden = true;
    dialog.addEventListener("close", () => flow.close());
    document.body.append(dialog);
    let evidence = null, input = null, rows = [], selected = new Set(), exportPayload = null, working = false;
    const credentialNames = () => names.value.split(",").map(v => v.trim()).filter(Boolean);
    async function guarded(fn) {
      if (working) return;
      error.hidden = true; working = true; dialog.setAttribute("aria-busy", "true");
      const busyAreas = [actions, environmentBox, list, outputActions, mapping, conversion];
      busyAreas.forEach(area => { area.inert = true; }); names.disabled = true;
      try { await fn(); } catch (e) { error.textContent = e.message; error.hidden = false; }
      finally { working = false; dialog.setAttribute("aria-busy", "false"); busyAreas.forEach(area => { area.inert = false; }); names.disabled = false; }
    }
    function resetPreview() { exportPayload = null; acknowledged.checked = false; downloadButton.disabled = true; warningList.replaceChildren(); exportPreview.hidden = true; }
    names.oninput = resetPreview;
    acknowledged.onchange = () => { downloadButton.disabled = !acknowledged.checked || !exportPayload; };
    function refreshOperations() {
      operation.replaceChildren(node("option", "Choose a matching contract operation")); operation.firstChild.value = "";
      for (const op of host.spec()?.operations || []) { const o = node("option", `${op.method} ${op.path}`); o.value = op.id; operation.append(o); }
    }
    function render() {
      selected = new Set(); resetPreview(); refreshOperations(); list.replaceChildren(); prepared.textContent = "";
      for (const row of rows) {
        const item = node("div", "", "bruno-row"), check = node("input"); check.type = "checkbox";
        const label = node("label", `${row.request?.method || "unknown method"} ${row.name || row.request?.url || row.id}`); label.prepend(check);
        check.onchange = () => { if (check.checked) selected.add(row.id); else selected.delete(row.id); resetPreview(); confirm.checked = false; };
        item.append(label, node("p", row.request?.url || "Resolved URL not captured", "mono hint"));
        if (row.observation) item.append(node("p", row.observation));
        if (row.iteration !== undefined) item.append(node("p", `Iteration ${row.iteration} · HTTP ${row.httpStatus ?? "unknown"} · ${row.elapsed ?? "unknown"} ms · ${row.source_ref}`, "hint"));
        for (const warning of [...(row.warnings || []), ...(row.blockers || []), ...(row.missing_evidence || [])]) item.append(node("p", warning, "hint"));
        const detail = node("details"), code = node("pre", JSON.stringify(row, null, 2)); detail.append(node("summary", "Evidence, assertions and source reference"), code); item.append(detail); list.append(item);
      }
      openEvidence.disabled = saveEvidence.disabled = !evidence;
      addWorkspace.disabled = !input?.files || !rows.length;
    }
    async function readFiles(fileList, directory) {
      const all = [...fileList], accepted = directory ? all.filter(f => f.name.endsWith(".bru") || f.name === "bruno.json") : all;
      if (!accepted.length || accepted.length > 200 || accepted.some(f => f.size > 256 * 1024) || accepted.reduce((n, f) => n + f.size, 0) > 8 * 1024 * 1024) throw Error("Select 1–200 definitions, at most 256 KiB each and 8 MiB total. Archives are not supported.");
      const files = await Promise.all(accepted.map(async file => ({path: file.webkitRelativePath || file.name, content: await file.text()})));
      await resolveCollection({files}, true);
      status.textContent = `Definitions read locally; ${all.length - accepted.length} non-definition files ignored without reading. No scripts, external files or requests executed.`;
    }
    fileInput.onchange = () => guarded(async () => { try { await readFiles(fileInput.files, false); } finally { fileInput.value = ""; } });
    folderInput.onchange = () => guarded(async () => { try { await readFiles(folderInput.files, true); } finally { folderInput.value = ""; } });
    async function readReport(file) {
      if (!file) return;
      if (file.size > 8 * 1024 * 1024) throw Error("Run reports are limited to 8 MiB.");
      const report = JSON.parse(await file.text());
      const result = await host.api("/api/bruno/report", {report, version: "4.2.1", credential_names: credentialNames()});
      evidence = result; input = {report: result.bruno.source, version: "4.2.1"}; environmentBox.hidden = true;
      rows = result.bruno.executions.map(ex => { const r = result.requests.find(r => r.exchange_id === ex.id); return {...ex, httpStatus: r?.status, elapsed: r?.elapsed_ms, request: r && {method:r.method,url:r.url,headers:r.request_headers,body:r.request_body}}; });
      const counts = result.bruno.assertion_counts;
      summary.textContent = `Imported Bruno run · ${rows.length} recorded executions · ${result.bruno.recorded_iterations} iterations · ${result.bruno.observed_responses} HTTP responses · wire request attempts unknown. Assertions ${counts.assertionResults.pass} passed / ${counts.assertionResults.fail} failed / ${counts.assertionResults.unknown} unknown; tests ${counts.testResults.pass} passed / ${counts.testResults.fail} failed / ${counts.testResults.unknown} unknown.`;
      status.textContent = `Imported at ${result.provenance.imported_at}. Execution time not supplied by this reporter. Zero requests sent during import.`;
      reportInput.value = ""; render();
    }
    reportInput.onchange = () => guarded(async () => { const file = reportInput.files[0]; reportInput.value = ""; await readReport(file); });
    async function resolveCollection(candidate = input, fresh = false) {
      if (!candidate?.files) throw Error("Select .bru definitions first.");
      const result = await host.api("/api/bruno/collection", {...candidate, spec:host.spec(), credential_names:credentialNames(), ...(!fresh && env.value !== "choose" && env.options.length ? {environment:env.value} : {})});
      input = candidate; evidence = null;
      if (fresh) { env.replaceChildren(); environmentBox.hidden = true; }
      if (result.requires_environment) {
        env.replaceChildren(); for (const [value, text] of [["choose", "Choose an environment"], ["", "No environment"], ...result.environments.map(v => [v,v])]) { const o=node("option",text);o.value=value;env.append(o); }
        environmentBox.hidden = false; rows = []; summary.textContent = result.warnings.join(" "); render(); return;
      }
      input.environment = result.environment || ""; rows = result.requests; summary.textContent = `${result.collection} · ${rows.length} request definitions · environment ${result.environment || "none"}. No target requests sent.`; render();
    }
    async function loadNative() { const next = await host.requests(); evidence = null; input = null; rows = next; environmentBox.hidden = true; summary.textContent = "Select the Namazu requests or prepared baselines to convert. No requests will be sent."; render(); }
    async function prepare() {
      if (!input || selected.size !== 1) throw Error("Select exactly one imported request to prepare.");
      const parseValue = value => { try { return JSON.parse(value); } catch { return value; } };
      const result = await host.api("/api/bruno/prepare", {...input, spec:host.spec(), credential_names:credentialNames(), selection:[...selected][0], operation_id:operation.value, identity_ref:identity.value, identity_confirmed:confirm.checked, expectation:{status:expected.value,negative:negative.checked}, assertions:[{purpose:"resource",operator:"equals",pointer:resourcePointer.value,expected:parseValue(resourceValue.value)},{purpose:"content",operator:"equals",pointer:contentPointer.value,expected:parseValue(contentValue.value)}]});
      await host.baseline(result); prepared.textContent = result.note; status.textContent = "Baseline template saved. No request sent; a new explicit run review is required.";
    }
    async function preview() {
      const requests = rows.filter(row => selected.has(row.id)).map(row => row.request && ({...row.request, conversion_warnings:[...(row.warnings || []), ...(row.blockers || []), ...(row.missing_evidence || [])]}));
      if (!requests.length || requests.some(row => !row)) throw Error("Select requests with captured or prepared method/URL evidence.");
      const payload = {requests, credential_names:credentialNames()};
      const result = await host.api("/api/bruno/export", payload); exportPayload = payload; acknowledged.checked = false; downloadButton.disabled = true;
      warningList.replaceChildren(...result.warnings.map(w => node("li", w)));
      exportPreview.textContent = result.files.map(file => `--- ${file.path}\n${file.content}`).join("\n\n"); exportPreview.hidden = false;
    }
    async function exportZip() {
      if (!exportPayload || !acknowledged.checked) throw Error("Review the preview and acknowledge conversion warnings first.");
      const response = await fetch("/api/bruno/download", {method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",body:JSON.stringify({...exportPayload,reviewed:true})});
      if (!response.ok) throw Error((await response.json()).detail || "Export failed");
      download(await response.blob(), "namazu-bruno.zip", "application/zip");
    }
    function download(value, filename, type) { const url=URL.createObjectURL(value instanceof Blob ? value : new Blob([value],{type}));const a=node("a");a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000); }
    document.getElementById("bruno-open").onclick = () => { error.hidden = true; refreshOperations(); dialog.showModal(); };
    function showLegacy(mode) { flow.panel.hidden = true; legacy.hidden = false; advanced.hidden = true; title.textContent = mode === "bruno-results" ? "Import Bruno execution results" : "Bruno mapping and export"; }
    window.NamazuBruno.selectMode = mode => {
      intro.textContent = mode === "bruno-results" ? "Bruno CLI 4.2.1 JSON execution results. These are historical records, with separate response and assertion counts. Missing headers or bodies remain unavailable; importing sends zero requests."
        : mode === "bruno-definitions" ? "Bruno collections and individual .bru files, parsed with @usebruno/lang 0.40.0. Definitions describe requests, not authoritative response schemas or proof of execution. Scripts remain inert; auth requires explicit local mapping." : "CLI 4.2.1 JSON reports and Bruno .bru definitions. Assertions are separate from HTTP responses and security findings. Collections are not response contracts.";
      dialog.dataset.inputMode = mode || "all";
      if (mode === "bruno-results") { showLegacy(mode); reportButton.focus(); }
      else { legacy.hidden = true; flow.open(); advanced.hidden = false; title.textContent = "Import Bruno workspace or collection"; }
    };
  },
};
