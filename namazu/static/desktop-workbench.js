/* One request workbench for browser and desktop. Credentials stay in server profiles. */
(function (root) {
  "use strict";
  if (typeof document === "undefined" || !root.NamazuDesktopModel) return;
  const M = root.NamazuDesktopModel, $ = id => document.getElementById(id), started = performance.now();
  const store = {tabs: [], closedTabs: [], selectedTab: null, layout: {}, filters: {}, environments: [], preferences: {}, workspaces: {}, activeWorkspaceId: null};
  const runtime = {workspace: null, workspaces: [], view: "welcome", revision: 0, ready: false, saves: Promise.resolve(), dirty: false, timer: null,
    requests: new Map(), treeOpen: new Set(), treeLimits: new Map(), globalTreeLimit: 400, search: "", requestEpoch: 0, menu: null, saveError: null};
  const responseCache = new WeakMap();
  let header;
  const node = (tag, text, cls) => { const item = document.createElement(tag); if (text != null) item.textContent = String(text); if (cls) item.className = cls; return item; };
  const button = (text, action, cls = "desktop-tool") => { const item = node("button", text, cls); item.type = "button"; item.onclick = () => guarded(action); return item; };
  const textValue = value => typeof value === "string" ? value : value == null ? "" : JSON.stringify(value, null, 2);
  const short = value => String(value || "").slice(0, 10);
  const activeTab = () => store.tabs.find(tab => tab.id === store.selectedTab);
  const collections = () => [...(runtime.workspace?.contracts || []), ...(runtime.workspace?.request_collections || [])];
  const contractFor = tab => collections().find(contract => contract.id === tab?.contractId);
  const operationFor = (tab, contract = contractFor(tab)) => contract?.operations.find(operation => operation.id === tab.operationKey);
  const identityFor = tab => operationFor(tab)?.identity || contractFor(tab)?.identity;
  const environmentFor = tab => store.environments.find(environment => environment.id === (tab?.environmentId || activeEnvironment()) && environment.workspaceId === runtime.workspace?.id);
  const activeEnvironment = () => store.workspaces[runtime.workspace?.id]?.environmentId || "default";
  function tabEnvironment(tab) { if (tab) store.workspaces[tab.workspaceId] = {...store.workspaces[tab.workspaceId], environmentId: tab.environmentId || "default"}; }
  function status(text) { $("desktop-status").textContent = text; }
  function error(message) { $("desktop-error").textContent = message || ""; $("desktop-error").hidden = !message; }
  async function guarded(action) { error(""); try { return await action(); } catch (failure) { error(failure.message || String(failure)); status("Action needs attention; current drafts are retained."); } }
  async function api(path, payload, method = "POST") {
    const response = await fetch(path, {method, credentials: "same-origin", headers: {"Content-Type": "application/json"}, ...(method === "GET" ? {} : {body: JSON.stringify(payload || {})})});
    let value; try { value = await response.json(); } catch { throw Error(`The local backend returned an unreadable response (${response.status}).`); }
    if (!response.ok) { const failure = Error(typeof value.detail === "string" ? value.detail : JSON.stringify(value.detail || value.error || response.status)); failure.status = response.status; throw failure; }
    return value;
  }
  function scheduleSave() {
    runtime.dirty = true; $("desktop-save-status").textContent = "Saving draft…";
    clearTimeout(runtime.timer); runtime.timer = setTimeout(() => flush().catch(failure => error(failure.message)), 350);
  }
  function flush() {
    clearTimeout(runtime.timer);
    runtime.saves = runtime.saves.catch(() => {}).then(async () => {
      if (!runtime.dirty) { if (runtime.saveError) throw runtime.saveError; return; }
      while (runtime.dirty) { const snapshot = M.serialise(store); runtime.dirty = false;
      try {
        const result = await api("/api/desktop/state", {version: 1, revision: runtime.revision, state: snapshot}, "PUT");
        runtime.revision = result.revision; runtime.saveError = null;
        $("desktop-save-status").textContent = runtime.dirty ? "Saving draft…" : "Saved locally";
      } catch (failure) {
        runtime.dirty = true; runtime.saveError = failure; $("desktop-save-status").textContent = "Not saved"; throw failure;
      } }
    });
    return runtime.saves;
  }
  function download(data, filename) { const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type: "application/json"})); const link = node("a"); link.href = url; link.download = filename; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
  function showView(view) {
    runtime.view = view;
    for (const name of ["welcome", "request", "workspace-review", "environment-editor", "request-history", "expert", "testing"]) $("desktop-" + name).hidden = name !== view;
    $("desktop-workbench").classList.remove("desktop-collections-open");
    renderTabs(); error("");
  }
  function renderToolbar() {
    const select = $("desktop-workspace"); select.replaceChildren();
    const empty = node("option", "Open a workspace"); empty.value = ""; select.append(empty);
    for (const workspace of runtime.workspaces) { const option = node("option", workspace.title || "Untitled workspace"); option.value = workspace.id; select.append(option); }
    select.value = runtime.workspace?.id || "";
    const environments = $("desktop-environment"); environments.replaceChildren();
    for (const environment of [{id: "default", name: "Contract targets"}, ...store.environments.filter(item => item.workspaceId === runtime.workspace?.id)]) { const option = node("option", environment.name); option.value = environment.id; environments.append(option); }
    environments.value = activeEnvironment();
    const identity = identityFor(activeTab());
    $("desktop-identity").textContent = identity?.profile_id ? `${identity.name || short(identity.profile_id)}${identity.source === "contract-specific override" ? " (override)" : ""}` : "No identity";
    $("desktop-identity").title = identity?.profile_id ? `${identity.source} · ${identity.profile_id} · revision ${identity.revision}` : "Configure explicitly scoped identity profiles";
    $("desktop-overlap-count").textContent = (runtime.workspace?.overlaps || []).filter(item => item.requires_review && !item.decision).length || "";
    header?.update({workspace: runtime.workspace?.title, environment: environments.selectedOptions[0]?.textContent,
      target: operationFor(activeTab())?.target || contractFor(activeTab())?.target, identity: identity?.name, identitySource: identity?.source});
    document.title = `${runtime.workspace?.title || "Namazu"} · Namazu API workbench`;
  }
  function renderRecent() {
    const recent = $("desktop-recent-workspaces"); recent.replaceChildren();
    if (!runtime.workspaces.length) recent.append(node("p", "No workspace yet. Import your contracts or try the local sample."));
    for (const workspace of runtime.workspaces.slice(0, 8)) { const item = button(workspace.title || "Untitled workspace", () => selectWorkspace(workspace.id), "desktop-recent"); item.append(node("small", `${workspace.contract_count ?? "Saved"} contracts · local workspace`)); recent.append(item); }
  }
  async function refreshWorkspaces() { const response = await api("/api/workspaces", null, "GET"); runtime.workspaces = response.workspaces || []; renderToolbar(); renderRecent(); }
  async function selectWorkspace(id) {
    if (!id) { showView("welcome"); return; }
    await flush(); const workspace = await api(`/api/workspaces/${encodeURIComponent(id)}`, null, "GET");
    runtime.workspace = workspace; store.activeWorkspaceId = workspace.id;
    if (!runtime.workspaces.some(item => item.id === workspace.id)) runtime.workspaces.unshift(workspace);
    const selected = activeTab(); if (!selected || selected.workspaceId !== id) store.selectedTab = store.tabs.find(tab => tab.workspaceId === id)?.id || null;
    tabEnvironment(activeTab());
    renderToolbar(); renderTree(); renderTabs();
    if (activeTab()) { showView("request"); renderRequest(); } else showView("welcome");
    scheduleSave(); status(`Opened ${workspace.title}. No requests replayed.`);
  }
  async function ensureWorkspace() {
    if (!runtime.workspace) { runtime.workspace = await api("/api/workspaces", {title: "API workspace"}); runtime.workspaces.unshift(runtime.workspace); store.activeWorkspaceId = runtime.workspace.id; renderToolbar(); renderTree(); scheduleSave(); }
    return runtime.workspace;
  }
  async function showWorkspace(view = "contracts", contractId) {
    const workspace = await ensureWorkspace();
    showView("workspace-review");
    await root.NamazuWorkspaces.instance.open({workspace, view, contractId, inlineHost: $("desktop-workspace-review")});
    status("Workspace review. Import, identity assignment and planning do not send endpoint requests.");
  }
  function methodBadge(method) { return node("span", method, `desktop-method ${String(method).toLowerCase()}`); }
  function highlightTree() { for (const row of $("desktop-collection-tree").querySelectorAll("[data-operation-key]")) row.setAttribute("aria-current", String(row.dataset.operationKey === activeTab()?.operationKey)); }
  function renderTree() {
    const tree = $("desktop-collection-tree"), start = performance.now(); tree.replaceChildren();
    const contracts = collections(), query = runtime.search.trim().toLowerCase();
    if (!contracts.length) {
      const empty = node("div", "", "desktop-empty-tree"); empty.append(node("p", "Start with your request collections or API contracts."),
        button("Import Bruno workspace or collection", () => openBruno("bruno-definitions")),
        button("Import API contracts", () => showWorkspace("contracts")),
        button("Open Namazu workspace", async () => { await showWorkspace("contracts"); root.NamazuWorkspaces.instance.openWorkspaceFile(); }),
        button("Configure authentication", () => root.NamazuIdentities?.open())); tree.append(empty); return;
    }
    const fragment = document.createDocumentFragment(); let rendered = 0;
    for (const contract of contracts) {
      const operations = contract.operations.filter(operation => !query || `${contract.title} ${operation.method} ${operation.path} ${operation.summary || ""} ${operation.operation_id || ""} ${(operation.tags || []).join(" ")}`.toLowerCase().includes(query));
      if (!operations.length && query) continue;
      const collection = node("details", "", "desktop-contract"); collection.open = Boolean(query) || (store.filters.treeExpansion?.[contract.id] ?? (contracts.length < 4));
      if (contract.request_collection) { collection.dataset.requestCollection = contract.id; collection.title = "Bruno request definitions · no response contract"; }
      collection.ontoggle = () => { if (collection.open) runtime.treeOpen.add(contract.id); else runtime.treeOpen.delete(contract.id); store.filters.treeExpansion = {...store.filters.treeExpansion, [contract.id]: collection.open}; scheduleSave(); };
      const summary = node("summary"); summary.append(node("strong", contract.title), node("span", `${operations.length}${contract.request_collection ? " · bru" : ""}`));
      const menu = button("⋯", event => contractMenu(contract, menu)); menu.setAttribute("aria-label", `Actions for ${contract.title}`); menu.onclick = event => { event.preventDefault(); contractMenu(contract, menu); }; summary.append(menu); collection.append(summary);
      const contractLimit = runtime.treeLimits.get(contract.id) || 120, visible = operations.slice(0, Math.min(contractLimit, Math.max(0, runtime.globalTreeLimit - rendered)));
      const groups = new Map(); for (const operation of visible) { const name = operation.tags?.[0] || operation.path.split("/").filter(Boolean)[0] || "Requests"; if (!groups.has(name)) groups.set(name, []); groups.get(name).push(operation); }
      const folders = new Map();
      function makeFolder(label, path, parent) {
        const folder = node("details", "", "desktop-folder"), groupKey = `${contract.id}:${path}`;
        folder.open = Boolean(query) || (store.filters.folderExpansion?.[groupKey] ?? true);
        folder.append(node("summary", label));
        folder.ontoggle = () => { store.filters.folderExpansion = {...store.filters.folderExpansion, [groupKey]: folder.open}; scheduleSave(); };
        parent.append(folder); return folder;
      }
      for (const [name, entries] of groups) {
        let folder;
        if (contract.request_collection) {
          let parent = collection, prefix = "";
          for (const part of name.split("/").filter(Boolean)) {
            prefix = prefix ? `${prefix}/${part}` : part;
            if (!folders.has(prefix)) folders.set(prefix, makeFolder(part, prefix, parent));
            parent = folders.get(prefix);
          }
          folder = parent;
        } else folder = makeFolder(name, name, collection);
        for (const operation of entries) {
          const row = button("", () => openOperation(contract, operation), "desktop-operation"); row.dataset.operationKey = operation.id; row.title = `${operation.method} ${operation.path} · ${contract.title}`;
          row.setAttribute("aria-label", `Open ${contract.title}: ${operation.method} ${operation.path}`);
          row.setAttribute("aria-current", String(activeTab()?.operationKey === operation.id)); row.append(methodBadge(operation.method), node("span", operation.summary || operation.path, "desktop-operation-name"));
          row.oncontextmenu = event => { event.preventDefault(); operationMenu(contract, operation, row); }; folder.append(row); rendered++;
        }
      }
      if (operations.length > visible.length) collection.append(button(`Show next ${Math.min(120, operations.length - visible.length)} of ${operations.length - visible.length} more`, () => { runtime.treeLimits.set(contract.id, contractLimit + 120); runtime.globalTreeLimit += 120; renderTree(); }, "desktop-tree-more"));
      fragment.append(collection);
    }
    tree.append(fragment);
    if (!rendered && query) { const empty = node("div", "", "desktop-empty-tree"); empty.append(node("p", "No requests match this search."), button("Clear search", () => { runtime.search = ""; store.filters.search = ""; $("desktop-search").value = ""; renderTree(); scheduleSave(); })); tree.append(empty); }
    runtime.lastTreeMs = performance.now() - start;
    $("desktop-performance").textContent = `${rendered} requests · tree ${runtime.lastTreeMs.toFixed(0)} ms`;
  }
  function contextMenu(anchor, actions) {
    runtime.menu?.remove(); const menu = node("div", "", "desktop-context-menu"); menu.setAttribute("role", "menu");
    for (const [title, action] of actions) { const choice = button(title, async () => { menu.remove(); await action(); }); choice.setAttribute("role", "menuitem"); menu.append(choice); }
    document.body.append(menu); const rect = anchor.getBoundingClientRect(); menu.style.left = `${Math.min(rect.left, innerWidth - menu.offsetWidth - 8)}px`; menu.style.top = `${Math.min(rect.bottom, innerHeight - menu.offsetHeight - 8)}px`; runtime.menu = menu;
    menu.firstElementChild?.focus(); setTimeout(() => document.addEventListener("click", event => { if (!menu.contains(event.target)) menu.remove(); }, {once: true}), 0);
  }
  function contractMenu(contract, anchor) {
    if (contract.request_collection) return contextMenu(anchor, [
      ["Inspect request definitions", async () => { await openOperation(contract, contract.operations[0]); activeTab().requestTab = "contract"; renderEditor(); }],
      ["Bruno import / export", () => openBruno("bruno-definitions")],
      ["Export workspace including definitions", async () => download(await api(`/api/workspaces/${runtime.workspace.id}/export`, null, "GET"), "namazu-workspace.json")],
      ["Remove collection from workspace", async () => {
        await flushSave(); const workspaceId = runtime.workspace.id;
        const updated = await api(`/api/workspaces/${workspaceId}/contracts/${contract.id}`, {}, "DELETE");
        if (runtime.workspace?.id !== workspaceId) return;
        runtime.workspace = updated; renderTree(); renderTabs(); renderRequest(); renderToolbar();
        status("Collection archived. Existing drafts and historical exchanges are retained; removed definitions cannot send new requests.");
      }],
    ]);
    contextMenu(anchor, [["Review contract and target", () => showWorkspace("contracts", contract.id)], ["Configure authentication", () => root.NamazuIdentities.open({workspace_id: runtime.workspace.id, profile_id: contract.identity?.profile_id})], ["Review overlaps", () => showWorkspace("overlap", contract.id)], ["Open contract schema explorer", () => openExpert("schemas", contract)], ["Export contract JSON", () => download(contract.spec.document, `${contract.title}.openapi.json`)]]);
  }
  function operationMenu(contract, operation, anchor) {
    contextMenu(anchor, [["Open request", () => openOperation(contract, operation)], ["Open independent copy", () => openOperation(contract, operation, true)],
      [contract.request_collection ? "Map baseline to an OpenAPI operation" : "Prepare audit baseline", async () => { await openOperation(contract, operation); if (contract.request_collection) return openBruno("bruno-definitions"); await openExpert("data", contract); }],
      [contract.request_collection ? "Inspect request definition" : "Inspect contract definition", async () => { await openOperation(contract, operation); activeTab().requestTab = "contract"; renderEditor(); }]]);
  }
  function replaceTab(tab) { const index = store.tabs.findIndex(item => item.id === tab.id); if (index >= 0) store.tabs[index] = tab; }
  function editDraft(patch) { const tab = activeTab(); if (!tab) return; replaceTab(M.updateDraft(tab, patch)); renderTabs(); scheduleSave(); }
  async function openOperation(contract, operation, duplicate = false) {
    const key = M.tabKey({workspaceId: runtime.workspace.id, contractId: contract.id, snapshotHash: contract.hash, operationKey: operation.id, environmentId: activeEnvironment()});
    let tab = !duplicate && store.tabs.find(item => item.key === key);
    if (!tab) { tab = M.createTab({workspace: runtime.workspace, contract, operation, environmentId: activeEnvironment()}); store.tabs.push(tab); }
    store.selectedTab = tab.id; showView("request"); renderToolbar(); highlightTree(); renderRequest(); scheduleSave();
    if (!contract.request_collection && !tab.prepared && !tab.dirty && contract.target && !contract.target_review_required) {
      tab.prepared = true;
      const openedDraft = JSON.stringify(tab.draft);
      try {
        const prepared = await api("/api/desktop/prepare", requestPayload(tab, true));
        const original = store.tabs.find(item => item.id === tab.id);
        if (original && JSON.stringify(original.draft) === openedDraft) { original.draft = {...original.draft, ...normalisePrepared(prepared.request || prepared)}; original.savedDraft = JSON.parse(JSON.stringify(original.draft)); if (activeTab()?.id === tab.id) renderRequest(); scheduleSave(); }
      } catch (failure) { if (activeTab()?.id === tab.id) status(`Request opened. ${failure.message}`); }
    }
  }
  function normalisePrepared(request) { return {method: request.method, url: request.url, headers: request.headers || {}, body: request.has_body && request.body === null && /json/i.test(request.content_type || "") ? "null" : textValue(request.body), bodyEntered: Boolean(request.has_body), content_type: request.content_type || "application/json"}; }
  function renderTabs() {
    const host = $("desktop-request-tabs"); host.replaceChildren();
    const home = button("Overview", () => showView("welcome"), "desktop-tab-home"); home.setAttribute("aria-current", String(runtime.view === "welcome")); host.append(home);
    for (const tab of store.tabs.filter(item => item.workspaceId === runtime.workspace?.id)) {
      const row = node("div", "", "desktop-request-tab"); row.setAttribute("role", "tab"); row.setAttribute("aria-selected", String(tab.id === store.selectedTab && runtime.view === "request")); row.dataset.tabId = tab.id;
      const label = button("", () => { store.selectedTab = tab.id; tabEnvironment(tab); showView("request"); renderRequest(); renderToolbar(); highlightTree(); scheduleSave(); }, "desktop-tab-label");
      label.title = `${tab.localOperationId}\nContract ${tab.contractId}\nEnvironment ${tab.environmentId}`;
      label.append(methodBadge(tab.draft.method), node("span", tab.title, "desktop-tab-title")); if (tab.dirty) { const dot = node("span", "", "desktop-tab-dirty"); dot.setAttribute("aria-label", "Unsaved changes"); label.append(dot); }
      const close = button("×", () => closeRequestTab(tab.id), "desktop-tab-close"); close.setAttribute("aria-label", `Close ${tab.title}`); row.append(label, close); host.append(row);
    }
    if (store.closedTabs?.length) host.append(button("↶", restoreClosed, "desktop-tab-home"));
  }
  function closeRequestTab(id) { if (runtime.requests.has(id)) throw Error("Cancel or finish the request before closing its tab."); Object.assign(store, M.closeTab(store, id)); if (activeTab()?.workspaceId !== runtime.workspace?.id) store.selectedTab = store.tabs.find(tab => tab.workspaceId === runtime.workspace?.id)?.id || null; if (activeTab()) { tabEnvironment(activeTab()); showView("request"); renderRequest(); } else showView("welcome"); renderToolbar(); highlightTree(); scheduleSave(); status("Tab closed. Its draft can be restored with Ctrl+Shift+T."); }
  async function restoreClosed() { Object.assign(store, M.restoreClosed(store)); const tab = activeTab(); if (tab) { tabEnvironment(tab); if (tab.workspaceId !== runtime.workspace?.id) await selectWorkspace(tab.workspaceId); showView("request"); renderRequest(); } renderToolbar(); highlightTree(); scheduleSave(); }
  function renderRequest() {
    const tab = activeTab(); if (!tab) return;
    $("desktop-method").value = tab.draft.method; $("desktop-request-url").value = tab.draft.url;
    $("desktop-write-consent").checked = Boolean(tab.writeConsent); $("desktop-write-consent").disabled = ["GET", "HEAD", "OPTIONS"].includes(tab.draft.method);
    const contract = contractFor(tab), context = $("desktop-request-context"); context.replaceChildren();
    context.append(node("span", contract?.title || "Removed contract"), node("span", `Snapshot ${short(tab.snapshotHash)}`), node("span", `Environment: ${environmentFor(tab)?.name || "Contract targets"}`));
    if (contract?.request_collection) context.append(node("span", "Bruno definition · no response contract", "desktop-context-warning"));
    if (contract?.hash !== tab.snapshotHash) context.append(node("span", "Contract replaced; open a new request from the collection", "desktop-context-warning"));
    if (contract?.target_review_required || contract?.scope_review_required) context.append(button("Target / identity scope needs review", () => showWorkspace("contracts", contract.id), "desktop-context-warning"));
    const definition = operationFor(tab)?.request_definition;
    const running = runtime.requests.has(tab.id); $("desktop-send").disabled = running || !contract || contract.hash !== tab.snapshotHash || (!contract.request_collection && !contract.target) || contract.target_review_required || contract.scope_review_required || (definition && !definition.can_prepare); $("desktop-cancel").hidden = !running; $("desktop-cancel").disabled = !runtime.requests.get(tab.id)?.request_id;
    $("desktop-save-baseline").disabled = Boolean(contract?.request_collection);
    $("desktop-save-baseline").title = contract?.request_collection ? "Map this definition to an OpenAPI operation through Bruno baseline review first." : "Save this request template for audit review";
    $("desktop-send").textContent = running ? "Sending…" : "Send";
    renderEditor(); renderResponse(); applyLayout();
  }
  function tabs(host, names, active, change) { host.replaceChildren(); for (const [key, title] of names) { const tab = button(title, () => change(key), "desktop-pane-tab"); tab.setAttribute("role", "tab"); tab.setAttribute("aria-selected", String(active === key)); host.append(tab); } }
  function renderEditor() {
    const tab = activeTab(); if (!tab) return;
    const operation = operationFor(tab), contract = contractFor(tab), editor = $("desktop-editor"); editor.replaceChildren();
    tabs($("desktop-editor-tabs"), [["params", "Params"], ["body", "Body"], ["headers", "Headers"], ["auth", "Auth"], ["assertions", "Assertions"], ["contract", contract?.request_collection ? "Definition" : "Contract"]], tab.requestTab || "params", value => { const current = activeTab(); if (current?.id !== tab.id) return; current.requestTab = value; renderEditor(); scheduleSave(); });
    const mode = tab.requestTab || "params";
    if (mode === "params") {
      editor.append(node("h3", "Path and query parameters"));
      if (operation?.request_definition) { editor.append(node("p", "Edit the resolved URL above. Bruno variables were resolved in the explicitly selected import environment; no scripts or runtime variables are evaluated.")); for (const warning of [...(operation.request_definition.warnings || []), ...(operation.request_definition.blockers || [])]) editor.append(node("p", warning, "desktop-context-warning")); }
      const parameters = operation?.parameters || [];
      if (!parameters.length) editor.append(node("p", "This operation declares no parameters. You can edit the request URL directly."));
      const table = node("table", "", "desktop-keyvalue"), head = node("tr"); head.append(node("th", "Name / location"), node("th", "Value")); table.append(head);
      for (const parameter of parameters) {
        const key = `${parameter.in}.${parameter.name}`, row = node("tr"), label = node("td"), value = node("td"), input = node("input"); input.type = "text"; input.value = textValue(tab.draft.parameters[key]); input.setAttribute("aria-label", `${parameter.in} parameter ${parameter.name}`);
        label.append(node("div", parameter.name + (parameter.required ? " *" : ""), "desktop-key-name"), node("small", `${parameter.in} · ${parameter.schema?.type || "value"}`));
        input.oninput = () => { let next = input.value; if (["integer", "number"].includes(parameter.schema?.type) && next !== "" && Number.isFinite(Number(next))) next = Number(next); const parameters = {...activeTab().draft.parameters}; if (next === "") delete parameters[key]; else parameters[key] = next; editDraft({parameters, manualUrl: false}); };
        value.append(input); row.append(label, value); table.append(row);
      }
      if (parameters.length) editor.append(table, node("p", "Changing parameters updates the prepared request when you validate or send. Environment variables use {{name}}."));
    } else if (mode === "headers") {
      editor.append(node("h3", "Request headers"), node("p", "Credential headers come only from the explicitly assigned profile. Add ordinary request headers here."));
      const table = node("table", "", "desktop-keyvalue"), head = node("tr"); head.append(node("th", "Name"), node("th", "Value")); table.append(head);
      for (const [name, value] of Object.entries(tab.draft.headers || {})) addHeaderRow(table, tab, name, value);
      editor.append(table, button("+ Add header", () => addHeaderRow(table, tab, "", "")));
    } else if (mode === "body") {
      const wrapper = node("div", "", "desktop-body-editor"), media = node("select"); media.setAttribute("aria-label", "Request content type");
      for (const value of [...new Set([tab.draft.content_type, ...Object.keys(operation?.request_body?.content || {}), "application/json", "text/plain", "application/xml", "application/x-www-form-urlencoded"])].filter(Boolean)) { const option = node("option", value); option.value = value; media.append(option); }
      media.value = tab.draft.content_type; media.onchange = () => editDraft({content_type: media.value});
      const input = node("textarea", "", "desktop-code-editor"); input.id = "desktop-request-body"; input.value = tab.draft.body || ""; input.spellcheck = false; input.setAttribute("aria-label", "Request body"); input.oninput = () => editDraft({body: input.value, bodyEntered: true});
      wrapper.append(media, input); editor.append(wrapper);
    } else if (mode === "auth") {
      const identity = identityFor(tab);
      editor.append(node("h3", identity?.name || "No identity configured"), node("p", identity?.profile_id ? `${identity.source} · reference ${identity.profile_id} · revision ${identity.revision}` : "This contract has no assigned identity. It will receive no shared token."));
      if (identity?.profile_id) { editor.append(node("p", `Credential: ${identity.credential_available ? "••••••••" : "not loaded"}`), node("p", `Allowed API scopes: ${(identity.allowed_scopes || []).join(", ")}`)); }
      if (contract?.request_collection) {
        editor.append(node("p", "Imported authentication is a requirement, not a live credential. Explicitly assign an existing bearer profile to this request only. Other requests and contracts keep their own assignments."));
        editor.append(node("pre", JSON.stringify(operation.request_definition.authentication || [], null, 2), "workspace-code"));
        const select = node("select"); select.id = "desktop-bruno-profile"; select.setAttribute("aria-label", "Bearer profile for this request");
        const none = node("option", "No identity assigned"); none.value = ""; select.append(none);
        for (const profile of runtime.workspace.profiles || []) { const option = node("option", profile.name); option.value = profile.id; select.append(option); }
        select.value = identity?.profile_id || "";
        const scope = node("textarea"); scope.id = "desktop-bruno-scopes"; scope.setAttribute("aria-label", "Allowed API base URLs for this request"); scope.value = (identity?.allowed_scopes || []).join("\n") || operation.target;
        const assign = button("Assign profile to this request", async () => { const workspace = await api(`/api/workspaces/${runtime.workspace.id}/contracts/${contract.id}/identity`, {operation_key: operation.id, profile_id: select.value || null, allowed_scopes: scope.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean)}, "PUT"); runtime.workspace = workspace; renderToolbar(); renderRequest(); status("Identity assignment updated for this request only. Imported credentials were not activated; no request sent."); }); assign.id = "desktop-bruno-assign";
        editor.append(select, node("label", "Explicit allowed API origins/base paths"), scope, assign, button("Configure authentication", () => root.NamazuIdentities.open({workspace_id: runtime.workspace.id, profile_id: identity?.profile_id, prefill: operation.request_definition.oauth_client_credentials})), node("p", "Bearer and client-credentials identities require explicit assignment. Basic and API-key sessions remain available in Advanced tools. Imported scripts and credentials stay inactive."));
      } else editor.append(button("Configure authentication", () => root.NamazuIdentities.open()), node("p", "Selecting another request or environment never extends credential scope. Token assignment does not establish permission or successful controls."), button("Advanced OAuth / Basic / API key session", () => openExpert("identity")));
    } else if (mode === "assertions") {
      editor.append(node("h3", "Expected response"), node("p", 'Use an expectation object, for example {"status":"200"}. Business assertions are specific to this contract, operation and identity.'));
      const input = node("textarea", "", "desktop-code-editor"); input.value = tab.draft.assertionsText ?? JSON.stringify(tab.draft.assertions || {}, null, 2); input.setAttribute("aria-label", "Response assertions JSON"); input.oninput = () => { try { const value = JSON.parse(input.value); if (!value || Array.isArray(value) || typeof value !== "object") throw Error(); input.setCustomValidity(""); editDraft({assertions: value, assertionsText: input.value, assertionsInvalid: false}); } catch { input.setCustomValidity("Enter a JSON expectation object."); editDraft({assertionsText: input.value, assertionsInvalid: true}); } }; editor.append(input);
    } else { const code = node("pre", JSON.stringify(operation || {}, null, 2), "workspace-code"); editor.append(node("h3", contract?.request_collection ? "Bruno request definition" : "Contract operation"), node("p", `${contract?.request_collection ? "Request collection" : "Contract"} ${tab.contractId} · snapshot ${tab.snapshotHash}`), code); }
  }
  function addHeaderRow(table, tab, initialName, initialValue) {
    const row = node("tr"), nameCell = node("td"), valueCell = node("td"), name = node("input"), value = node("input");
    name.value = initialName; name.placeholder = "Header name"; name.setAttribute("aria-label", "Header name"); value.value = initialValue; value.placeholder = "Value"; value.setAttribute("aria-label", "Header value");
    let previous = initialName;
    const update = () => { const key = name.value.trim(); if (M.secretName(key)) { value.type = "password"; error("Assign bearer credentials through Auth. Credential headers cannot be stored in request drafts."); return; } value.type = "text"; const headers = {...activeTab().draft.headers}; if (previous) delete headers[previous]; if (key) headers[key] = value.value; previous = key; editDraft({headers}); };
    name.onchange = update; value.oninput = update; nameCell.append(name); valueCell.append(value); row.append(nameCell, valueCell); table.append(row); if (!initialName) name.focus();
  }
  function requestPayload(tab, generate = false) {
    if (tab.environmentId !== "default" && !environmentFor(tab)) throw Error("This request's environment was removed. Choose an existing environment and open a new scoped draft.");
    const contract = contractFor(tab), payload = M.requestPayload(tab, contract, environmentFor(tab), generate);
    return {...payload, ...(root.NamazuWorkbench.connectionOptions?.(runtime.workspace, contract, {environmentId: tab.environmentId, tabId: tab.id}) || {})};
  }
  async function validateRequest() {
    const tab = activeTab(); if (!tab) return; const draftVersion = JSON.stringify(tab.draft), prepared = await api("/api/desktop/prepare", requestPayload(tab));
    const current = store.tabs.find(item => item.id === tab.id);
    if (!current || JSON.stringify(current.draft) !== draftVersion) { status("The draft changed during preparation. Your edits were retained; validate again to review them."); return; }
    replaceTab(M.updateDraft(current, normalisePrepared(prepared.request || prepared))); if (activeTab()?.id === tab.id) renderRequest(); renderTabs(); scheduleSave();
    status((prepared.warnings || []).join("; ") || "Request prepared and validated offline. No target request sent.");
  }
  async function sendRequest() {
    const tab = activeTab(); if (!tab || runtime.requests.has(tab.id)) return;
    const payload = requestPayload(tab);
    if (!["GET", "HEAD", "OPTIONS"].includes(tab.draft.method) && !tab.writeConsent) throw Error("Explicitly authorise this write in the request footer before sending.");
    runtime.requests.set(tab.id, {status: "starting"}); renderRequest();
    let submission; try { if (tab.oobCaseIds?.length) await testing?.validateCases(tab.oobCaseIds); submission = await api("/api/desktop/requests", payload); } catch (failure) { runtime.requests.delete(tab.id); if (activeTab()?.id === tab.id) renderRequest(); throw failure; }
    runtime.requests.set(tab.id, submission); tab.lastRequestId = submission.request_id;
    renderRequest(); status(`Sending ${tab.draft.method} ${tab.draft.url}`); pollRequest(tab.id, submission.request_id, [...(tab.oobCaseIds || [])]);
  }
  async function pollRequest(tabId, requestId, oobCaseIds = []) {
    try {
      const record = await api(`/api/desktop/requests/${encodeURIComponent(requestId)}`, null, "GET"), tab = store.tabs.find(item => item.id === tabId);
      if (!tab) return;
      tab.record = record;
      if (["pending", "running", "stopping"].includes(record.status)) { runtime.requests.set(tabId, record); if (activeTab()?.id === tabId) renderResponse(); setTimeout(() => pollRequest(tabId, requestId, oobCaseIds), 200); return; }
      runtime.requests.delete(tabId); tab.result = record.result || null;
      if (activeTab()?.id === tabId) renderRequest();
      status(record.persistence_error || record.error || `${record.status}: ${tab.draft.method} ${tab.draft.url}. Evidence remains tied to its original contract and identity.`);
      if (record.persistence_error) error(record.persistence_error);
      if (record.result && oobCaseIds.length && testing) { const issues = await testing.linkReceipts(oobCaseIds, requestId); if (issues.length) error(`Request evidence retained. OOB receipt linking needs review: ${issues.join("; ")}`); }
    } catch (failure) { runtime.requests.delete(tabId); if (activeTab()?.id === tabId) { renderRequest(); error(failure.message); } }
  }
  async function cancelRequest() { const tab = activeTab(), running = tab && runtime.requests.get(tab.id); if (!running) return; const record = await api(`/api/desktop/requests/${encodeURIComponent(running.request_id)}/cancel`, {}); tab.record = record; status("Cancellation requested. An in-flight exchange may still reach the target; retained evidence will remain available."); renderResponse(); }
  function boundedCode(host, text) {
    const code = node("pre"), chunk = 65536; let shown = Math.min(chunk, text.length);
    code.textContent = text.slice(0, shown); host.append(code);
    if (shown >= text.length) return;
    const note = node("p", "", "desktop-capture-note"), more = button("Show next 64K characters", () => { shown = Math.min(text.length, shown + chunk); code.textContent = text.slice(0, shown); note.textContent = `Showing ${shown.toLocaleString()} of ${text.length.toLocaleString()} characters. Full captured evidence remains available in the exchange export.`; more.hidden = shown === text.length; });
    note.textContent = `Showing ${shown.toLocaleString()} of ${text.length.toLocaleString()} characters. Full captured evidence remains available in the exchange export.`; host.append(note, more);
  }
  function renderResponse() {
    const tab = activeTab(); if (!tab) return;
    tabs($("desktop-response-tabs"), [["body", "Response"], ["headers", "Headers"], ["validation", "Validation"], ["exchange", "Exchange"]], tab.responseTab || "body", value => { const current = activeTab(); if (current?.id !== tab.id) return; current.responseTab = value; renderResponse(); scheduleSave(); });
    const content = $("desktop-response"), meta = $("desktop-response-meta"), record = tab.record, result = tab.result || record?.result; content.replaceChildren(); meta.replaceChildren();
    if (!result) { const empty = node("div", "", "desktop-response-empty"); empty.append(node("strong", runtime.requests.has(tab.id) ? record?.cancellation_requested ? "Stopping; waiting for in-flight evidence" : "Waiting for the response" : record?.error ? "Request did not complete" : "Ready when you are"), node("p", record?.error || "Send a request to inspect status, headers, timing and the exact captured response.")); content.append(empty); return; }
    const response = result.response || {}, context = record?.context || result.context || {};
    let cached = responseCache.get(result); if (!cached) { const body = textValue(response.body); cached = {body, bytes: new TextEncoder().encode(body).length}; responseCache.set(result, cached); }
    meta.append(node("span", `HTTP ${response.status ?? "unknown"}`, `desktop-http-status${response.status >= 400 ? " error" : ""}`), node("span", `${Math.round(response.elapsed_ms || 0)} ms`), node("span", `${cached.bytes.toLocaleString()} bytes`), node("span", response.truncated ? "Truncated capture" : "Captured response"));
    const receiptContext = node("div", `Contract ${short(context.contract_id || tab.contractId)} · snapshot ${short(context.snapshot_hash || tab.snapshotHash)} · identity ${context.identity_ref || "none"}${context.identity_revision ? ` / revision ${context.identity_revision}` : ""}`, "desktop-receipt-context");
    receiptContext.title = `Contract ${context.contract_id || tab.contractId}\nSnapshot ${context.snapshot_hash || tab.snapshotHash}\nTarget ${context.target || result.request?.url || ""}\nIdentity ${context.identity_ref || "none"}`;
    receiptContext.append(node("div", context.target || result.request?.url || "")); meta.append(receiptContext);
    if (tab.responseTab === "headers") {
      const table = node("dl", "", "desktop-response-data"); for (const [key, value] of Object.entries(response.headers || {})) table.append(node("dt", key), node("dd", value)); content.append(table);
    } else if (tab.responseTab === "validation") {
      const validation = result.validation || {}; content.append(node("h3", validation.valid === true ? "Matches the recorded response contract" : validation.valid === false ? "Contract mismatch" : "Validation incomplete"), node("p", "Contract validation is separate from demonstrated security impact.", "workspace-muted"), node("pre", JSON.stringify({validation, assertions: result.assertions || result.expectation}, null, 2)));
    } else if (tab.responseTab === "exchange") {
      const facts = node("dl", "", "desktop-response-data"); for (const [key, value] of [["Contract", context.contract_id || tab.contractId], ["Snapshot", context.snapshot_hash || tab.snapshotHash], ["Target", context.target || result.request?.url], ["Identity reference", context.identity_ref || "No identity"], ["Identity source", context.identity_source || "No identity configured"], ["Request receipt", record?.request_id], ["State", record?.status]]) facts.append(node("dt", key), node("dd", value));
      content.append(facts, button("Export captured exchange", () => download(record || result, `namazu-exchange-${record?.request_id || tab.id}.json`)));
      cached.exchange ||= JSON.stringify(result, null, 2); boundedCode(content, cached.exchange);
    } else {
      if (cached.formatted === undefined) { cached.formatted = cached.body; if (cached.body.length <= 131072) try { cached.formatted = JSON.stringify(JSON.parse(cached.body), null, 2); } catch { /* Keep the retained text. */ } }
      boundedCode(content, cached.formatted || "(empty response body)");
    }
  }
  async function saveBaseline() {
    const tab = activeTab(), contract = contractFor(tab); if (!tab || !contract) return;
    const draft = requestPayload(tab), prepared = await api("/api/desktop/prepare", draft), payload = prepared.request;
    const saved = await api(`/api/workspaces/${tab.workspaceId}/contracts/${tab.contractId}`, {review_operation_ids: [tab.localOperationId], config: {
      examples: {...contract.config.examples, [tab.localOperationId]: {url: payload.url, body: payload.body, headers: payload.headers}},
      expectations: {...contract.config.expectations, [tab.localOperationId]: draft.request.assertions}}}, "PATCH");
    if (runtime.workspace?.id === tab.workspaceId) runtime.workspace = saved;
    status("Prepared request and expectations saved for this operation. No successful control is inferred; review a new audit plan.");
  }
  function applyLayout() { const stacked = store.layout.orientation === "rows"; $("desktop-workbench").classList.toggle("desktop-stacked", stacked); $("desktop-workbench").style.setProperty("--desktop-sidebar", `${store.layout.sidebarWidth || 244}px`); $("desktop-workbench").style.setProperty("--desktop-ratio", `${store.layout.requestRatio || 48}%`); $("desktop-layout-toggle").textContent = stacked ? "Columns" : "Stack"; $("desktop-response-resize").setAttribute("aria-orientation", stacked ? "horizontal" : "vertical"); }
  function setupResize(id, apply, read) {
    const handle = $(id); handle.onpointerdown = event => { event.preventDefault(); handle.setPointerCapture(event.pointerId); handle.onpointermove = move => { apply(move); applyLayout(); }; handle.onpointerup = () => { handle.onpointermove = null; scheduleSave(); }; };
    handle.onkeydown = event => { if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) return; event.preventDefault(); read(["ArrowLeft", "ArrowUp"].includes(event.key) ? -1 : 1); applyLayout(); scheduleSave(); };
  }
  async function openExpert(section = "settings", contract = contractFor(activeTab())) {
    if (contract?.request_collection) { if (!["settings", "audit", "traffic", "history"].includes(section)) throw Error("Select an OpenAPI contract operation for these advanced controls. A Bruno request collection is not a response contract."); contract = null; }
    if (contract) await root.NamazuWorkbench.useContract(runtime.workspace, contract, activeTab()?.operationKey, {environmentId: activeEnvironment(), tabId: activeTab()?.id});
    showView("expert"); const shell = $("shell"); if (shell.parentNode !== $("desktop-expert-content")) $("desktop-expert-content").append(shell);
    $("desktop-expert-context").textContent = contract ? `${contract.title} · ${contract.target || "target not chosen"} · snapshot ${short(contract.hash)}. Advanced credentials are a separate explicit session; workspace profile values remain on the server.` : "Full workbench tools. Import a contract or use guided setup to begin.";
    const nav = $("desktop-expert-nav"); nav.replaceChildren();
    for (const [key, label] of [["api", "Guided setup"], ["identity", "OAuth / identity"], ["data", "Baseline / readiness"], ["endpoints", "Request tools"], ["schemas", "Schemas"], ["runner", "Runner"], ["access", "Access / sequences"], ["audit", "Audit / tools"], ["history", "History"], ["traffic", "Traffic"], ["settings", "Connection / settings"]]) nav.append(button(label, () => openExpert(key, contract)));
    if (["api", "identity", "data", "readiness"].includes(section)) root.NamazuWorkbench.openSetup(section);
    else if (section === "traffic") root.NamazuWorkbench.showTraffic(); else root.NamazuWorkbench.openSection(section);
    if (section === "settings") renderMigration();
  }
  function renderMigration(preferences = runtime.migrationPreferences) {
    const host = $("desktop-migration"); if (!host) return; host.replaceChildren(node("p", "Explicitly transfer this browser origin's visual preferences, baseline templates and access / sequence drafts. Credentials, write consent and running actions are excluded. Imported templates still require review for the selected contract and target.", "hint"));
    const actions = node("div", "", "row-actions"), file = node("input"); file.type = "file"; file.accept = ".json,application/json"; file.hidden = true;
    actions.append(button("Export browser preferences / test data", async () => {
      const exported = await api("/api/desktop/preferences/sanitise", {preferences: root.NamazuWorkbench.browserPreferences()});
      download(exported, "namazu-browser-preferences.json"); status("Browser preferences and test data exported after credential masking. No request sent.");
    }, "btn sm"), button("Import browser preferences / test data", () => file.click(), "btn sm"));
    file.onchange = () => guarded(async () => { const selected = file.files[0]; if (!selected) return; if (selected.size > 8 * 1024 * 1024) throw Error("Preference imports are limited to 8 MiB."); const data = JSON.parse(await selected.text()); if (data.format !== "namazu-browser-preferences" || data.version !== 1) throw Error("Choose a version 1 Namazu browser preference export."); const safe = await api("/api/desktop/preferences/sanitise", {preferences: data.preferences}); root.NamazuWorkbench.restoreBrowserPreferences(safe.preferences); runtime.migrationPreferences = safe.preferences; store.preferences.theme = document.documentElement.dataset.theme; scheduleSave(); renderToolbar(); renderMigration(safe.preferences); status("Nonsecret preferences imported. Choose a baseline or access source below to explicitly assign it to the current contract context."); });
    host.append(actions, file);
    if (!preferences) return;
    const sources = Object.keys(preferences).filter(key => /^namazu-(?:examples|access):/.test(key));
    if (!sources.length) { host.append(node("p", "This export contains visual preferences only.", "hint")); return; }
    const select = node("select"); select.setAttribute("aria-label", "Imported test data source");
    for (const key of sources) { const choice = node("option", key.replace(/^namazu-/, "")); choice.value = key; select.append(choice); }
    const contract = contractFor(activeTab()); host.append(select, node("p", contract ? `Explicit destination: ${contract.title}, ${contract.target}, snapshot ${short(contract.hash)}, environment ${activeEnvironment()}. Review all imported URLs and permission expectations before execution.` : "Open an operation to choose a destination for imported templates.", "hint"));
    const apply = button("Assign selected test data to this contract context", () => { root.NamazuWorkbench.applyBrowserTestData(select.value, preferences[select.value]); status("Selected draft templates assigned to this contract context. Write permission remains off; no baseline replayed."); }, "btn sm"); apply.disabled = !contract; host.append(apply);
  }
  async function openBruno(mode) { const contract = contractFor(activeTab()) || runtime.workspace?.contracts[0]; if (contract && !contract.request_collection) await root.NamazuWorkbench.useContract(runtime.workspace, contract, activeTab()?.operationKey, {environmentId: activeEnvironment(), tabId: activeTab()?.id}); root.NamazuWorkbench.openBruno(); root.NamazuBruno.selectMode?.(mode); }
  async function addBrunoCollection(input) {
    const workspace = await ensureWorkspace(), result = await api(`/api/workspaces/${workspace.id}/bruno`, input);
    // A slow import may finish after a context switch. Never overwrite another workspace view.
    if (runtime.workspace?.id !== workspace.id) { status("Definitions were saved in their original workspace. Reopen that workspace to inspect them."); return result; }
    runtime.workspace = result.workspace; await refreshWorkspaces(); renderTree(); renderToolbar();
    const collection = runtime.workspace.request_collections.find(item => item.id === result.collection_id);
    if (collection?.operations[0]) await openOperation(collection, collection.operations[0]);
    status(result.duplicate ? "This collection snapshot is already present. Existing drafts and identities were retained." : "Bruno definitions added to this workspace. No requests sent, scripts executed, identity assigned or readiness inferred.");
    return result;
  }
  async function acceptBrunoSources(result) {
    const workspace = result.workspace;
    if (!workspace || workspace.id !== runtime.workspace?.id) { status("Collections imported into their original workspace. Open that workspace to inspect them."); return; }
    const treeScroll = $("desktop-collection-tree").scrollTop;
    runtime.workspace = workspace; await refreshWorkspaces(); renderTree(); renderTabs(); renderToolbar();
    $("desktop-collection-tree").scrollTop = treeScroll; scheduleSave();
    status("Collections imported. Existing tabs, drafts and identities were retained. No requests sent.");
  }
  async function openImportedRequests(ids = []) {
    const collection = (runtime.workspace?.request_collections || []).find(item => ids.includes(item.id)) || collections()[0];
    if (collection?.operations?.[0]) await openOperation(collection, collection.operations[0]);
    else showView("welcome");
  }
  async function history() {
    showView("request-history"); const host = $("desktop-request-history"); host.replaceChildren(node("h2", "Request history"), node("p", "Recorded requests retain their contract, target, identity reference and snapshot. Opening a receipt never sends it again."));
    const response = await api("/api/desktop/requests", null, "GET"), rows = response.requests || [];
    if (!rows.length) host.append(node("p", "No requests have been sent in this local workbench."));
    for (const row of rows) { const item = button(`${row.request?.method || row.method || row.context?.method || "Request"} ${row.request?.url || row.url || row.context?.target || row.request_id} · ${row.status}`, async () => {
      const record = await api(`/api/desktop/requests/${encodeURIComponent(row.request_id)}`, null, "GET"), context = record.context || {};
      const contract = runtime.workspace?.contracts.find(value => value.id === context.contract_id);
      const operation = contract?.operations.find(value => value.id === context.operation_key);
      if (contract && operation) { await openOperation(contract, operation); activeTab().record = record; activeTab().result = record.result; activeTab().responseTab = "exchange"; renderResponse(); }
      else { host.append(node("h3", "Historical exchange"), node("pre", JSON.stringify(record, null, 2), "workspace-code"), button("Export exchange", () => download(record, `namazu-exchange-${record.request_id}.json`))); }
    }, "desktop-recent"); host.append(item); }
  }
  function environments(editingId) {
    showView("environment-editor"); const host = $("desktop-environment-editor"); host.replaceChildren(node("h2", "Environments"), node("p", "Variables and target choices belong to this workspace. Changing an environment never extends credential scope. Review any changed API target in Contracts & setup before sending."));
    if (!runtime.workspace) { host.append(button("Create a workspace", () => showWorkspace("contracts"))); return; }
    const editing = store.environments.find(item => item.id === editingId && item.workspaceId === runtime.workspace.id);
    const name = labelled("Environment name", editing?.name || ""), variables = labelled("Variables (JSON object, no credentials)", JSON.stringify(editing?.variables || {}, null, 2), true);
    const targets = runtime.workspace.contracts.map(contract => ({contract, field: labelled(`${contract.title} API target`, editing?.targets?.[contract.id] ?? contract.target ?? "")}));
    host.append(name.wrapper, variables.wrapper, ...targets.map(item => item.field.wrapper), button("Save environment", async () => {
      if (!name.input.value.trim()) throw Error("Enter an environment name."); const values = JSON.parse(variables.input.value);
      if (!values || Array.isArray(values) || typeof values !== "object") throw Error("Variables must be a JSON object.");
      if (Object.keys(values).some(M.secretName)) throw Error("Store credentials in named identity profiles, not environment variables.");
      if (JSON.stringify(M.safeValue(values)) !== JSON.stringify(values)) throw Error("Credential-like environment values must use a named identity profile.");
      const environment = {id: editing?.id || crypto.randomUUID(), workspaceId: runtime.workspace.id, name: name.input.value.trim(), variables: values, targets: Object.fromEntries(targets.map(item => [item.contract.id, item.field.input.value.trim()]))};
      if (editing) store.environments[store.environments.indexOf(editing)] = environment; else store.environments.push(environment); scheduleSave(); await flush(); renderToolbar(); environments(); status("Environment saved locally. Choose it in the toolbar to open separate request drafts.");
    }, "btn primary"));
    for (const environment of store.environments.filter(item => item.workspaceId === runtime.workspace.id)) host.append(node("h3", environment.name), node("pre", JSON.stringify({variables: environment.variables, targets: environment.targets}, null, 2), "workspace-code"), button("Edit environment", () => environments(environment.id)), button("Remove environment", () => { store.environments = store.environments.filter(item => item.id !== environment.id); if (activeEnvironment() === environment.id) store.workspaces[runtime.workspace.id].environmentId = "default"; scheduleSave(); renderToolbar(); environments(); }));
  }
  function labelled(label, value, multiline = false) { const wrapper = node("label", "", "workspace-field"), input = node(multiline ? "textarea" : "input"); input.value = value; input.setAttribute("aria-label", label); wrapper.append(node("span", label), input); return {wrapper, input}; }
  async function changeEnvironment(id) {
    if (!runtime.workspace) return; store.workspaces[runtime.workspace.id] = {...store.workspaces[runtime.workspace.id], environmentId: id};
    const tab = activeTab(), contract = contractFor(tab), operation = tab && operationFor(tab); if (contract && operation) await openOperation(contract, operation); renderToolbar(); scheduleSave();
  }
  async function newWorkspace() { await showWorkspace("contracts"); $("desktop-workspace-review").querySelector(".workspace-header-actions button")?.click(); }
  async function localSample() { await flush(); const response = await api("/api/desktop/sample", {}), workspace = response.workspace || response; runtime.workspace = workspace; store.activeWorkspaceId = workspace.id; await refreshWorkspaces(); renderTree(); renderToolbar(); const contract = workspace.contracts[0]; if (contract?.operations[0]) await openOperation(contract, contract.operations[0]); status("Local sample ready. The mock API is running on loopback; no request sent yet."); }
  function bind() {
    header = root.NamazuDesktopHeader.create({api, guard: guarded, settings: () => openExpert("settings"), history,
      target: () => { if (contractFor(activeTab())?.request_collection) { activeTab().requestTab = "contract"; showView("request"); renderRequest(); } else return showWorkspace("contracts", activeTab()?.contractId); },
      closeWorkspace: async () => { await flush(); runtime.workspace = null; store.activeWorkspaceId = null; store.selectedTab = null; renderToolbar(); renderTree(); showView("welcome"); scheduleSave(); status("Workspace view closed. Saved drafts and evidence remain available; this does not close Namazu or stop active work."); },
      importKind: async kind => { if (kind === "openapi") await showWorkspace("contracts");
        else if (kind === "bruno-definitions" || kind === "bruno-results") await openBruno(kind);
        else if (kind === "workspace") { await showWorkspace("contracts"); root.NamazuWorkspaces.instance.openWorkspaceFile(); }
        else { await openExpert("audit"); root.NamazuWorkbench.openSavedReport(); }
      }});
    $("desktop-home").onclick = () => showView("welcome"); $("desktop-workspace").onchange = () => guarded(() => selectWorkspace($("desktop-workspace").value));
    $("desktop-import").onclick = () => header.openImport();
    $("desktop-welcome-import").onclick = () => guarded(() => showWorkspace("contracts"));
    $("desktop-welcome-open").onclick = () => guarded(async () => { await showWorkspace("contracts"); root.NamazuWorkspaces.instance.openWorkspaceFile(); });
    $("desktop-welcome-auth").onclick = () => guarded(() => root.NamazuIdentities?.open());
    $("desktop-welcome-continue").onclick = () => guarded(async () => { if (activeTab()) { showView("request"); renderRequest(); } else if (collections().length) await openImportedRequests(); else { $("desktop-workspace").focus(); status("Open a recent workspace or import a collection to continue."); } });
    $("desktop-new-workspace").onclick = () => guarded(newWorkspace); $("desktop-welcome-sample").onclick = () => guarded(localSample);
    $("desktop-identity").onclick = () => guarded(() => root.NamazuIdentities?.open());
    $("desktop-environments").onclick = () => environments(); $("desktop-environment").onchange = () => guarded(() => changeEnvironment($("desktop-environment").value));
    $("theme-select").addEventListener("change", () => { store.preferences.theme = $("theme-select").value; renderToolbar(); scheduleSave(); });
    $("desktop-search").oninput = () => { runtime.search = $("desktop-search").value; store.filters.search = runtime.search; renderTree(); scheduleSave(); };
    $("desktop-method").onchange = () => { editDraft({method: $("desktop-method").value}); activeTab().writeConsent = false; renderRequest(); };
    $("desktop-request-url").oninput = () => editDraft({url: $("desktop-request-url").value, manualUrl: true});
    $("desktop-write-consent").onchange = () => { if (activeTab()) activeTab().writeConsent = $("desktop-write-consent").checked; };
    $("desktop-send").onclick = () => guarded(sendRequest); $("desktop-cancel").onclick = () => guarded(cancelRequest);
    $("desktop-validate").onclick = () => guarded(validateRequest); $("desktop-save-baseline").onclick = () => guarded(saveBaseline);
    $("desktop-save-draft").onclick = () => guarded(async () => { const previous = activeTab(); if (!previous) return; replaceTab(M.saveDraft(previous)); renderTabs(); scheduleSave(); try { await flush(); } catch (failure) { const current = store.tabs.find(tab => tab.id === previous.id); if (current) { current.savedDraft = previous.savedDraft; current.dirty = true; renderTabs(); } throw failure; } status("Request draft saved locally. Credential-like values are masked in persisted data."); });
    $("desktop-layout-toggle").onclick = () => { store.layout.orientation = store.layout.orientation === "rows" ? "columns" : "rows"; applyLayout(); scheduleSave(); };
    $("desktop-sidebar-toggle").onclick = () => $("desktop-workbench").classList.toggle("desktop-collections-open");
    $("desktop-theme").onclick = () => { const theme = document.documentElement.dataset.theme === "light" ? "dark" : "light"; root.NamazuWorkbench.setTheme(theme); store.preferences.theme = theme; renderToolbar(); scheduleSave(); };
    $("desktop-history").onclick = () => guarded(history); $("desktop-advanced").onclick = () => guarded(() => openExpert("settings"));
    $("desktop-testing-open").onclick = () => guarded(() => testing.open());
    for (const id of ["desktop-bruno", "desktop-welcome-bruno"]) $(id).onclick = () => guarded(openBruno);
    $("desktop-welcome-guided").onclick = () => guarded(() => openExpert("api"));
    $("desktop-welcome-report").onclick = () => guarded(async () => { await openExpert("audit"); root.NamazuWorkbench.openSavedReport(); });
    document.querySelectorAll("[data-desktop-view]").forEach(item => { item.onclick = () => guarded(() => showWorkspace(item.dataset.desktopView)); });
    setupResize("desktop-sidebar-resize", event => { store.layout.sidebarWidth = Math.max(185, Math.min(450, event.clientX)); }, direction => { store.layout.sidebarWidth = Math.max(185, Math.min(450, (store.layout.sidebarWidth || 244) + direction * 10)); });
    setupResize("desktop-response-resize", event => { const rect = $("desktop-request-split").getBoundingClientRect(), vertical = store.layout.orientation === "rows" || innerWidth < 760; store.layout.requestRatio = Math.max(20, Math.min(80, (vertical ? (event.clientY - rect.top) / rect.height : (event.clientX - rect.left) / rect.width) * 100)); }, direction => { store.layout.requestRatio = Math.max(20, Math.min(80, (store.layout.requestRatio || 48) + direction * 3)); });
    root.addEventListener("namazu:workspace-updated", event => {
      const workspace = event.detail.workspace; if (!workspace) return; runtime.workspace = workspace; store.activeWorkspaceId = workspace.id;
      const existing = runtime.workspaces.findIndex(item => item.id === workspace.id); if (existing < 0) runtime.workspaces.unshift(workspace); else runtime.workspaces[existing] = workspace;
      renderToolbar(); renderTree(); renderRecent(); scheduleSave();
    });
    root.addEventListener("namazu:workspace-close", () => { showView(activeTab() ? "request" : "welcome"); if (activeTab()) renderRequest(); });
    root.addEventListener("namazu:workspace-busy", event => { for (const element of [$("desktop-workspace"), $("desktop-import"), $("desktop-header-context"), $("desktop-sidebar"), $("desktop-request-tabs")]) element.inert = Boolean(event.detail.saving); });
    root.addEventListener("namazu:contract-imported", event => guarded(async () => { const workspace = await ensureWorkspace(); runtime.workspace = await api(`/api/workspaces/${workspace.id}/contracts/import`, {items: [{raw_spec: event.detail.spec.document, source_url: event.detail.spec.source_url || ""}]}); renderTree(); renderToolbar(); status("Imported contract is now in this workspace. Review target and identity assignments before sending."); }));
    document.addEventListener("keydown", event => {
      if (!runtime.ready) return;
      if (event.key === "Escape") { runtime.menu?.remove(); error(""); }
      if (!(event.ctrlKey || event.metaKey) || document.querySelector("dialog[open]")) return;
      if (runtime.view === "expert") return;
      if (["Enter", "s", "o", "t", "w", "k"].includes(event.key.toLowerCase()) || event.key === "Enter") event.stopImmediatePropagation();
      if (event.key === "Enter") { event.preventDefault(); event.stopImmediatePropagation(); if (runtime.view === "request") guarded(sendRequest); }
      else if (event.key.toLowerCase() === "s") { event.preventDefault(); $("desktop-save-draft").click(); }
      else if (event.key.toLowerCase() === "o") { event.preventDefault(); header.openImport(); }
      else if (event.shiftKey && event.key.toLowerCase() === "t") { event.preventDefault(); guarded(restoreClosed); }
      else if (event.key.toLowerCase() === "w" && activeTab()) { event.preventDefault(); guarded(() => closeRequestTab(activeTab().id)); }
      else if (event.key.toLowerCase() === "k") { event.preventDefault(); $("desktop-search").focus(); }
    }, true);
  }
  async function start() {
    document.body.classList.add("desktop-enabled"); $("desktop-workbench").hidden = false; $("desktop-workbench").inert = true; bind();
    const [saved, listed] = await Promise.all([api("/api/desktop/state", null, "GET"), api("/api/workspaces", null, "GET")]);
    Object.assign(store, saved.state || {}); runtime.revision = saved.revision || 0; runtime.workspaces = listed.workspaces || [];
    runtime.search = store.filters.search || ""; runtime.treeOpen = new Set(store.filters.treeOpen || []); $("desktop-search").value = runtime.search;
    if (store.preferences.theme) root.NamazuWorkbench.setTheme(store.preferences.theme);
    // Write consent is an action, never a restorable preference.
    for (const tab of [...store.tabs, ...(store.closedTabs || [])]) { tab.writeConsent = false; delete tab.result; delete tab.record; }
    renderRecent(); renderToolbar(); applyLayout();
    const chosen = runtime.workspaces.find(item => item.id === store.activeWorkspaceId);
    if (chosen) await selectWorkspace(chosen.id); else { renderTree(); showView("welcome"); }
    runtime.startupMs = performance.now() - started;
    $("desktop-workbench").inert = false;
    if (!root.NamazuStartup) throw Error("Startup checks could not load. Reload Namazu to retry.");
    await root.NamazuStartup.complete();
    runtime.ready = true; $("desktop-workbench").dataset.ready = "true";
    status(`Ready. Workbench loaded in ${Math.round(runtime.startupMs)} ms. Opening saved drafts sends no requests.`);
  }
  let initialisation;
  async function requireReady() {
    await initialisation;
    if (!runtime.ready) throw Error("The workbench has not finished loading. Reload Namazu to retry.");
  }
  const testing = root.NamazuDesktopTesting?.create({api, workspace: () => runtime.workspace, activeTab, guard: guarded, status, download,
    show: () => showView("testing"), workspaceView: showWorkspace,
    requestView: () => { if (!activeTab()) throw Error("Open the associated operation from the collection first."); showView("request"); renderRequest(); },
    applyDraft(id, draft, caseId) { const current = store.tabs.find(tab => tab.id === id); if (!current) throw Error("The request tab was closed."); const updated = M.updateDraft(current, draft); updated.oobCaseIds = [...new Set([...(current.oobCaseIds || []), caseId])]; updated.writeConsent = false; replaceTab(updated); renderTabs(); scheduleSave(); },
    unlinkCase(caseId) { const tab = activeTab(); if (!tab) throw Error("Select a request draft first."); tab.oobCaseIds = (tab.oobCaseIds || []).filter(id => id !== caseId); tab.writeConsent = false; scheduleSave(); },
    async reviewPlan(plan, workspaceId) { if (runtime.workspace?.id !== workspaceId) throw Error("Workspace changed during planning. Reopen the intended workspace to review its new plan."); await showWorkspace("plan"); root.NamazuWorkspaces.instance.state.plan = plan; root.NamazuWorkspaces.instance.render(); },
  });
  root.NamazuDesktop = {flush: async () => { await requireReady(); return flush(); }, openImport: async () => { await requireReady(); header.openImport(); }, importContracts: async () => { await requireReady(); return showWorkspace("contracts"); }, showWorkspace, openExpert, openOperation, addBrunoCollection,
    brunoDestination: async () => { await requireReady(); await flush(); return ensureWorkspace(); }, acceptBrunoSources, openImportedRequests, openEnvironments: environments,
    identityContext: () => ({workspace: runtime.workspace, tab: activeTab(), contract: contractFor(activeTab())}),
    refreshIdentityWorkspace(workspace) { if (!workspace || workspace.id !== runtime.workspace?.id) return; root.dispatchEvent(new CustomEvent("namazu:workspace-updated", {detail: {workspace}})); if (activeTab()) renderRequest(); },
    evidenceExpansion: () => Object.fromEntries(Object.entries(store.filters.evidenceExpansion || {}).filter(([key, value]) => key.length <= 2048 && typeof value === "boolean").slice(-1000)),
    setEvidenceExpansion(key, expanded) { if (typeof key !== "string" || key.length > 2048 || typeof expanded !== "boolean") return; const held = {...store.filters.evidenceExpansion}; delete held[key]; held[key] = expanded; store.filters.evidenceExpansion = Object.fromEntries(Object.entries(held).slice(-1000)); scheduleSave(); },
    diagnostics: () => ({startupMs: runtime.startupMs, treeRenderMs: runtime.lastTreeMs, tabs: store.tabs.length, workspaceId: runtime.workspace?.id, revision: runtime.revision}),
  };
  initialisation = start().catch(() => {
    runtime.ready = false; $("desktop-workbench").inert = true; $("desktop-workbench").dataset.ready = "false";
    root.NamazuStartup?.fail("initialization-failed");
    error("The workbench could not finish loading. Reload Namazu to retry; saved work remains on disk.");
    status("Startup failed. No requests were replayed.");
  });
})(typeof window === "undefined" ? globalThis : window);
