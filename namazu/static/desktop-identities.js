/* Named OAuth identities; secrets never enter localStorage or request drafts. */
(function (root) {
  "use strict";
  const node = (tag, text, cls) => { const value = document.createElement(tag); if (text !== undefined) value.textContent = text; if (cls) value.className = cls; return value; };
  const state = {workspace: null, profileId: null, job: null, busy: false};
  let dialog, body, message, closeButton, workspacePicker, fields = {}, assignmentRows = [], capabilities = {};
  async function api(url, payload, method) {
    const response = await fetch(url, {method: method || (payload === undefined ? "GET" : "POST"), headers: payload === undefined ? {} : {"Content-Type": "application/json"}, body: payload === undefined ? undefined : JSON.stringify(payload)});
    const value = await response.json(); if (!response.ok) throw Error(typeof value.detail === "string" ? value.detail : "The identity change could not be completed."); return value;
  }
  function button(label, action, primary = false) { const value = node("button", label, "btn" + (primary ? " primary" : "")); value.type = "button"; value.onclick = () => run(action); return value; }
  function field(label, key, value = "", type = "text") {
    const wrap = node("label", undefined, "identity-field"); wrap.append(node("span", label)); const input = node(type === "textarea" ? "textarea" : "input");
    if (type !== "textarea") input.type = type; input.id = "identity-" + key; input.value = value; input.autocomplete = "off"; input.spellcheck = false; wrap.append(input); fields[key] = input; return wrap;
  }
  function select(label, key, options, selected) { const wrap = node("label", undefined, "identity-field"); wrap.append(node("span", label)); const input = node("select"); input.id = "identity-" + key; for (const [value, title] of options) { const option = node("option", title); option.value = value; option.selected = value === selected; input.append(option); } fields[key] = input; wrap.append(input); return wrap; }
  function update(workspace) { state.workspace = workspace; root.dispatchEvent(new CustomEvent("namazu:workspace-updated", {detail: {workspace}})); }
  async function run(action) {
    if (state.busy) return; state.busy = true; body.inert = true; dialog.setAttribute("aria-busy", "true"); message.textContent = "Working…";
    try { await action(); } catch (error) { message.textContent = error.message || "The change could not be completed. Your workspace is retained."; }
    finally { state.busy = false; body.inert = false; dialog.setAttribute("aria-busy", "false"); }
  }
  function create() {
    if (dialog) return;
    dialog = node("dialog", undefined, "identity-dialog"); dialog.id = "identity-dialog"; dialog.setAttribute("aria-labelledby", "identity-title");
    const header = node("header"); const title = node("h2", "Configure authentication"); title.id = "identity-title"; closeButton = button("Close", () => dialog.close()); closeButton.onclick = () => { if (!state.busy) dialog.close(); }; header.append(title, closeButton);
    dialog.append(header, node("p", "Configure a named identity, acquire a token explicitly, then assign only the API targets that may receive it.", "identity-intro"));
    workspacePicker = node("div", undefined, "identity-workspace"); body = node("div", undefined, "identity-body"); message = node("p", "", "identity-message"); message.id = "identity-message"; message.setAttribute("role", "status"); message.setAttribute("aria-live", "polite"); dialog.append(workspacePicker, body, message);
    dialog.addEventListener("cancel", event => { if (state.busy) event.preventDefault(); });
    dialog.addEventListener("close", () => { if (fields.client_secret) fields.client_secret.value = ""; });
    document.body.append(dialog);
  }
  function selected() { return (state.workspace?.profiles || []).find(profile => profile.id === state.profileId); }
  function render(prefill = {}) {
    fields = {}; body.replaceChildren(); if (!state.workspace) { body.append(node("p", "Choose or create a Namazu workspace to keep identities and assignments together.")); return; }
    const columns = node("div", undefined, "identity-columns"), profiles = node("aside", undefined, "identity-profiles"); profiles.setAttribute("aria-label", "Named identities"); profiles.append(node("h3", "Identities"), button("New client-credentials identity", () => { state.profileId = null; render(); message.textContent = "No credentials saved or token requested yet."; }));
    for (const profile of state.workspace.profiles || []) { const item = button(profile.name, () => { state.profileId = profile.id; render(); message.textContent = "Identity selected. No token request sent."; }); item.title = profile.name; item.setAttribute("aria-pressed", String(profile.id === state.profileId)); profiles.append(item); }
    const main = node("section", undefined, "identity-editor"); columns.append(profiles, main); body.append(columns);
    const profile = selected();
    if (profile && profile.kind !== "oauth-client-credentials") {
      main.append(node("h3", profile.name), node("p", "Bearer identity · credential " + (profile.credential_available ? "available and masked" : "not loaded")), button("Edit bearer identity in workspace setup", () => { dialog.close(); return root.NamazuDesktop.showWorkspace("identities"); })); renderAssignments(main, profile); return;
    }
    const config = profile?.oauth_config || prefill;
    main.append(node("h3", "OAuth 2.0 client credentials"), node("p", "POST · application/x-www-form-urlencoded. Saving credentials makes no network requests.", "identity-note"));
    const grid = node("div", undefined, "identity-grid");
    grid.append(field("Identity / profile name", "name", profile?.name || prefill.name || ""), field("Token endpoint URL", "endpoint", config.endpoint || "", "url"), field("Client ID", "client_id", config.client_id || ""), field("Client secret", "client_secret", "", "password"), field("Scope", "scope", config.scope || ""), field("Grant type", "grant", "client_credentials"));
    fields.grant.readOnly = true; fields.client_secret.autocomplete = "new-password"; fields.client_secret.placeholder = profile?.configuration_available ? "Configured; leave blank to keep" : prefill.secret_reference ? "Unresolved reference; enter locally" : "Enter client secret";
    main.append(grid);
    const advanced = node("details", undefined, "identity-advanced"); advanced.append(node("summary", "Advanced client authentication and storage"));
    advanced.append(select("Client authentication", "credential_placement", [["post", "Client ID and secret in POST body (default)"], ["basic", "HTTP Basic client authentication"]], config.credential_placement || "post"), select("Credential storage", "persistence", [["session", "This session only"], ["windows", "Windows protected storage for this user"]], profile?.configuration_persistence || "session"));
    fields.persistence.querySelector('[value="windows"]').disabled = !capabilities.windows;
    advanced.append(node("p", "No automatic acquisition or refresh. Reacquire explicitly after expiry. API bearer assignments and write authorization remain separate.", "identity-note")); main.append(advanced);
    const actions = node("div", undefined, "identity-actions"); actions.append(button("Save credentials", save), button(profile?.acquisition?.state === "acquired" || profile?.acquisition?.state === "expired" ? "Reacquire token" : "Get token", acquire, true)); main.append(actions);
    if (prefill.secret_reference) main.append(node("p", "Bruno secret reference: " + prefill.secret_reference + ". Imported scripts are not executed.", "identity-note"));
    renderStatus(main, profile);
    if (profile) renderAssignments(main, profile);
  }
  function renderStatus(host, profile) {
    const section = node("section", undefined, "identity-state"); section.append(node("h3", "What is established?")); const facts = node("dl");
    const acquisition = profile?.acquisition || {}, ctx = root.NamazuDesktop?.identityContext?.(), tab = ctx?.tab, operation = ctx?.contract?.operations?.find(row => row.id === tab?.operationKey), identity = operation?.identity || ctx?.contract?.identity;
    const receipt = tab?.record?.context || tab?.result?.context, response = tab?.result?.response || tab?.record?.result?.response;
    const attached = Boolean(profile && receipt?.identity_ref === profile.id && response), assigned = Boolean(profile && identity?.profile_id === profile.id);
    const rows = [["Credentials", profile?.configuration_available ? "Configured; secret protected" : "Client secret not configured in this session"], ["Token", acquisition.state === "acquired" && profile?.credential_available ? "Acquired; API access remains unverified" : acquisition.state === "expired" ? "Expired; reacquire explicitly" : "Not acquired or not loaded"], ["Current request", attached ? "Recorded exchange used this identity reference" : assigned ? "Assigned; attachment occurs only on explicit Send within scope" : "This identity is not assigned to the current request"], ["API acceptance", attached && response?.status >= 200 && response.status < 300 ? "Recorded 2xx response; roles and resource access remain unverified" : attached && response?.status === 403 ? "403 recorded; credentials, roles and entitlement cannot be distinguished from this alone" : "Not established by token acquisition"], ["Business baseline", "Token acquisition establishes no successful business baseline"]];
    if (acquisition.acquired_at) rows.push(["Acquired", new Date(acquisition.acquired_at * 1000).toLocaleString()]);
    if (acquisition.expires_at) rows.push(["Expiry", new Date(acquisition.expires_at * 1000).toLocaleString()]); else if (acquisition.acquired_at) rows.push(["Expiry", "Not supplied by identity platform"]);
    if (acquisition.scope !== null && acquisition.scope !== undefined) rows.push(["Returned scope", acquisition.scope || "(empty)"]);
    for (const [key, value] of rows) facts.append(node("dt", key), node("dd", value)); section.append(facts); host.append(section);
  }
  async function save() {
    const payload = Object.fromEntries(Object.entries(fields).filter(([key]) => ["name", "endpoint", "client_id", "scope", "grant", "credential_placement", "persistence"].includes(key)).map(([key, value]) => [key, value.value]));
    if (!payload.name.trim() || !payload.endpoint.trim() || !payload.client_id.trim()) throw Error("Enter a profile name, token endpoint and client ID.");
    if (state.profileId) payload.id = state.profileId;
    if (fields.client_secret.value) payload.client_secret = fields.client_secret.value;
    fields.client_secret.value = "";
    const result = await api(`/api/workspaces/${state.workspace.id}/oauth-identities`, payload);
    state.profileId = result.profile_id; update(result.workspace); render(); message.textContent = "Credentials configured. No token or API request was sent.";
  }
  async function acquire() {
    await save(); const wid = state.workspace.id; const job = await api(`/api/workspaces/${wid}/oauth-identities/${state.profileId}/acquire`, {}); state.job = job;
    const cancel = button("Cancel token request", async () => {}); cancel.onclick = async () => { try { await api(`/api/workspaces/${wid}/acquisitions/${job.id}/cancel`, {}); cancel.disabled = true; } catch { message.textContent = "Cancellation could not be confirmed; wait for the bounded token request to settle."; } };
    // Cancellation remains usable while the editor is inert.
    message.replaceChildren(node("span", "Requesting a token… API requests: 0. "), cancel);
    let result = job;
    while (["requesting", "stopping"].includes(result.state)) { await new Promise(resolve => setTimeout(resolve, 200)); result = await api(`/api/workspaces/${wid}/acquisitions/${job.id}`); }
    state.job = null; update(await api(`/api/workspaces/${wid}`)); render();
    message.textContent = `${result.detail} Authentication attempts: ${result.attempts}; responses: ${result.responses}. API requests: 0.`;
  }
  function renderAssignments(host, profile) {
    const section = node("section", undefined, "identity-assignments"); section.append(node("h3", "Assign to selected API targets"), node("p", "Choose only the collections or contracts that may receive this identity. Per-request and contract overrides take precedence. Assigning grants no write permission.", "identity-note")); assignmentRows = [];
    for (const contract of [...(state.workspace.contracts || []), ...(state.workspace.request_collections || [])]) {
      const row = node("div", undefined, "identity-assignment"); const label = node("label"), check = node("input"); check.type = "checkbox"; check.dataset.contractId = contract.id; label.append(check, node("span", contract.title));
      const scopes = node("textarea"); scopes.rows = 2; scopes.setAttribute("aria-label", `Allowed API origins/base paths for ${contract.title}`); scopes.value = (contract.identity?.allowed_scopes?.length ? contract.identity.allowed_scopes : contract.targets || [contract.target]).filter(Boolean).join("\n");
      const mode = node("select"); mode.setAttribute("aria-label", `Assignment level for ${contract.title}`); for (const [value, title] of [["shared", "Shared collection / contract identity"], ...(contract.environment ? [["environment", `Imported environment: ${contract.environment}`]] : [])]) { const option = node("option", title); option.value = value; mode.append(option); }
      row.append(label, mode, scopes, node("small", `Current identity: ${contract.identity?.name || "none"}. Only URLs inside these scopes can receive the token.`)); section.append(row); assignmentRows.push({contract, check, scopes, mode});
    }
    const apply = async remove => { const selectedRows = assignmentRows.filter(row => row.check.checked); if (!selectedRows.length) throw Error("Select at least one collection or contract."); const result = await api(`/api/workspaces/${state.workspace.id}/identity-assignments`, {profile_id: profile.id, assignments: selectedRows.map(row => ({contract_id: row.contract.id, kind: row.mode.value, environment: row.contract.environment || null, allowed_scopes: row.scopes.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean), remove}))}); update(result.workspace); render(); message.textContent = remove ? "Selected assignments removed. Explicit overrides remain visible and take precedence." : "Selected assignments saved. No token or API requests sent; write permissions unchanged."; };
    const actions = node("div", undefined, "identity-actions"); actions.append(button("Assign to selected", () => apply(false)), button("Remove selected assignments", () => apply(true))); section.append(actions);
    const ctx = root.NamazuDesktop?.identityContext?.();
    if (ctx?.contract?.request_collection && ctx.tab) {
      const scope = node("textarea"); scope.rows = 2; scope.value = ctx.contract.targets.join("\n"); scope.setAttribute("aria-label", "Current request override API scopes");
      const override = async kind => { const result = await api(`/api/workspaces/${state.workspace.id}/identity-assignments`, {profile_id: profile.id, assignments: [{contract_id: ctx.contract.id, operation_key: ctx.tab.operationKey, kind, allowed_scopes: scope.value.split(/\r?\n/).filter(Boolean)}]}); update(result.workspace); render(); message.textContent = "Current request override saved; no requests sent."; };
      const details = node("details"); details.append(node("summary", "Current request override"), scope, button("Use this identity for current request", () => override("request")), button("Use no identity for current request", () => override("anonymous"))); section.append(details);
    }
    host.append(section);
  }
  async function open(options = {}) {
    create(); if (!dialog.open) dialog.showModal(); message.textContent = "Loading named identities…";
    await run(async () => {
      capabilities = await api("/api/desktop/credentials"); const list = await api("/api/workspaces"); const current = root.NamazuDesktop?.identityContext?.()?.workspace;
      const id = options.workspace_id || current?.id || state.workspace?.id;
      state.workspace = id ? await api(`/api/workspaces/${id}`) : null;
      workspacePicker.replaceChildren(); const select = node("select"); select.setAttribute("aria-label", "Authentication workspace"); const empty = node("option", "Choose a Namazu workspace"); empty.value = ""; select.append(empty);
      for (const item of list.workspaces || []) { const option = node("option", item.title); option.value = item.id; select.append(option); } select.value = id || "";
      select.onchange = () => run(async () => { state.workspace = select.value ? await api(`/api/workspaces/${select.value}`) : null; state.profileId = null; render(); message.textContent = "Workspace selected; no token requests sent."; });
      workspacePicker.append(select, button("Create Namazu workspace", async () => { const result = await api("/api/workspaces", {title: "API workspace"}); update(result); const option = node("option", result.title); option.value = result.id; select.append(option); select.value = result.id; state.profileId = null; render(options.prefill || {}); message.textContent = "Workspace created. Configure credentials without contacting any API."; }));
      state.profileId = options.profile_id || null; render(options.prefill || {}); message.textContent = "Acquiring a token is an explicit action. Import and report viewing never acquire tokens.";
    });
  }
  root.NamazuIdentities = Object.freeze({open});
})(window);
