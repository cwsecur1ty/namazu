/* Pure request-tab state. No IO, credentials, or target dispatch. */
(function (root, factory) {
  const api = factory(); root.NamazuDesktopModel = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window === "undefined" ? globalThis : window, function () {
  "use strict";
  const copy = value => JSON.parse(JSON.stringify(value));
  const secretName = name => /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|token|access[-_]?token|refresh[-_]?token|password|client[-_]?secret|bearer)$/i.test(name);
  const tabKey = value => JSON.stringify([value.workspaceId, value.contractId, value.snapshotHash, value.operationKey, value.environmentId || "default"]);
  function parameterExample(parameter) {
    const schema = parameter.schema || {};
    return parameter.example ?? schema.example ?? schema.default ?? schema.enum?.[0];
  }
  function createTab({workspace, contract, operation, environmentId = "default", request, id}) {
    const parameters = {};
    for (const parameter of operation.parameters || []) { const example = parameterExample(parameter); if (example !== undefined) parameters[`${parameter.in}.${parameter.name}`] = example; }
    const draft = {method: operation.method, url: `${contract.target || ""}${operation.path || ""}`, parameters, headers: {},
      body: "", content_type: Object.keys(operation.request_body?.content || {})[0] || "application/json", assertions: {},
      identityRef: contract.identity?.profile_id || null, manualUrl: false, bodyEntered: false};
    if (request) Object.assign(draft, request);
    if (operation.request_definition) {
      const imported = operation.request_definition.request;
      Object.assign(draft, {url: imported.url, method: imported.method, headers: copy(imported.headers || {}),
        body: imported.body == null ? (imported.has_body && imported.body_mode === "json" ? "null" : "") : typeof imported.body === "string" ? imported.body : JSON.stringify(imported.body),
        content_type: imported.content_type || "application/json", bodyEntered: Boolean(imported.has_body),
        bodyEncoding: imported.body_mode === "form-urlencoded" ? "raw-form" : "", manualUrl: true});
    }
    const tab = {id: id || `request-${typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2)}`,
      workspaceId: workspace.id, contractId: contract.id, snapshotHash: contract.hash, operationKey: operation.id,
      localOperationId: operation.local_id || `${operation.method} ${operation.path}`, environmentId,
      title: operation.summary || operation.operation_id || operation.path, method: operation.method, path: operation.path,
      draft, savedDraft: copy(draft), dirty: false, requestTab: "params", responseTab: "body"};
    tab.key = tabKey(tab); return tab;
  }
  function updateDraft(tab, patch) {
    const draft = {...tab.draft, ...copy(patch)};
    return {...tab, draft, dirty: JSON.stringify(draft) !== JSON.stringify(tab.savedDraft)};
  }
  function saveDraft(tab) { return {...tab, savedDraft: copy(tab.draft), dirty: false}; }
  function closeTab(state, id) {
    const index = state.tabs.findIndex(tab => tab.id === id), closed = state.tabs[index];
    if (!closed) return state;
    const tabs = state.tabs.filter(tab => tab.id !== id);
    return {...state, tabs, selectedTab: state.selectedTab === id ? tabs[Math.min(index, tabs.length - 1)]?.id || null : state.selectedTab,
      closedTabs: [...(state.closedTabs || []), closed].slice(-20)};
  }
  function restoreClosed(state) {
    const closed = [...(state.closedTabs || [])], tab = closed.pop();
    return tab ? {...state, tabs: [...state.tabs, tab], closedTabs: closed, selectedTab: tab.id} : state;
  }
  function resolveVariables(value, variables = {}) {
    if (typeof value === "string") return value.replace(/\{\{\s*([\w.-]+)\s*\}\}/g, (_match, name) => {
      if (!Object.prototype.hasOwnProperty.call(variables, name)) throw Error(`Environment variable ${name} is not defined.`);
      return String(variables[name]);
    });
    if (Array.isArray(value)) return value.map(item => resolveVariables(item, variables));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, resolveVariables(item, variables)]));
    return value;
  }
  function requestPayload(tab, contract, environment, generate = false) {
    if (tab.draft.assertionsInvalid) throw Error("Response assertions contain invalid JSON. Correct them before preparing or sending this request.");
    const draft = resolveVariables(tab.draft, environment?.variables || {}), target = environment?.targets?.[tab.contractId];
    if (target && target.replace(/\/$/, "") !== contract?.target?.replace(/\/$/, "")) throw Error("This environment's target needs explicit contract target and identity scope review before sending.");
    const request = {method: draft.method, parameters: draft.parameters || {}, headers: draft.headers || {}, content_type: draft.content_type, assertions: draft.assertions || {}};
    if (!generate && draft.manualUrl && draft.url) request.url = draft.url;
    if (!generate && (draft.body !== "" || draft.bodyEntered)) {
      if (draft.body !== "" && /json|x-www-form-urlencoded|multipart\/form-data/i.test(draft.content_type || "") && !(draft.bodyEncoding === "raw-form" && /x-www-form-urlencoded/i.test(draft.content_type))) {
        try { request.body = JSON.parse(draft.body); } catch { throw Error("The request body must be valid JSON for this content type."); }
      } else request.body = draft.body;
    }
    return {workspace_id: tab.workspaceId, contract_id: tab.contractId, snapshot_hash: tab.snapshotHash, operation_key: tab.operationKey,
      environment_id: tab.environmentId, request, timeout: 15, allow_mutating: Boolean(tab.writeConsent)};
  }
  function safeValue(value, parent = "") {
    if (Array.isArray(value)) return value.map(item => safeValue(item, parent));
    if (value && typeof value === "object") {
      const result = {};
      for (const [name, item] of Object.entries(value)) {
        if (["result", "response", "record", "running", "controller", "polling", "writeConsent"].includes(name)) continue;
        if (secretName(name) && !/Ref$|_ref$/i.test(name)) result[name] = "<credential>";
        else result[name] = safeValue(item, name);
      }
      return result;
    }
    if (typeof value !== "string") return value;
    let text = value.replace(/((?:Bearer|Basic)\s+)[A-Za-z0-9+/_.=-]+/gi, "$1<credential>");
    text = text.replace(/([?&](?:token|access_token|api_key|key|password)=)[^&#\s]*/gi, "$1<credential>");
    if (parent === "body" || parent === "variables" || /^[\s]*[\[{]/.test(text)) {
      try { return JSON.stringify(safeValue(JSON.parse(text))); } catch { /* Keep non-JSON request bodies. */ }
    }
    return text.replace(/((?:password|access_token|refresh_token|client_secret|api_key)=)[^&\s]*/gi, "$1<credential>");
  }
  function serialise(state) {
    return safeValue({tabs: state.tabs || [], closedTabs: state.closedTabs || [], selectedTab: state.selectedTab || null,
      layout: state.layout || {}, filters: state.filters || {}, environments: state.environments || [],
      preferences: state.preferences || {}, workspaces: state.workspaces || {}, activeWorkspaceId: state.activeWorkspaceId || null});
  }
  return {tabKey, createTab, updateDraft, saveDraft, closeTab, restoreClosed, resolveVariables, requestPayload, safeValue, serialise, secretName};
});
