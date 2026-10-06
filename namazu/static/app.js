"use strict";



(() => {

  const SVG_NS = "http://www.w3.org/2000/svg";

  const $ = (id) => document.getElementById(id);

  const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

  const METHOD_ORDER = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"];

  const STRUCTURED_MEDIA = /json|x-www-form-urlencoded|multipart\/form-data/i;



  const state = {

    spec: null,

    operation: null,

    schema: null,

    importMode: "url",

    selected: new Set(),

    collapsed: new Set(),

    history: [],

    seq: 0,

    run: { rows: [], total: 0, running: false, cancelled: false },

    busy: false,

    busyFocus: null,

    baseOverride: false,

    section: "endpoints",

    savedEntry: null,

    audit: { findings: [], running: false, cancelled: false, done: 0, total: 0,

             requests: 0, notes: [], discovery: null, finding: null, startedAt: null,
             log: [], logEntry: null, logTruncated: false },

  };

  const SEVERITIES = ["critical", "high", "medium", "low", "info"];

  const PROFILE_NOTES = {

    passive: "One request per endpoint. Everything else is read from the contract and that single response.",

    readonly: "Adds authorization, CORS, TLS, method and input probes. Only GET, HEAD and OPTIONS are sent; nothing is written.",

    thorough: "Everything read-only, with more parameters probed per endpoint and a short rate-limit burst. More requests per endpoint.",

    writes: "Adds mass-assignment and write-authorization probes. These create or modify data on the target.",

  };



  /* ───────────────────────── preferences ───────────────────────── */

  const prefs = {

    read(key, fallback) {

      try { const value = localStorage.getItem(`namazu-${key}`); return value === null ? fallback : value; }

      catch { return fallback; }

    },

    write(key, value) {

      try { localStorage.setItem(`namazu-${key}`, String(value)); } catch { /* preferences are optional */ }

    },

    clear(key) {

      try { localStorage.removeItem(`namazu-${key}`); } catch { /* preferences are optional */ }

    },

  };



  function setTheme(theme, persist = false) {

    const selected = theme === "light" ? "light" : "dark";

    document.documentElement.dataset.theme = selected;

    document.querySelector('meta[name="color-scheme"]')?.setAttribute("content", selected);

    const next = selected === "dark" ? "light" : "dark";

    $("theme-toggle").setAttribute("aria-label", `Switch to ${next} mode`);

    $("theme-toggle").title = `Switch to ${next} mode`;

    $("theme-toggle").querySelector('[data-icon="sun"]').hidden = selected === "light";

    $("theme-toggle").querySelector('[data-icon="moon"]').hidden = selected === "dark";

    $("theme-select").value = selected;

    if (persist) prefs.write("theme", selected);

  }



  function setLayout(mode, persist = false) {

    const stacked = mode === "rows";

    $("op-split").classList.toggle("stacked", stacked);

    $("layout-toggle").querySelector('[data-icon="cols"]').hidden = stacked;

    $("layout-toggle").querySelector('[data-icon="rows"]').hidden = !stacked;

    const label = stacked ? "Switch to side-by-side layout" : "Switch to stacked layout";

    $("layout-toggle").setAttribute("aria-label", label);

    $("layout-toggle").title = label;

    $("op-splitter").setAttribute("aria-orientation", stacked ? "horizontal" : "vertical");

    if (persist) prefs.write("layout", stacked ? "rows" : "cols");

  }



  function setPanelWidth(px, persist = false) {

    const width = Math.min(Math.max(Math.round(px), 210), 560);

    document.documentElement.style.setProperty("--panel-w", `${width}px`);

    if (persist) prefs.write("panel-w", width);

    return width;

  }



  function setRequestBasis(percent, persist = false) {

    const value = Math.min(Math.max(percent, 22), 78);

    document.documentElement.style.setProperty("--req-basis", `${value.toFixed(1)}%`);

    if (persist) prefs.write("req-basis", value.toFixed(1));

  }



  function setWrap(on, persist = false) {

    $("response-body").classList.toggle("wrap", on);

    $("wrap-toggle").setAttribute("aria-pressed", String(on));

    if (persist) prefs.write("wrap", on ? "1" : "0");

  }



  /* ───────────────────────── small helpers ───────────────────────── */

  function el(tag, className, text) {

    const node = document.createElement(tag);

    if (className) node.className = className;

    if (text !== undefined) node.textContent = String(text);

    return node;

  }

  function icon(d, width = "2.2") {

    const svg = document.createElementNS(SVG_NS, "svg");

    svg.setAttribute("viewBox", "0 0 24 24");

    svg.setAttribute("fill", "none");

    svg.setAttribute("stroke", "currentColor");

    svg.setAttribute("stroke-width", width);

    svg.setAttribute("stroke-linecap", "round");

    svg.setAttribute("stroke-linejoin", "round");

    svg.setAttribute("aria-hidden", "true");

    const path = document.createElementNS(SVG_NS, "path");

    path.setAttribute("d", d);

    svg.append(path);

    return svg;

  }

  function stringify(value) { return typeof value === "string" ? value : JSON.stringify(value, null, 2); }

  function prettyBody(value) {

    if (typeof value !== "string") return stringify(value) ?? "";

    try { return JSON.stringify(JSON.parse(value), null, 2); } catch { return value; }

  }

  function errorText(error) { return error instanceof Error ? error.message : String(error); }

  function announce(text) { $("live-status").textContent = text; }

  function message(id, value) { $(id).textContent = value || ""; $(id).hidden = !value; }

  function methodBadge(method) { return el("span", `method ${String(method).toLowerCase()}`, method); }

  function pill(text, kind = "") { return el("span", `pill ${kind}`.trim(), text); }

  function validationLabel(v) { return v?.valid === true ? "Contract passed" : v?.valid === false ? "Contract failed" : "Not validated"; }

  function validationKind(v) { return v?.valid === true ? "pass" : v?.valid === false ? "fail" : "warn"; }

  function statusKind(status) { return status >= 200 && status < 300 ? "pass" : status >= 400 ? "fail" : "warn"; }

  function byteSize(text) { try { return new TextEncoder().encode(String(text ?? "")).length; } catch { return String(text ?? "").length; } }

  function humanBytes(count) {

    if (count < 1024) return `${count} B`;

    if (count < 1024 * 1024) return `${(count / 1024).toFixed(count < 10240 ? 1 : 0)} KB`;

    return `${(count / 1048576).toFixed(1)} MB`;

  }

  function clockTime(iso) {

    const date = new Date(iso);

    return Number.isNaN(date.getTime()) ? "" : date.toTimeString().slice(0, 8);

  }

  function formatIssues(issues) {

    return (issues || []).map((issue) => {

      if (typeof issue === "string") return issue;

      const where = issue.path || issue.location || "";

      return `${where}${where ? ": " : ""}${issue.message || stringify(issue)}`;

    });

  }

  let toastTimer = 0;

  function toast(text) {

    $("toast").textContent = text;

    $("toast").hidden = false;

    clearTimeout(toastTimer);

    toastTimer = setTimeout(() => { $("toast").hidden = true; }, 2400);

  }

  async function copyText(text, label) {

    if (!text) return;

    try {

      await navigator.clipboard.writeText(text);

      toast(`${label} copied.`);

    } catch {

      const holder = el("textarea");

      holder.value = text;

      document.body.append(holder);

      holder.select();

      const copied = document.execCommand?.("copy");

      holder.remove();

      toast(copied ? `${label} copied.` : "Copying is blocked in this browser. Select the text instead.");

    }

    announce(`${label} copied to the clipboard.`);

  }



  /* ───────────────────────── sample contract ───────────────────────── */

  const sample = {

    openapi: "3.0.3",

    info: { title: "Pet service", version: "1.0.0", description: "An example contract for exploring Namazu. Point the base URL at your own service before sending requests." },

    servers: [{ url: "http://127.0.0.1:8080" }],

    paths: {

      "/pets": {

        get: { summary: "List available pets", tags: ["Pets"], parameters: [{ name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 100, default: 10 } }], responses: { "200": { description: "Pet list", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Pet" } } } } } } },

        post: { summary: "Create a pet", tags: ["Pets"], requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/NewPet" } } } }, responses: { "201": { description: "Created pet", content: { "application/json": { schema: { $ref: "#/components/schemas/Pet" } } } }, "400": { description: "Invalid request", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } } } }

      },

      "/pets/{petId}": {

        get: { summary: "Find a pet by ID", tags: ["Pets"], parameters: [{ name: "petId", in: "path", required: true, schema: { type: "integer", minimum: 1, example: 1 } }], responses: { "200": { description: "A pet", content: { "application/json": { schema: { $ref: "#/components/schemas/Pet" } } } }, "404": { description: "Pet not found" } } },

        delete: { summary: "Delete a pet", tags: ["Pets"], parameters: [{ name: "petId", in: "path", required: true, schema: { type: "integer", minimum: 1, example: 1 } }], responses: { "204": { description: "Pet deleted" } } }

      }

    },

    components: {

      schemas: {

        NewPet: { type: "object", required: ["name"], properties: { name: { type: "string", minLength: 1, example: "Milo" }, status: { type: "string", enum: ["available", "pending", "adopted"], default: "available" } } },

        Pet: { type: "object", required: ["id", "name"], properties: { id: { type: "integer", example: 1 }, name: { type: "string", example: "Milo" }, status: { type: "string", enum: ["available", "pending", "adopted"] } } },

        Error: { type: "object", required: ["message"], properties: { message: { type: "string" } } }

      }

    }

  };



  /* ───────────────────────── key / value editor ───────────────────────── */

  function createKv(containerId, { noun, onChange }) {

    const container = $(containerId);



    function rows() { return [...container.querySelectorAll(".kv-row")]; }

    function trailing() {

      const list = rows();

      const last = list[list.length - 1];

      if (!last || last.querySelector(".kv-name").value.trim() || last.querySelector(".kv-value").value) addRow();

      if (!rows().length) addRow();

    }

    function changed() { trailing(); onChange?.(); }



    function addRow(name = "", value = "", enabled = true) {

      const row = el("div", "kv-row");

      const toggle = el("input");

      toggle.type = "checkbox";

      toggle.checked = enabled;

      toggle.setAttribute("aria-label", `Send this ${noun}`);

      const nameInput = el("input", "kv-name");

      nameInput.type = "text";

      nameInput.placeholder = "Name";

      nameInput.autocomplete = "off";

      nameInput.spellcheck = false;

      nameInput.value = name;

      nameInput.setAttribute("aria-label", `${noun} name`);

      const valueInput = el("input", "kv-value");

      valueInput.type = "text";

      valueInput.placeholder = "Value";

      valueInput.autocomplete = "off";

      valueInput.spellcheck = false;

      valueInput.value = value;

      valueInput.setAttribute("aria-label", `${noun} value`);

      const remove = el("button", "icon-btn");

      remove.type = "button";

      remove.setAttribute("aria-label", `Remove this ${noun}`);

      remove.append(icon("M6 6l12 12M18 6L6 18", "1.8"));

      remove.addEventListener("click", () => { row.remove(); changed(); });

      toggle.addEventListener("change", () => { row.classList.toggle("off", !toggle.checked); onChange?.(); });

      for (const input of [nameInput, valueInput]) input.addEventListener("input", changed);

      row.classList.toggle("off", !enabled);

      row.append(toggle, nameInput, valueInput, remove);

      container.append(row);

      return row;

    }



    function setAll(entries) {

      container.replaceChildren();

      for (const [name, value] of Object.entries(entries || {})) addRow(name, String(value));

      addRow();

      onChange?.();

    }



    function read() {

      const output = {};

      for (const row of rows()) {

        if (!row.querySelector("input[type=checkbox]").checked) continue;

        const name = row.querySelector(".kv-name").value.trim();

        const value = row.querySelector(".kv-value").value;

        if (!name) continue;

        if (/[\r\n]/.test(name + value)) throw new Error(`${noun} names and values cannot contain line breaks.`);

        if (/[^!-~]/.test(name)) throw new Error(`“${name}” is not a valid ${noun.toLowerCase()} name.`);

        output[name] = value;

      }

      return output;

    }



    function safeRead() { try { return read(); } catch { return {}; } }

    function count() { return Object.keys(safeRead()).length; }

    function text() { return rows().map((row) => `${row.querySelector(".kv-name").value}: ${row.querySelector(".kv-value").value}`).filter((line) => line.trim() !== ":").join("\n"); }

    function fromText(value) {

      const entries = {};

      for (const line of String(value).split("\n")) {

        if (!line.trim()) continue;

        const split = line.indexOf(":");

        if (split < 1) throw new Error(`Use “Name: value” on each line. Could not read “${line.trim().slice(0, 40)}”.`);

        entries[line.slice(0, split).trim()] = line.slice(split + 1).trim();

      }

      setAll(entries);

    }



    addRow();

    return { addRow, setAll, read, safeRead, count, text, fromText, focusLast: () => rows().at(-1)?.querySelector(".kv-name").focus() };

  }



  /* ───────────────────────── sections and views ───────────────────────── */

  const SECTIONS = {

    endpoints: { panel: "panel-endpoints" },

    schemas: { panel: "panel-schemas" },

    runner: { panel: "panel-runner", view: "view-runner" },

    history: { panel: "panel-history" },

    audit: { panel: "panel-audit" },

    source: { view: "view-source" },

    settings: { view: "view-settings" },

  };

  const VIEWS = ["view-empty", "view-operation", "view-schema", "view-runner", "view-source",

    "view-settings", "view-audit-report", "view-finding", "view-audit-log"];



  function showView(id) {

    for (const view of VIEWS) $(view).hidden = view !== id;

  }

  // Below the list/work breakpoint the two columns take turns, so opening an

  // item has to hand the screen back to the work area.

  function narrowLayout() { return window.matchMedia("(max-width: 680px)").matches; }

  function revealWork() { if (narrowLayout()) $("shell").classList.remove("mobile-panel"); }

  function updateEmptyState() {

    const loaded = Boolean(state.spec);

    $("empty-title").textContent = loaded ? "Nothing selected" : "No contract loaded";

    $("empty-text").textContent = loaded

      ? "Pick an endpoint or a component schema from the list."

      : "Import a Swagger or OpenAPI document to list its operations, build requests and validate responses.";

    $("empty-import").hidden = loaded;

    $("empty-sample").hidden = loaded;

  }

  function activateSection(name) {

    const config = SECTIONS[name] || SECTIONS.endpoints;

    state.section = name;

    for (const button of document.querySelectorAll(".rail-btn")) {

      const active = button.dataset.section === name;

      if (active) button.setAttribute("aria-current", "true");

      else button.removeAttribute("aria-current");

    }

    for (const key of Object.keys(SECTIONS)) {

      const panel = SECTIONS[key].panel;

      if (panel) $(panel).hidden = panel !== config.panel;

    }

    $("shell").classList.toggle("no-panel", !config.panel);

    $("shell").classList.toggle("mobile-panel", Boolean(config.panel) && narrowLayout());

    updateEmptyState();

    if (config.view) showView(config.view);

    else if (name === "schemas") showView(state.schema ? "view-schema" : "view-empty");

    else if (name === "audit") showView(state.audit.finding ? "view-finding" : "view-audit-report");

    else showView(state.operation ? "view-operation" : "view-empty");

    if (name === "runner") renderQueue();

    if (name === "history") renderHistory();

    if (name === "audit") renderFindings();

  }



  /* ───────────────────────── busy + status ───────────────────────── */

  const BUSY_IDS = ["send-request", "prepare-request", "regenerate", "format-body", "import-submit", "sample-import", "content-type", "empty-import", "empty-sample"];

  function setBusy(value, activeId) {

    if (value && !state.busy) state.busyFocus = document.activeElement;

    state.busy = value;

    for (const id of BUSY_IDS) $(id).disabled = value;

    for (const id of BUSY_IDS) $(id).classList.toggle("busy-ind", value && id === activeId);

    $("state-dot").classList.toggle("busy", value);

    document.querySelectorAll(".op-open,.leaf,.hist-row,.result-inspect,.finding-row").forEach((node) => { node.disabled = value; });

    updateSelection();

    $("session-state").textContent = value ? "Request in progress" : state.spec ? "Contract loaded" : "Ready";

    if (!value && state.busyFocus) {

      const target = state.busyFocus;

      if (document.activeElement === document.body && target.isConnected && target.getClientRects().length && !target.disabled) target.focus({ preventScroll: true });

      state.busyFocus = null;

    }

  }

  function updateStatusBar() {

    const writes = $("allow-writes").checked;

    $("status-writes").textContent = writes ? "writes enabled" : "writes off";

    $("status-writes").classList.toggle("on", writes);

    const verify = $("verify-tls").checked;

    $("status-tls").textContent = verify ? "TLS verify" : "TLS unverified";

    $("status-tls").classList.toggle("off", !verify);

    $("status-timeout").textContent = `${$("request-timeout").value || "15"}s timeout`;

    const base = $("base-url").value.trim();

    $("status-context").textContent = state.spec

      ? [state.spec.title, base, `${state.spec.operations.length} operations`].filter(Boolean).join("  ·  ")

      : "";

  }

  function syncWrites(source) {

    const value = source === "mirror" ? $("allow-writes-mirror").checked : $("allow-writes").checked;

    $("allow-writes").checked = value;

    $("allow-writes-mirror").checked = value;

    updateStatusBar();

    updateProfileNote();

  }



  /* ───────────────────────── server calls ───────────────────────── */

  async function api(path, payload) {

    const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload), credentials: "same-origin" });

    let data;

    try { data = await response.json(); }

    catch { throw new Error(`Namazu returned an unreadable response (HTTP ${response.status}). Check that the local server is running.`); }

    if (!response.ok) {

      const detail = data.detail ?? data.error ?? `HTTP ${response.status}`;

      throw new Error(typeof detail === "string" ? detail : stringify(detail));

    }

    return data;

  }

  function numericTimeout(id) {

    const value = Number($(id).value);

    if (!Number.isFinite(value) || value < 1 || value > 120) throw new Error("Timeout must be between 1 and 120 seconds.");

    return value;

  }



  const headerKv = createKv("header-rows", { noun: "Header", onChange: () => { updateHeaderCount(); markRequestDirty(); } });

  const importKv = createKv("import-header-rows", { noun: "Header" });



  function updateHeaderCount() {

    const count = Object.keys(headerKv.safeRead()).length;

    $("headers-count").textContent = count;

    $("headers-count").hidden = count === 0;

  }



  function authHeaders() {

    const mode = $("auth-mode").value;

    if (mode === "bearer") {

      const token = $("bearer-token").value.trim();

      return token ? { Authorization: `Bearer ${token}` } : {};

    }

    if (mode === "basic") {

      const user = $("basic-user").value;

      const pass = $("basic-pass").value;

      if (!user && !pass) return {};

      if (/[\r\n]/.test(user + pass)) throw new Error("Basic credentials cannot contain line breaks.");

      let encoded;

      try { encoded = btoa(unescape(encodeURIComponent(`${user}:${pass}`))); }

      catch { throw new Error("Basic credentials could not be encoded."); }

      return { Authorization: `Basic ${encoded}` };

    }

    if (mode === "apikey") {

      const name = $("apikey-name").value.trim();

      const value = $("apikey-value").value;

      if (!name) return {};

      if (/[^!-~]/.test(name) || /[\r\n]/.test(value)) throw new Error("Enter a valid API key header name and a single-line value.");

      return { [name]: value };

    }

    return {};

  }

  function requestHeaders() {

    const headers = headerKv.read();

    const auth = authHeaders();

    for (const name of Object.keys(auth)) {

      for (const existing of Object.keys(headers)) {

        if (existing.toLowerCase() === name.toLowerCase()) delete headers[existing];

      }

      headers[name] = auth[name];

    }

    return headers;

  }

  function renderAuthState() {

    const mode = $("auth-mode").value;

    $("auth-bearer").hidden = mode !== "bearer";

    $("auth-basic").hidden = mode !== "basic";

    $("auth-apikey").hidden = mode !== "apikey";

    oauthVisible();

    let text = "Nothing is added to the request.";

    let active = false;

    if (mode === "bearer") {

      const filled = Boolean($("bearer-token").value.trim());

      text = filled ? "Adds  Authorization: Bearer ••••" : "Enter a token to add an Authorization header.";

      active = filled;

    } else if (mode === "basic") {

      const filled = Boolean($("basic-user").value || $("basic-pass").value);

      text = filled ? `Adds  Authorization: Basic ••••  for ${$("basic-user").value || "(no user)"}` : "Enter credentials to add an Authorization header.";

      active = filled;

    } else if (mode === "oauth2") {

      const applied = Object.keys(headerKv.safeRead()).some((name) => name.toLowerCase() === "authorization");

      text = applied

        ? "A token obtained below is sent as an Authorization header."

        : "Fetch a token below; it is added to the Headers tab when it arrives.";

      active = applied;

    } else if (mode === "apikey") {

      const name = $("apikey-name").value.trim();

      text = name ? `Adds  ${name}: ••••` : "Enter a header name to send an API key.";

      active = Boolean(name);

    }

    $("auth-preview").textContent = text;

    $("auth-dot").hidden = !active;

    $("header-note").textContent = active

      ? "Sent with single requests and runner requests. The Auth tab overwrites any matching header here."

      : "Sent with single requests and runner requests. Auth settings are applied on top of these.";

    markRequestDirty();

  }



  /* ───────────────────────── import ───────────────────────── */

  function importMode(mode) {

    state.importMode = mode;

    $("url-source").hidden = mode !== "url";

    $("raw-source").hidden = mode !== "raw";

    for (const button of document.querySelectorAll("[data-import-mode]")) {

      const active = button.dataset.importMode === mode;

      button.classList.toggle("active", active);

      button.setAttribute("aria-selected", String(active));

      button.tabIndex = active ? 0 : -1;

    }

    message("import-error", "");

  }



  function renderContractFacts(spec, warnings) {

    $("loaded-card").hidden = false;

    $("fact-title").textContent = spec.title || "Untitled API";

    $("fact-version").textContent = spec.api_version || "-";

    $("fact-spec").textContent = spec.version ? (spec.version === "2.0" ? "Swagger 2.0" : `OpenAPI ${spec.version}`) : "-";

    $("fact-source").textContent = spec.source_url || "Pasted or uploaded document";

    $("fact-servers").textContent = (spec.servers || []).join("\n") || "-";

    $("fact-operations").textContent = spec.operations.length;

    $("fact-schemas").textContent = Object.keys(spec.schemas || {}).length;

    const list = $("warning-list");

    list.replaceChildren();

    for (const warning of warnings) list.append(el("li", "", warning));

    $("warning-block").hidden = warnings.length === 0;

  }



  function showNotice(lines) {

    const text = lines.filter(Boolean).join("\n");

    $("notice-text").textContent = text;

    $("notice").hidden = !text;

  }



  async function importSpec(useSample = false) {

    if (state.busy) return;

    message("import-error", "");

    try {

      const payload = { headers: importKv.read(), timeout: numericTimeout("import-timeout"), verify_tls: $("import-verify-tls").checked };

      if (useSample) {

        payload.raw_spec = JSON.stringify(sample);

      } else if (state.importMode === "url") {

        payload.url = $("spec-url").value.trim();

        if (!payload.url) throw new Error("Enter a Swagger or OpenAPI documentation URL.");

        if (!/^https?:\/\//i.test(payload.url)) throw new Error("Use a documentation URL beginning with http:// or https://.");

      } else {

        payload.raw_spec = $("raw-spec").value.trim();

        if (!payload.raw_spec) throw new Error("Paste a JSON or YAML specification, or choose a file.");

        const source = $("source-url").value.trim();

        if (source) {

          if (!/^https?:\/\//i.test(source)) throw new Error("Use a source URL beginning with http:// or https://.");

          payload.source_url = source;

        }

      }

      setBusy(true, useSample ? "sample-import" : "import-submit");

      const spec = await api("/api/import", payload);

      if (!Array.isArray(spec.operations)) throw new Error("The imported contract did not contain an operation list.");



      state.spec = spec;

      state.operation = null;

      state.schema = null;

      state.savedEntry = null;

      state.selected.clear();

      state.collapsed.clear();

      state.history = [];

      state.seq = 0;

      state.run = { rows: [], total: 0, running: false, cancelled: false };

      state.baseOverride = false;



      $("topbar-context").hidden = false;

      $("writes-switch").hidden = false;

      $("ctx-title").textContent = spec.title || "Untitled API";

      $("ctx-title").title = spec.title || "Untitled API";

      const apiVersion = spec.api_version || "";

      $("ctx-version").textContent = apiVersion ? `v${String(apiVersion).replace(/^v/i, "")}` : (spec.version || "OpenAPI");

      $("base-url").value = spec.base_url || "";

      $("server-options").replaceChildren(...(spec.servers || []).map((server) => {

        const option = el("option");

        option.value = typeof server === "string" ? server : server.url;

        return option;

      }));

      $("endpoint-count").textContent = spec.operations.length;

      $("schema-count").textContent = Object.keys(spec.schemas || {}).length;

      $("endpoint-search").value = "";

      $("schema-search").value = "";

      $("method-filter").value = "all";

      $("allow-writes").checked = false;

      syncWrites();

      headerKv.setAll({});

      $("auth-mode").value = "none";

      $("bearer-token").value = "";

      $("basic-user").value = "";

      $("basic-pass").value = "";

      $("apikey-name").value = "";

      $("apikey-value").value = "";

      renderAuthState();

      $("download-results").disabled = true;

      $("source-back").hidden = false;

      message("work-error", "");



      const warnings = [...(spec.warnings || [])];

      if (useSample) warnings.push("Sample contract loaded. Point the base URL at your own service before sending requests.");

      renderContractFacts(spec, warnings);

      showNotice(warnings);

      renderSecuritySchemes();

      fillOauthPresets();

      renderEndpoints();

      renderSchemas();

      renderHistory();

      renderRun();

      updateStatusBar();

      setBusy(false);



      activateSection("endpoints");

      const first = spec.operations[0];

      if (first) await selectOperation(first.id);

      else { showView("view-empty"); updateEmptyState(); $("endpoint-search").focus(); }

      announce(`Imported ${spec.title || "API"} with ${spec.operations.length} operations.`);

    } catch (error) {

      message("import-error", errorText(error));

      activateSection("source");

    } finally {

      setBusy(false);

    }

  }



  function renderSecuritySchemes() {

    const schemes = state.spec?.security_schemes || {};

    const names = Object.keys(schemes);

    const list = $("scheme-list");

    list.replaceChildren();

    for (const name of names) {

      const scheme = schemes[name] || {};

      const row = el("div", "scheme-row");

      row.append(el("code", "", name));

      const parts = [scheme.type, scheme.scheme, scheme.in && `in ${scheme.in}`, scheme.name && `“${scheme.name}”`, scheme.bearerFormat].filter(Boolean);

      row.append(el("span", "", parts.join(" · ") || "unspecified"));

      list.append(row);

    }

    $("security-schemes").hidden = names.length === 0;

  }



  /* ───────────────────────── endpoint list ───────────────────────── */

  function visibleOperations() {

    const query = $("endpoint-search").value.trim().toLowerCase();

    const method = $("method-filter").value;

    return (state.spec?.operations || []).filter((op) => {

      if (method !== "all" && op.method !== method) return false;

      if (!query) return true;

      return `${op.method} ${op.path} ${op.summary || ""} ${op.operation_id || ""} ${(op.tags || []).join(" ")}`.toLowerCase().includes(query);

    });

  }

  function groupKey(op, mode) {

    if (mode === "method") return op.method;

    if (mode === "path") return `/${String(op.path).replace(/^\//, "").split("/")[0] || ""}`;

    return (op.tags || [])[0] || "Untagged";

  }

  function groupOperations(operations) {

    const mode = $("group-mode").value;

    if (mode === "none") return [["", operations]];

    const groups = new Map();

    for (const op of operations) {

      const key = groupKey(op, mode);

      if (!groups.has(key)) groups.set(key, []);

      groups.get(key).push(op);

    }

    const entries = [...groups.entries()];

    if (mode === "method") entries.sort((a, b) => METHOD_ORDER.indexOf(a[0]) - METHOD_ORDER.indexOf(b[0]));

    if (mode === "path") entries.sort((a, b) => a[0].localeCompare(b[0]));

    return entries;

  }

  function operationRow(op) {

    const row = el("div", `op-row${state.operation?.id === op.id ? " active" : ""}${op.deprecated ? " deprecated" : ""}`);

    const checkbox = el("input");

    checkbox.type = "checkbox";

    checkbox.checked = state.selected.has(op.id);

    checkbox.disabled = state.run.running;

    checkbox.setAttribute("aria-label", `Select ${op.method} ${op.path} for the runner`);

    checkbox.addEventListener("change", () => {

      if (checkbox.checked) state.selected.add(op.id); else state.selected.delete(op.id);

      updateSelection();

      renderQueue();

      updateGroupToggles();

    });

    const open = el("button", "op-open");

    open.type = "button";

    open.disabled = state.busy;

    open.title = `${op.method} ${op.path}${op.summary ? `: ${op.summary}` : ""}`;

    open.setAttribute("aria-label", `Open ${op.method} ${op.path}`);

    if (state.operation?.id === op.id) open.setAttribute("aria-current", "true");

    open.append(methodBadge(op.method), el("span", "op-name", op.path));

    open.addEventListener("click", () => { state.savedEntry = null; selectOperation(op.id); });

    row.append(checkbox, open);

    row.dataset.operation = op.id;

    return row;

  }

  function renderEndpoints() {

    const list = $("endpoint-list");

    list.replaceChildren();

    const operations = visibleOperations();

    if (!operations.length) {

      list.append(el("p", "list-empty", state.spec ? "No endpoint matches this filter." : "Import a contract to see its endpoints."));

      updateSelection();

      return;

    }

    for (const [name, ops] of groupOperations(operations)) {

      if (!name) {

        for (const op of ops) list.append(operationRow(op));

        continue;

      }

      const group = el("div", "group");

      const head = el("div", "group-head");

      const toggle = el("button", "group-toggle");

      toggle.type = "button";

      const expanded = !state.collapsed.has(name);

      toggle.setAttribute("aria-expanded", String(expanded));

      toggle.append(icon("M6 9.5l6 6 6-6"), el("span", "group-name", name), el("span", "group-count", ops.length));

      const selectAll = el("input");

      selectAll.type = "checkbox";

      selectAll.disabled = state.run.running;

      selectAll.dataset.group = name;

      selectAll.setAttribute("aria-label", `Select every endpoint in ${name}`);

      selectAll.addEventListener("change", () => {

        for (const op of ops) {

          if (selectAll.checked) state.selected.add(op.id); else state.selected.delete(op.id);

        }

        renderEndpoints();

        renderQueue();

      });

      head.append(toggle, selectAll);

      const body = el("div", "group-body");

      body.hidden = !expanded;

      for (const op of ops) body.append(operationRow(op));

      toggle.addEventListener("click", () => {

        const open = state.collapsed.has(name);

        if (open) state.collapsed.delete(name); else state.collapsed.add(name);

        toggle.setAttribute("aria-expanded", String(open));

        body.hidden = !open;

      });

      group.append(head, body);

      list.append(group);

      const chosen = ops.filter((op) => state.selected.has(op.id)).length;

      selectAll.checked = chosen === ops.length;

      selectAll.indeterminate = chosen > 0 && chosen < ops.length;

    }

    updateSelection();

  }

  function updateGroupToggles() {

    const grouped = groupOperations(visibleOperations());

    for (const [name, ops] of grouped) {

      if (!name) continue;

      const box = $("endpoint-list").querySelector(`input[data-group="${CSS.escape(name)}"]`);

      if (!box) continue;

      const chosen = ops.filter((op) => state.selected.has(op.id)).length;

      box.checked = chosen === ops.length;

      box.indeterminate = chosen > 0 && chosen < ops.length;

    }

  }

  function updateSelection() {

    const count = state.selected.size;

    $("selection-count").textContent = `${count} selected`;

    $("runner-count").textContent = count;

    $("rail-selected").textContent = count;

    $("rail-selected").hidden = count === 0;

    $("run-suite").disabled = state.busy || count === 0;

    $("run-audit").disabled = state.busy || state.audit.running || !state.spec;

    $("clear-selection").disabled = state.run.running || count === 0;

    $("clear-queue").disabled = state.run.running || count === 0;

    $("select-visible").disabled = state.run.running || !state.spec;

    $("runner-foot").textContent = count === 0 ? "No endpoints selected" : `${count} queued`;

  }



  function renderSchemas() {

    const list = $("schema-list");

    const query = $("schema-search").value.trim().toLowerCase();

    const names = Object.keys(state.spec?.schemas || {}).filter((name) => name.toLowerCase().includes(query)).sort();

    list.replaceChildren();

    if (!names.length) {

      list.append(el("p", "list-empty", state.spec ? "No component schema matches this filter." : "Import a contract to see its schemas."));

      return;

    }

    for (const name of names) {

      const button = el("button", `leaf${state.schema === name ? " active" : ""}`, name);

      button.type = "button";

      button.disabled = state.busy;

      button.addEventListener("click", () => selectSchema(name));

      list.append(button);

    }

  }

  function selectSchema(name) {

    state.schema = name;

    revealWork();

    showView("view-schema");

    $("schema-title").textContent = name;

    $("schema-content").textContent = stringify(state.spec.schemas[name]);

    renderSchemas();

    $("schema-title").focus();

    announce(`Showing component schema ${name}.`);

  }



  /* ───────────────────────── schema sampling ───────────────────────── */

  function resolveSchema(schema, depth = 0) {

    if (!schema || typeof schema !== "object" || depth > 8) return schema || {};

    if (schema.$ref?.startsWith("#/")) {

      let current = state.spec.document;

      for (const part of schema.$ref.slice(2).split("/")) current = current?.[part.replace(/~1/g, "/").replace(/~0/g, "~")];

      if (current) return resolveSchema({ ...current, ...Object.fromEntries(Object.entries(schema).filter(([key]) => key !== "$ref")) }, depth + 1);

    }

    return schema;

  }

  function sampleValue(source, depth = 0) {

    const schema = resolveSchema(source);

    if (schema.example !== undefined) return schema.example;

    if (schema.default !== undefined) return schema.default;

    if (schema.const !== undefined) return schema.const;

    if (schema.enum?.length) return schema.enum[0];

    if (schema.examples?.length) return schema.examples[0];

    if (depth > 5) return null;

    if (schema.oneOf?.length || schema.anyOf?.length) return sampleValue((schema.oneOf || schema.anyOf)[0], depth + 1);

    if (schema.allOf?.length) {

      const values = schema.allOf.map((part) => sampleValue(part, depth + 1));

      return values.every((value) => value && typeof value === "object" && !Array.isArray(value)) ? Object.assign({}, ...values) : values[0];

    }

    const type = Array.isArray(schema.type) ? schema.type.find((entry) => entry !== "null") : schema.type;

    if (type === "integer" || type === "number") {

      return Math.max(schema.minimum ?? 1, typeof schema.exclusiveMinimum === "number" ? schema.exclusiveMinimum + 1 : schema.exclusiveMinimum === true ? (schema.minimum ?? 0) + 1 : schema.minimum ?? 1);

    }

    if (type === "boolean") return true;

    if (type === "array") return Array.from({ length: Math.min(Math.max(schema.minItems || 1, 1), 5) }, () => sampleValue(schema.items || {}, depth + 1));

    if (type === "object" || schema.properties) {

      return Object.fromEntries(Object.entries(schema.properties || {})

        .filter(([key, property]) => !property.readOnly && (!schema.required || schema.required.includes(key)))

        .map(([key, value]) => [key, sampleValue(value, depth + 1)]));

    }

    if (schema.format === "date") return "2026-01-01";

    if (schema.format === "date-time") return "2026-01-01T00:00:00Z";

    if (schema.format === "uuid") return "00000000-0000-4000-8000-000000000001";

    if (schema.format === "email") return "tester@example.com";

    if (schema.format === "uri" || schema.format === "url") return "https://example.com";

    return "example".padEnd(Math.min(schema.minLength || 0, 256), "x").slice(0, schema.maxLength ?? undefined);

  }

  function parameterSchema(parameter) {

    return resolveSchema(parameter.schema || Object.values(parameter.content || {})[0]?.schema || parameter);

  }

  function schemaType(schema) { return Array.isArray(schema.type) ? schema.type.find((type) => type !== "null") : schema.type; }

  function parameterExample(parameter) {

    if (parameter.example !== undefined) return parameter.example;

    const example = Object.values(parameter.examples || {})[0];

    if (example?.value !== undefined) return example.value;

    const schema = parameterSchema(parameter);

    if (!parameter.required && parameter.in !== "path" && schema.default === undefined && schema.example === undefined) return "";

    return sampleValue(schema);

  }

  function requestParameters(op) {

    return (op.parameters || []).filter((parameter) => parameter.name && parameter.in && !["body", "formData"].includes(parameter.in));

  }

  function generatedParameters(op) {

    const result = {};

    for (const parameter of requestParameters(op)) {

      const value = parameterExample(parameter);

      if (value !== "") result[`${parameter.in}.${parameter.name}`] = value;

    }

    return result;

  }



  /* ───────────────────────── parameter editor ───────────────────────── */

  function renderParameters(op) {

    const parameters = requestParameters(op);

    const host = $("parameter-fields");

    host.replaceChildren();

    $("param-head").hidden = parameters.length === 0;

    $("no-params").hidden = parameters.length > 0;

    $("params-count").textContent = parameters.length;

    $("params-count").hidden = parameters.length === 0;



    parameters.forEach((parameter, index) => {

      const schema = parameterSchema(parameter);

      const required = Boolean(parameter.required) || parameter.in === "path";

      const id = `parameter-${index}`;

      const row = el("div", "kv-row");



      const include = el("input");

      include.type = "checkbox";

      include.checked = true;

      include.disabled = required;

      include.setAttribute("aria-label", required ? `${parameter.name} is required` : `Send ${parameter.name}`);

      include.addEventListener("change", () => { row.classList.toggle("off", !include.checked); markRequestDirty(); });



      const name = el("div", "pname");

      const label = el("label", "", parameter.name);

      label.htmlFor = id;

      if (required) label.append(el("span", "req", "*"));

      name.append(label, el("span", "in", parameter.in));



      const choices = Array.isArray(schema.enum)

        ? schema.enum

        : schemaType(schema) === "boolean"

          ? [true, false, ...((schema.nullable || schema.type?.includes?.("null")) ? [null] : [])]

          : null;

      const input = choices ? el("select") : el("input");

      input.id = id;

      input.dataset.parameterKey = `${parameter.in}.${parameter.name}`;

      input.dataset.parameterIndex = index;

      input.autocomplete = "off";

      input.spellcheck = false;

      if (required) input.setAttribute("aria-required", "true");

      if (choices) {

        input.dataset.choiceValues = "json";

        const blank = el("option", "", required ? "Select a value" : "Omit");

        blank.value = "";

        input.append(blank);

        for (const value of choices) {

          const option = el("option", "", value === "" ? "(empty string)" : stringify(value));

          option.value = JSON.stringify(value);

          input.append(option);

        }

      } else {

        input.type = "text";

        const type = schemaType(schema);

        input.placeholder = ["object", "array"].includes(type)

          ? `${type === "array" ? "Array" : "Object"} as JSON`

          : required ? "Required" : "Omit when empty";

      }



      const value = parameterExample(parameter);

      const explicit = parameter.example !== undefined || schema.example !== undefined || schema.default !== undefined

        || Object.values(parameter.examples || {}).some((example) => example?.value !== undefined);

      input.value = choices

        ? (value === undefined || (value === "" && !required && !explicit) ? "" : JSON.stringify(value))

        : (value === undefined || value === null ? "" : typeof value === "object" ? JSON.stringify(value) : String(value));



      const typeText = Array.isArray(schema.type) ? schema.type.join("|") : schema.type || "string";

      const meta = el("span", "kv-meta", schema.format ? `${typeText}/${schema.format}` : typeText);



      row.append(include, name, input, meta);

      if (parameter.description) {

        const note = el("p", "kv-desc", parameter.description);

        note.id = `${id}-note`;

        input.setAttribute("aria-describedby", note.id);

        row.append(note);

      }

      host.append(row);

    });

  }

  function collectParameters(op) {

    const output = {};

    const parameters = requestParameters(op);

    for (const input of $("parameter-fields").querySelectorAll("[data-parameter-key]")) {

      const row = input.closest(".kv-row");

      const include = row.querySelector("input[type=checkbox]");

      const parameter = parameters[Number(input.dataset.parameterIndex)];

      const required = Boolean(parameter.required) || parameter.in === "path";

      if (!include.checked) continue;

      const schema = parameterSchema(parameter);

      const raw = input.value;

      if (raw === "") {

        if (required) throw new Error(`Enter the required ${parameter.in} parameter “${parameter.name}”.`);

        continue;

      }

      let value = raw;

      const type = schemaType(schema);

      if (input.dataset.choiceValues === "json") {

        value = JSON.parse(raw);

      } else if (["integer", "number"].includes(type)) {

        value = Number(raw);

        if (!Number.isFinite(value) || (type === "integer" && !Number.isInteger(value))) {

          throw new Error(`“${parameter.name}” must be ${type === "integer" ? "an integer" : "a number"}.`);

        }

      } else if (type === "boolean") {

        if (!["true", "false"].includes(raw)) throw new Error(`“${parameter.name}” must be true or false.`);

        value = raw === "true";

      } else if (["array", "object"].includes(type)) {

        try { value = JSON.parse(raw); } catch { throw new Error(`“${parameter.name}” must contain valid JSON.`); }

      }

      output[input.dataset.parameterKey] = value;

    }

    return output;

  }



  /* ───────────────────────── request assembly ───────────────────────── */

  function connectionPayload() {

    const base = $("base-url").value.trim();

    if (base && !/^https?:\/\//i.test(base)) throw new Error("The base URL must begin with http:// or https://.");

    return {

      spec: state.spec,

      ...(base && state.baseOverride ? { base_url: base } : {}),

      headers: requestHeaders(),

      verify_tls: $("verify-tls").checked,

      timeout: numericTimeout("request-timeout"),

      allow_mutating: $("allow-writes").checked,

    };

  }

  function bodyContentTypes(op) { return Object.keys(op?.request_body?.content || op?.requestBody?.content || {}); }

  function requestPayload(generate = false) {

    if (!state.operation) throw new Error("Choose an endpoint first.");

    const payload = { ...connectionPayload(), operation_id: state.operation.id, parameters: collectParameters(state.operation) };

    if (bodyContentTypes(state.operation).length) {

      payload.content_type = $("content-type").value;

      if (!generate) {

        const raw = $("request-body").value;

        if (STRUCTURED_MEDIA.test(payload.content_type)) {

          if (!raw.trim()) throw new Error("Enter a request body, or choose Reset from schema to generate one.");

          try { payload.body = JSON.parse(raw); }

          catch { throw new Error("The request body is not valid JSON. Check the syntax before sending."); }

        } else {

          payload.body = raw;

        }

      }

    }

    return payload;

  }

  function markRequestDirty() {

    $("request-validation").hidden = true;

    $("request-preview").hidden = true;

  }

  function updateBodyMeta() {

    const value = $("request-body").value;

    const hasBody = bodyContentTypes(state.operation || {}).length > 0;

    $("body-dot").hidden = !hasBody || !value.trim();

    if (!hasBody) { $("body-meta").textContent = ""; return; }

    const lines = value ? value.split("\n").length : 0;

    $("body-meta").textContent = value

      ? `${$("content-type").value || "application/json"} · ${lines} line${lines === 1 ? "" : "s"} · ${humanBytes(byteSize(value))}`

      : `${$("content-type").value || "application/json"} · empty`;

  }



  function requestTab(name) {

    for (const tab of ["params", "headers", "auth", "body", "contract"]) {

      const active = tab === name;

      $(`req-${tab}`).hidden = !active;

      $(`req-${tab}-tab`).classList.toggle("active", active);

      $(`req-${tab}-tab`).setAttribute("aria-selected", String(active));

      $(`req-${tab}-tab`).tabIndex = active ? 0 : -1;

    }

  }

  function responseTab(name) {

    for (const tab of ["body", "validation", "headers"]) {

      const active = tab === name;

      $(`response-${tab}-panel`).hidden = !active;

      $(`response-${tab}-tab`).classList.toggle("active", active);

      $(`response-${tab}-tab`).setAttribute("aria-selected", String(active));

      $(`response-${tab}-tab`).tabIndex = active ? 0 : -1;

    }

  }



  function operationAuth(op) {

    const entries = (op.security || []).filter((entry) => entry && Object.keys(entry).length);

    if (!entries.length) return "";

    const names = [...new Set(entries.flatMap((entry) => Object.keys(entry)))];

    return names.length ? `auth: ${names.join(", ")}` : "auth required";

  }



  async function selectOperation(id, { prepare = null, focus = true, saved = null } = {}) {

    if (state.busy) return;

    const op = state.spec?.operations.find((entry) => entry.id === id);

    if (!op) return;

    state.operation = op;

    state.savedEntry = saved;

    if (!state.baseOverride) $("base-url").value = op.servers?.[0] || state.spec.base_url || "";



    revealWork();

    showView("view-operation");

    $("op-method").textContent = op.method;

    $("op-method").className = `method ${op.method.toLowerCase()}`;

    $("op-path").textContent = op.path;

    $("op-summary").textContent = op.summary && op.description && op.description !== op.summary

      ? `${op.summary}. ${op.description}`

      : op.summary || op.description || "";

    $("op-summary").hidden = !$("op-summary").textContent;

    const tags = (op.tags || []).join(", ");

    $("op-tag").textContent = tags;

    $("op-tag").hidden = !tags;

    const auth = operationAuth(op);

    $("op-auth").textContent = auth;

    $("op-auth").hidden = !auth;

    $("op-saved").hidden = !saved;

    $("operation-schema").textContent = stringify(op);

    $("response-contract").textContent = stringify(op.responses || {});

    const codes = Object.keys(op.responses || {});

    $("response-contract-count").textContent = codes.join(" ");



    renderParameters(op);

    const contentTypes = bodyContentTypes(op);

    $("content-type").replaceChildren(...contentTypes.map((type) => {

      const option = el("option", "", type);

      option.value = type;

      return option;

    }));

    if (contentTypes.includes("application/json")) $("content-type").value = "application/json";

    const hasBody = contentTypes.length > 0;

    $("body-bar").hidden = !hasBody;

    $("request-body").hidden = !hasBody;

    $("body-meta").hidden = !hasBody;

    $("no-body").hidden = hasBody;

    $("request-body").value = "";

    updateBodyMeta();



    $("request-validation").hidden = true;

    $("request-preview").hidden = true;

    $("response-empty").hidden = false;

    $("response-result").hidden = true;

    $("response-status").replaceChildren(el("span", "dim", "Response"));

    $("validation-dot").hidden = true;

    $("response-headers-count").hidden = true;

    requestTab(contentTypes.length && !requestParameters(op).length ? "body" : "params");

    responseTab("body");

    message("work-error", "");

    renderEndpoints();

    updateStatusBar();

    if (focus) $("op-path").focus();

    const shouldPrepare = prepare === null ? $("auto-prepare").checked : prepare;

    if (shouldPrepare) await prepareRequest(true, true);

  }



  function renderRequestValidation(validation, warnings = []) {

    const block = $("request-validation");

    block.replaceChildren();

    block.hidden = false;

    block.className = `verdict${validation?.valid === false ? " invalid" : validation?.valid !== true ? " unknown" : ""}`;

    block.append(el("strong", "", validation?.valid === true ? "Request matches the schema"

      : validation?.valid === false ? "Request validation failed" : "Request prepared"));

    const issues = [...new Set([...formatIssues(validation?.errors), ...formatIssues(validation?.warnings), ...formatIssues(warnings)])];

    if (issues.length) {

      const list = el("ul");

      for (const issue of issues) list.append(el("li", "", issue));

      block.append(list);

    }

  }



  async function prepareRequest(generate = false, initial = false) {

    if (state.busy || !state.operation) return;

    message("work-error", "");

    try {

      if (generate && !initial) renderParameters(state.operation);

      const payload = requestPayload(generate);

      setBusy(true, initial ? undefined : generate ? "regenerate" : "prepare-request");

      const result = await api("/api/prepare", payload);

      if (generate && result.has_body) {

        $("request-body").value = STRUCTURED_MEDIA.test(result.content_type || $("content-type").value)

          ? JSON.stringify(result.body, null, 2)

          : stringify(result.body) ?? "";

      }

      updateBodyMeta();

      renderRequestValidation(result.request_validation, result.warnings);

      $("prepared-url").textContent = `${result.method} ${result.url}`;

      $("request-preview").hidden = false;

      if (!initial) announce("Request prepared and validated locally.");

    } catch (error) {

      message("work-error", errorText(error));

    } finally {

      setBusy(false);

    }

  }



  function pushHistory(entry) {

    entry.seq = ++state.seq;

    state.history.unshift(entry);

    const limit = Number($("history-limit").value) || 100;

    if (state.history.length > limit) state.history.length = limit;

    renderHistory();

  }



  async function sendRequest() {

    if (state.busy || !state.operation) return;

    message("work-error", "");

    const op = state.operation;

    try {

      const payload = requestPayload();

      if (!SAFE_METHODS.has(op.method) && !payload.allow_mutating) {

        throw new Error(`Enable “Allow writes” in the top bar to send a ${op.method} request.`);

      }

      setBusy(true, "send-request");

      $("response-result").hidden = true;

      $("response-empty").hidden = false;

      announce(`Sending ${op.method} ${op.path}.`);

      const result = await api("/api/run", payload);

      state.savedEntry = null;

      $("op-saved").hidden = true;

      renderResponse(result);

      pushHistory({ operation_id: op.id, method: op.method, path: op.path, timestamp: new Date().toISOString(), source: "request", result });

      announce(`HTTP ${result.response?.status}. ${validationLabel(result.validation)}.`);

    } catch (error) {

      message("work-error", errorText(error));

      if (state.busy) {

        pushHistory({ operation_id: op.id, method: op.method, path: op.path, timestamp: new Date().toISOString(), source: "request", error: errorText(error) });

      }

      announce("The request failed.");

    } finally {

      setBusy(false);

    }

  }



  function renderResponse(result, { saved = false } = {}) {

    const response = result.response || {};

    const validation = result.validation || {};

    $("response-empty").hidden = true;

    $("response-result").hidden = false;



    const status = $("response-status");

    status.replaceChildren();

    status.append(pill(`HTTP ${response.status ?? "-"}`, statusKind(response.status)));

    status.append(pill(validationLabel(validation), validationKind(validation)));

    if (Number.isFinite(response.elapsed_ms)) status.append(el("span", "res-meta", `${Math.round(response.elapsed_ms)} ms`));

    status.append(el("span", "res-meta", humanBytes(byteSize(response.body))));

    if (response.truncated) status.append(pill("truncated", "warn"));

    const request = result.request || {};

    if (request.url) {

      status.append(el("span", "res-url", `${saved ? "saved · " : ""}${request.method || ""} ${request.url}`.trim()));

    }



    $("response-body").textContent = response.body === "" || response.body === undefined || response.body === null

      ? "(empty response body)"

      : prettyBody(response.body);



    const headers = response.headers || {};

    const table = $("response-headers");

    table.replaceChildren();

    for (const [name, value] of Object.entries(headers)) {

      table.append(el("div", "hk", name), el("div", "hv", value));

    }

    if (!Object.keys(headers).length) table.append(el("div", "hk", "-"), el("div", "hv", "no headers"));

    $("response-headers-count").textContent = Object.keys(headers).length;

    $("response-headers-count").hidden = Object.keys(headers).length === 0;



    const content = $("response-validation");

    content.replaceChildren(el("h4", "", validationLabel(validation)));

    content.append(el("p", "", validation.valid === true

      ? "The response matches the documented contract."

      : validation.valid === false

        ? "The response does not match the documented contract. Findings follow."

        : "A complete schema validation was not available for this response."));

    const errors = formatIssues(validation.errors);

    if (errors.length) {

      const list = el("ul", "issues bad");

      for (const issue of errors) list.append(el("li", "", issue));

      content.append(list);

    }

    const warnings = formatIssues(validation.warnings);

    if (response.truncated) warnings.push("The captured body was truncated, so validation is incomplete.");

    if (warnings.length) {

      content.append(el("h4", "", "Notes"));

      const list = el("ul", "issues");

      for (const issue of warnings) list.append(el("li", "", issue));

      content.append(list);

    }

    if (validation.checks?.length) {

      content.append(el("h4", "", "Contract checks"));

      for (const check of validation.checks) {

        if (typeof check === "string") { content.append(el("div", "check-row", check)); continue; }

        const row = el("div", "check-row");

        row.append(el("strong", "", check.name || check.check || check.type || "Check"));

        row.append(pill(check.valid === true ? "passed" : check.valid === false ? "failed" : "not validated", validationKind(check)));

        if (check.message || check.detail) row.append(el("p", "", check.message || check.detail));

        content.append(row);

      }

    }

    $("validation-dot").hidden = validation.valid !== false;

    $("validation-dot").className = `dot${validation.valid === false ? " bad" : ""}`;

    responseTab(validation.valid === false ? "validation" : "body");

  }



  /* ───────────────────────── history ───────────────────────── */

  function renderHistory() {

    const list = $("history-list");

    list.replaceChildren();

    $("history-count").textContent = state.history.length;

    $("rail-history").textContent = state.history.length;

    $("rail-history").hidden = state.history.length === 0;

    $("export-history").disabled = state.history.length === 0;

    $("clear-history").disabled = state.history.length === 0;

    $("download-results").disabled = state.run.rows.length === 0;

    if (!state.history.length) {

      list.append(el("p", "list-empty", "No requests sent in this session."));

      return;

    }

    for (const entry of state.history) {

      const row = el("button", `hist-row${state.savedEntry?.seq === entry.seq ? " active" : ""}`);

      row.type = "button";

      row.disabled = state.busy;

      const status = entry.result?.response?.status;

      const kind = entry.skipped ? "warn" : entry.error ? "fail" : statusKind(status);

      row.append(methodBadge(entry.method));

      const main = el("div", "hist-main");

      main.append(el("div", "hist-path", entry.path));

      const meta = el("div", "hist-meta");

      meta.append(el("span", "", clockTime(entry.timestamp)));

      if (entry.source === "runner") meta.append(el("span", "", "runner"));

      if (Number.isFinite(entry.result?.response?.elapsed_ms)) meta.append(el("span", "", `${Math.round(entry.result.response.elapsed_ms)} ms`));

      if (entry.result?.validation) meta.append(el("span", "", entry.result.validation.valid === true ? "contract ok" : entry.result.validation.valid === false ? "contract failed" : "unvalidated"));

      main.append(meta);

      row.append(main);

      row.append(el("span", `hist-status ${kind}`, entry.skipped ? "skip" : entry.error ? "err" : String(status ?? "-")));

      row.title = `${entry.method} ${entry.path} · ${entry.error || entry.skipped || `HTTP ${status ?? "-"}`}`;

      row.addEventListener("click", () => inspectEntry(entry));

      list.append(row);

    }

  }



  async function inspectEntry(entry) {

    if (state.busy) return;

    if (!entry.result) {

      message("work-error", entry.error || entry.skipped || "This entry has no captured exchange.");

      await selectOperation(entry.operation_id, { prepare: false, focus: false, saved: entry });

      renderHistory();

      return;

    }

    await selectOperation(entry.operation_id, { prepare: false, focus: false, saved: entry });

    const request = entry.result.request || {};

    if (request.has_body && bodyContentTypes(state.operation).length) {

      if (bodyContentTypes(state.operation).includes(request.content_type)) $("content-type").value = request.content_type;

      $("request-body").value = STRUCTURED_MEDIA.test(request.content_type || "")

        ? JSON.stringify(request.body, null, 2)

        : stringify(request.body) ?? "";

      updateBodyMeta();

    }

    renderResponse(entry.result, { saved: true });

    renderHistory();

    $(`response-${entry.result.validation?.valid === false ? "validation" : "body"}-tab`).focus();

    announce(`Showing the saved ${entry.method} ${entry.path} exchange. No request was sent.`);

  }



  /* ───────────────────────── runner ───────────────────────── */

  function selectedOperations() {

    return (state.spec?.operations || []).filter((op) => state.selected.has(op.id));

  }

  function renderQueue() {

    const queue = $("run-queue");

    queue.replaceChildren();

    const operations = selectedOperations();

    if (!operations.length) {

      queue.append(el("p", "list-empty", "Select endpoints in the Endpoints list to build a run."));

      return;

    }

    for (const op of operations) {

      const row = el("div", "queue-row");

      row.append(methodBadge(op.method), el("span", "op-name", op.path));

      const done = state.run.rows.find((entry) => entry.operation_id === op.id);

      const label = !state.run.rows.length ? "" : done

        ? (done.skipped ? "skipped" : done.error ? "failed" : `${done.result?.response?.status ?? "-"}`)

        : state.run.running ? "queued" : "";

      row.append(el("span", "qstate", label));

      queue.append(row);

    }

  }

  async function runSuite() {

    if (state.busy || !state.selected.size) return;

    message("work-error", "");

    let connection;

    try { connection = connectionPayload(); }

    catch (error) { message("work-error", errorText(error)); activateSection("endpoints"); return; }



    const operations = selectedOperations();

    state.run = { rows: [], total: operations.length, running: true, cancelled: false };

    activateSection("runner");

    $("cancel-suite").hidden = false;

    $("cancel-suite").disabled = false;

    $("cancel-suite").textContent = "Stop after current";

    $("suite-progress").hidden = false;

    $("run-state").hidden = false;

    $("run-state").textContent = "running";

    $("run-state").className = "chip warn";

    $("download-results").disabled = true;

    setBusy(true);

    renderEndpoints();

    renderRun();

    renderQueue();



    try {

      for (const op of operations) {

        if (state.run.cancelled) break;

        const entry = { operation_id: op.id, method: op.method, path: op.path, timestamp: new Date().toISOString(), source: "runner" };

        $("session-state").textContent = `Running ${state.run.rows.length + 1} of ${operations.length}`;

        if (!SAFE_METHODS.has(op.method) && !connection.allow_mutating) {

          entry.skipped = "Write methods are disabled.";

        } else {

          try {

            const contentTypes = bodyContentTypes(op);

            const payload = {

              ...connection,

              operation_id: op.id,

              parameters: generatedParameters(op),

              ...(contentTypes.length ? { content_type: contentTypes.includes("application/json") ? "application/json" : contentTypes[0] } : {}),

            };

            entry.result = await api("/api/run", payload);

          } catch (error) {

            entry.error = errorText(error);

          }

        }

        state.run.rows.push(entry);

        pushHistory({ ...entry });

        renderRun();

        renderQueue();

        announce(`Completed ${state.run.rows.length} of ${operations.length}.`);

      }

    } finally {

      state.run.running = false;

      $("cancel-suite").hidden = true;

      $("run-state").textContent = state.run.cancelled ? "stopped" : "finished";

      $("run-state").className = `chip ${state.run.cancelled ? "warn" : ""}`.trim();

      $("download-results").disabled = state.run.rows.length === 0;

      renderRun();

      renderQueue();

      setBusy(false);

      renderEndpoints();

      announce(state.run.cancelled ? "The run stopped." : "The run finished.");

    }

  }

  function renderRun() {

    const body = $("suite-results");

    body.replaceChildren();

    let passed = 0, failed = 0, skipped = 0, unknown = 0, requestErrors = 0, httpErrors = 0;



    for (const entry of state.run.rows) {

      const row = el("tr");

      const routeCell = el("td");

      const route = el("div", "result-route");

      route.append(methodBadge(entry.method), el("span", "op-name", entry.path));

      routeCell.append(route);

      const issue = entry.error || entry.skipped;

      if (issue) routeCell.append(el("p", "result-note bad", issue));



      const statusCell = el("td");

      const contractCell = el("td");

      const timeCell = el("td", "mono");

      const actionCell = el("td");



      if (entry.skipped) {

        skipped++;

        statusCell.append(pill("skipped", "warn"));

        contractCell.textContent = "-";

        timeCell.textContent = "-";

      } else if (entry.error) {

        requestErrors++;

        statusCell.append(pill("failed", "fail"));

        contractCell.textContent = "-";

        timeCell.textContent = "-";

      } else {

        const response = entry.result?.response || {};

        const check = entry.result?.validation;

        if (check?.valid === true) passed++; else if (check?.valid === false) failed++; else unknown++;

        if (response.status >= 400) httpErrors++;

        statusCell.append(pill(`HTTP ${response.status ?? "-"}`, statusKind(response.status)));

        contractCell.append(pill(validationLabel(check), validationKind(check)));

        timeCell.textContent = Number.isFinite(response.elapsed_ms) ? `${Math.round(response.elapsed_ms)} ms` : "-";

        const errors = formatIssues(check?.errors);

        const warnings = formatIssues(check?.warnings);

        if (errors.length) {

          contractCell.append(el("p", "result-note bad", errors[0]));

          if (errors.length > 1) {

            const details = el("details", "result-more");

            details.append(el("summary", "", `${errors.length - 1} more finding${errors.length > 2 ? "s" : ""}`));

            const list = el("ul", "issues bad");

            for (const issue of errors.slice(1)) list.append(el("li", "", issue));

            details.append(list);

            contractCell.append(details);

          }

        } else if (check?.valid !== true && warnings.length) {

          contractCell.append(el("p", "result-note", warnings[0]));

        }

        const inspect = el("button", "link result-inspect", "Inspect");

        inspect.type = "button";

        inspect.disabled = state.busy;

        inspect.setAttribute("aria-label", `Inspect the saved ${entry.method} ${entry.path} exchange`);

        inspect.addEventListener("click", () => {

          const saved = state.history.find((item) => item.source === "runner" && item.operation_id === entry.operation_id && item.timestamp === entry.timestamp) || entry;

          activateSection("history");

          inspectEntry(saved);

        });

        actionCell.append(inspect);

      }

      row.append(routeCell, statusCell, contractCell, timeCell, actionCell);

      body.append(row);

    }



    const progress = state.run.total ? Math.round(state.run.rows.length / state.run.total * 100) : 0;

    $("suite-progress").setAttribute("aria-valuenow", String(progress));

    $("suite-progress").firstElementChild.style.width = `${progress}%`;

    $("suite-progress").hidden = state.run.total === 0;



    if (!state.run.total) {

      $("suite-summary").textContent = "Select endpoints in the Endpoints list, then run them here.";

      $("run-state").hidden = true;

      return;

    }

    const prefix = state.run.running

      ? `${state.run.rows.length} of ${state.run.total} completed`

      : state.run.cancelled

        ? `stopped after ${state.run.rows.length} of ${state.run.total}`

        : `${state.run.rows.length} request${state.run.rows.length === 1 ? "" : "s"}`;

    const parts = [`${passed} passed`, `${failed} failed`];

    if (requestErrors) parts.push(`${requestErrors} request error${requestErrors === 1 ? "" : "s"}`);

    if (skipped) parts.push(`${skipped} skipped`);

    if (unknown) parts.push(`${unknown} not validated`);

    if (httpErrors) parts.push(`${httpErrors} HTTP error response${httpErrors === 1 ? "" : "s"}`);

    $("suite-summary").textContent = `${prefix} · ${parts.join(" · ")}`;

  }



  /* ───────────────────────── finding highlights ───────────────────────── */

  const SHELLS = [["bash", "bash"], ["powershell", "PowerShell"], ["cmd", "cmd"]];



  function activeShell() { return prefs.read("shell", "bash"); }



  /** Longest-first so a short marker cannot split a longer one. */

  function sortedHighlights(highlights) {

    return [...(highlights || [])]

      .filter((entry) => entry && entry.text)

      .sort((a, b) => b.text.length - a.text.length);

  }



  /**

   * Text with every highlight wrapped in a <mark>. Builds DOM nodes rather than

   * markup, so a value containing angle brackets stays inert.

   */

  function marked(text, highlights, { limit = 3 } = {}) {

    const fragment = document.createDocumentFragment();

    const source = String(text ?? "");

    const entries = sortedHighlights(highlights);

    if (!source || !entries.length) {

      fragment.append(document.createTextNode(source));

      return fragment;

    }

    // Claim ranges, longest marker first, skipping anything already covered.

    const claimed = [];

    for (const entry of entries) {

      let from = 0;

      let hits = 0;

      while (hits < limit) {

        const at = source.indexOf(entry.text, from);

        if (at < 0) break;

        const end = at + entry.text.length;

        if (!claimed.some((range) => at < range.end && end > range.start)) {

          claimed.push({ start: at, end, entry });

          hits++;

        }

        from = at + 1;

      }

    }

    if (!claimed.length) {

      fragment.append(document.createTextNode(source));

      return fragment;

    }

    claimed.sort((a, b) => a.start - b.start);

    let cursor = 0;

    for (const range of claimed) {

      if (range.start > cursor) fragment.append(document.createTextNode(source.slice(cursor, range.start)));

      const node = el("mark", `hl hl-${range.entry.kind || "weak"}`, source.slice(range.start, range.end));

      if (range.entry.note) {

        node.title = range.entry.note;

        node.tabIndex = 0;

        node.setAttribute("aria-label", `${source.slice(range.start, range.end)}: ${range.entry.note}`);

      }

      fragment.append(node);

      cursor = range.end;

    }

    if (cursor < source.length) fragment.append(document.createTextNode(source.slice(cursor)));

    return fragment;

  }



  function markedInto(node, text, highlights, options) {

    node.replaceChildren(marked(text, highlights, options));

    return node;

  }



  function highlightLegend(highlights) {

    const kinds = new Map();

    for (const entry of sortedHighlights(highlights)) {

      if (!kinds.has(entry.kind)) kinds.set(entry.kind, entry.note);

    }

    if (!kinds.size) return null;

    const labels = {

      weak: "the weakness", leak: "data that escaped",

      attacker: "what Namazu sent", proof: "what proves it",

    };

    const row = el("div", "hl-legend");

    for (const [kind] of kinds) {

      const chip = el("span", `hl hl-${kind}`, labels[kind] || kind);

      row.append(chip);

    }

    row.append(el("span", "dim", "Hover a marked value for the reason."));

    return row;

  }



  // Values worth marking wherever they turn up in a captured response body,

  // independently of which check produced the finding.

  const BODY_MARKERS = [

    [/"(?:password|passwd|pwd|password_hash|secret|client_secret|token|access_token|refresh_token|api_?key|private_key|ssn|social_security|card_number|cardnumber|cvv|cvc|pin)"\s*:\s*"[^"]{2,80}"/gi,

     "leak", "A secret-bearing field returned in the response body."],

    [/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g,

     "leak", "A value matching a payment card number."],

    [/-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,

     "leak", "A private key block."],

    [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g,

     "leak", "A JSON Web Token carried in the response."],

  ];



  function bodyHighlights(text) {

    const out = [];

    const seen = new Set();

    for (const [pattern, kind, note] of BODY_MARKERS) {

      for (const match of String(text || "").matchAll(pattern)) {

        if (seen.has(match[0])) continue;

        seen.add(match[0]);

        out.push({ text: match[0], kind, note });

        if (out.length >= 8) return out;

      }

    }

    return out;

  }



  /** A shell picker over a command set, with copy. */

  function commandBlock(commands, highlights) {

    if (!commands) return null;

    const wrap = el("div", "cmd-block");

    const bar = el("div", "cmd-bar");

    const pre = el("pre", "code-block wrap cmd-text");

    let shell = commands[activeShell()] ? activeShell() : Object.keys(commands)[0];



    const buttons = new Map();

    function show(name) {

      shell = name;

      prefs.write("shell", name);

      for (const [key, button] of buttons) button.classList.toggle("active", key === name);

      markedInto(pre, commands[name], highlights, { limit: 2 });

    }

    for (const [key, label] of SHELLS) {

      if (!commands[key]) continue;

      const button = el("button", "cmd-tab", label);

      button.type = "button";

      button.addEventListener("click", () => show(key));

      buttons.set(key, button);

      bar.append(button);

    }

    const copy = el("button", "link", "Copy");

    copy.type = "button";

    copy.addEventListener("click", () => copyText(commands[shell], "Command"));

    bar.append(copy);

    wrap.append(bar, pre);

    show(shell);

    return wrap;

  }



  /* ───────────────────────── request log ───────────────────────── */
  const MAX_LOG = 4000;

  function renderLog() {
    const rows = state.audit.log;
    $("log-count").textContent = rows.length;
    const query = $("log-search").value.trim().toLowerCase();
    const only = $("log-filter").value;
    const shown = rows.filter((entry) => {
      if (only === "errors" && !(entry.status >= 400 || entry.error)) return false;
      if (only === "mutating" && !entry.mutating) return false;
      if (only === "probes" && entry.label === "baseline") return false;
      if (!query) return true;
      return `${entry.method} ${entry.url} ${entry.label} ${entry.status} ${entry.identity} ${entry.endpoint}`
        .toLowerCase().includes(query);
    });

    const body = $("log-rows");
    body.replaceChildren();
    if (!shown.length) {
      const row = el("tr");
      const cell = el("td", "", rows.length ? "No request matches this filter."
        : "No requests yet. Run an audit to populate the log.");
      cell.colSpan = 7;
      cell.className = "log-empty";
      row.append(cell);
      body.append(row);
      $("log-detail").hidden = true;
      return;
    }
    for (const entry of shown) {
      const row = el("tr", `log-row${state.audit.logEntry?.key === entry.key ? " active" : ""}`);
      row.tabIndex = 0;
      row.append(el("td", "mono dim", entry.seqGlobal));
      const method = el("td");
      method.append(methodBadge(entry.method));
      row.append(method);
      const path = el("td", "mono log-url", shortUrl(entry.url));
      path.title = entry.url;
      row.append(path);
      row.append(el("td", "mono", entry.label));
      const status = el("td");
      status.append(entry.error ? pill("error", "fail")
        : pill(String(entry.status), statusKind(entry.status)));
      row.append(status);
      row.append(el("td", "mono num", humanBytes(entry.body_length || 0)));
      row.append(el("td", "mono num", Number.isFinite(entry.elapsed_ms) ? `${Math.round(entry.elapsed_ms)} ms` : "-"));
      const open = () => showLogEntry(entry);
      row.addEventListener("click", open);
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); }
      });
      body.append(row);
    }
    $("log-shown").textContent = shown.length === rows.length
      ? `${rows.length} requests`
      : `${shown.length} of ${rows.length} requests`;
  }

  function shortUrl(url) {
    try {
      const parsed = new URL(url);
      return parsed.pathname + parsed.search;
    } catch { return url; }
  }

  function showLogEntry(entry) {
    state.audit.logEntry = entry;
    const panel = $("log-detail");
    panel.replaceChildren();
    panel.hidden = false;

    const head = el("div", "log-detail-head");
    head.append(methodBadge(entry.method));
    head.append(el("span", "mono log-detail-url", entry.url));
    head.append(el("span", "chip", entry.identity));
    if (entry.mutating) head.append(el("span", "chip warn", "wrote data"));
    head.append(entry.error ? pill("error", "fail") : pill(`HTTP ${entry.status}`, statusKind(entry.status)));
    panel.append(head);
    panel.append(el("p", "hint pad", `${entry.endpoint} · ${entry.label}`));

    panel.append(el("p", "proof-label", "reproduce"));
    panel.append(commandBlock(entry.commands || { bash: entry.curl }, []));

    panel.append(el("p", "proof-label", "request headers"));
    const request = el("div", "header-table");
    for (const [name, value] of Object.entries(entry.request_headers || {})) {
      request.append(el("div", "hk", name), el("div", "hv", value));
    }
    panel.append(request);
    if (entry.request_body) {
      panel.append(el("p", "proof-label", "request body"));
      panel.append(el("pre", "code-block wrap", entry.request_body));
    }

    panel.append(el("p", "proof-label", "response headers"));
    const response = el("div", "header-table");
    for (const [name, value] of Object.entries(entry.response_headers || {})) {
      response.append(el("div", "hk", name), el("div", "hv", value));
    }
    if (!Object.keys(entry.response_headers || {}).length) {
      response.append(el("div", "hk", "-"), el("div", "hv", entry.error || "no response"));
    }
    panel.append(response);
    if (entry.body_excerpt) {
      panel.append(el("p", "proof-label", `response body · ${humanBytes(entry.body_length || 0)}`));
      panel.append(markedInto(el("pre", "code-block wrap"), entry.body_excerpt,
        bodyHighlights(entry.body_excerpt), { limit: 4 }));
    }
    renderLog();
  }

  function absorbLog(result, endpoint) {
    for (const entry of result.log || []) {
      if (state.audit.log.length >= MAX_LOG) {
        state.audit.logTruncated = true;
        return;
      }
      state.audit.log.push({
        ...entry,
        endpoint: entry.endpoint || endpoint,
        seqGlobal: state.audit.log.length + 1,
        key: `${state.audit.log.length + 1}`,
      });
    }
  }

  function exportLog() {
    if (!state.audit.log.length) return;
    const payload = {
      application: "Namazu",
      export: "audit-request-log",
      exported_at: new Date().toISOString(),
      api: { title: state.spec?.title, base_url: redactUrl($("base-url").value) },
      note: "Every request the audit sent, in order. Credential headers and credential-looking query "
          + "values are masked; response excerpts are not.",
      truncated: Boolean(state.audit.logTruncated),
      requests: state.audit.log.map(({ key, ...entry }) => entry),
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    const link = el("a");
    link.href = url;
    link.download = `namazu-log-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Request log exported.");
  }

  function wireLog() {
    $("log-search").addEventListener("input", renderLog);
    $("log-filter").addEventListener("change", renderLog);
    $("export-log").addEventListener("click", exportLog);
    $("audit-log").addEventListener("click", () => {
      state.audit.finding = null;
      activateSection("audit");
      showView("view-audit-log");
      renderLog();
    });
    $("log-back").addEventListener("click", () => {
      showView("view-audit-report");
      renderFindings();
    });
  }

  /* ───────────────────────── security audit ───────────────────────── */

  const identityKv = createKv("identity-b-rows", { noun: "Header", onChange: () => updateIdentityState() });



  function identityB() { return identityKv.safeRead(); }

  function updateIdentityState() {

    const count = Object.keys(identityB()).length;

    $("identity-b-state").textContent = count ? `${count} header${count === 1 ? "" : "s"}` : "not set";

  }

  function auditProfile() { return $("audit-profile").value; }

  function updateProfileNote() {

    const profile = auditProfile();

    const needsConsent = profile === "writes" && !$("allow-writes").checked;

    $("profile-note").textContent = PROFILE_NOTES[profile]

      + (needsConsent ? " Turn on Allow writes in the top bar to run them." : "");

    $("run-audit").disabled = state.busy || state.audit.running || !state.spec;

  }



  function auditScope() {

    const operations = state.spec?.operations || [];

    if (!$("audit-selected-only").checked) return operations;

    const chosen = operations.filter((op) => state.selected.has(op.id));

    return chosen.length ? chosen : operations;

  }



  function visibleFindings() {

    const query = $("finding-search").value.trim().toLowerCase();

    const severity = $("severity-filter").value;

    const confidence = $("confidence-filter").value;

    return state.audit.findings.filter((item) => {

      if (severity !== "all" && item.severity !== severity) return false;

      if (confidence === "confirmed" && item.confidence !== "confirmed") return false;

      if (confidence === "probable" && item.confidence === "possible") return false;

      if (!query) return true;

      return `${item.title} ${item.endpoint} ${item.owasp} ${item.id} ${item.parameter || ""}`

        .toLowerCase().includes(query);

    });

  }



  function severityTally(findings) {

    const tally = Object.fromEntries(SEVERITIES.map((name) => [name, 0]));

    for (const item of findings) tally[item.severity] = (tally[item.severity] || 0) + 1;

    return tally;

  }



  function renderSeverityBar() {

    const bar = $("audit-severity");

    const tally = severityTally(state.audit.findings);

    bar.replaceChildren();

    bar.hidden = state.audit.findings.length === 0;

    const active = $("severity-filter").value;

    for (const name of SEVERITIES) {

      if (!tally[name]) continue;

      const chip = el("button", `sev-chip${active !== "all" && active !== name ? " off" : ""}`);

      chip.type = "button";

      chip.dataset.sev = name;

      chip.append(el("span", "n", tally[name]), el("span", "", name));

      chip.setAttribute("aria-label", `${tally[name]} ${name} findings. Filter to this severity.`);

      chip.addEventListener("click", () => {

        $("severity-filter").value = active === name ? "all" : name;

        renderFindings();

      });

      bar.append(chip);

    }

  }



  function renderFindings() {

    const list = $("finding-list");

    list.replaceChildren();

    const all = state.audit.findings;

    $("audit-count").textContent = all.length;

    $("rail-findings").textContent = all.length;

    $("rail-findings").hidden = all.length === 0;

    $("audit-filters").hidden = all.length === 0;

    $("export-audit").disabled = all.length === 0;

    $("export-audit-top").disabled = all.length === 0;

    renderSeverityBar();



    if (!all.length) {

      list.append(el("p", "list-empty", state.audit.running

        ? "Running…" : "No findings yet. Run an audit to populate this list."));

      return;

    }

    const shown = visibleFindings();

    if (!shown.length) {

      list.append(el("p", "list-empty", "No finding matches this filter."));

      return;

    }

    for (const item of shown) {

      const row = el("button", `finding-row${state.audit.finding?.key === item.key ? " active" : ""}`);

      row.type = "button";

      row.dataset.sev = item.severity;

      row.disabled = state.busy;

      row.append(el("span", "edge"));

      const main = el("div", "finding-main");

      main.append(el("div", "finding-name", item.title));

      const meta = el("div", "finding-meta");

      meta.append(el("span", `conf ${item.confidence}`, item.confidence));

      meta.append(el("span", "ep", item.endpoint || item.owasp || ""));

      main.append(meta);

      row.append(main);

      row.title = `${item.severity} · ${item.confidence} · ${item.endpoint}`;

      row.addEventListener("click", () => showFinding(item));

      list.append(row);

    }

  }



  function evidenceTable(evidence, highlights) {

    const table = el("div", "ev-table");

    for (const [key, value] of Object.entries(evidence || {})) {

      if (value === null || value === undefined || value === "") continue;

      table.append(el("div", "ek", key.replace(/_/g, " ")));

      const text = typeof value === "object" ? JSON.stringify(value, null, 2) : String(value);

      table.append(markedInto(el("div", "ev"), text, highlights, { limit: 4 }));

    }

    return table.childElementCount ? table : null;

  }



  function proofBlock(step, exchange, highlights) {

    const block = el("section", "proof");

    const head = el("div", "proof-head");

    head.append(el("span", "step", `STEP ${step}`));

    head.append(methodBadge(exchange.method));

    head.append(el("span", "what", exchange.label));

    if (exchange.identity) head.append(el("span", "chip", exchange.identity));

    head.append(pill(exchange.error ? "failed" : `HTTP ${exchange.status}`,

      exchange.error ? "fail" : statusKind(exchange.status)));

    if (exchange.mutating) head.append(el("span", "chip warn", "wrote data"));

    block.append(head);



    const body = el("div", "proof-body");

    body.append(el("p", "proof-label", "reproduce"));

    body.append(commandBlock(exchange.commands || { bash: exchange.curl }, highlights));

    if (exchange.body_excerpt) {

      body.append(el("p", "proof-label", `response · ${humanBytes(exchange.body_length || 0)}`));

      const all = [...(highlights || []), ...bodyHighlights(exchange.body_excerpt)];

      body.append(markedInto(el("pre", "code-block wrap"), exchange.body_excerpt, all, { limit: 4 }));

    }

    block.append(body);

    return block;

  }



  // Sections a reader usually wants open, versus reference material that makes
  // the advisory long. A reader's own choice overrides these and persists.
  const SECTION_DEFAULTS = {
    "Issue detail": true, "Issue background": false, "How this was found": true,
    "Impact": true, "Limitations": true, "Classification": true, "Evidence": true,
    "Proof of concept": true, "Check it yourself": true, "Remediation": true,
    "Remediation background": false, "References": false,
  };

  function sectionOpen(key) {
    const stored = prefs.read(`sec:${key}`, null);
    if (stored === "1") return true;
    if (stored === "0") return false;
    return SECTION_DEFAULTS[key] !== false;
  }

  function reportCard(title, children, { collapsible = false, key = title } = {}) {
    const inner = el("div", "card-body");
    for (const child of children) {
      if (child) inner.append(child);
    }
    if (!collapsible) {
      const card = el("section", "card");
      const head = el("div", "card-head");
      head.append(el("h3", "", title));
      card.append(head, inner);
      return card;
    }
    const card = el("details", "card collapsible");
    card.open = sectionOpen(key);
    const head = el("summary", "card-head");
    head.append(icon("M9 6l6 6-6 6", "2.4"), el("h3", "", title));
    card.append(head, inner);
    card.addEventListener("toggle", () => prefs.write(`sec:${key}`, card.open ? "1" : "0"));
    return card;
  }

  function setAllSections(open) {
    for (const card of $("finding-body").querySelectorAll("details.card")) {
      card.open = open;
      const key = card.dataset.sectionKey || card.querySelector("h3")?.textContent || "";
      if (key) prefs.write(`sec:${key}`, open ? "1" : "0");
    }
    announce(open ? "All sections expanded." : "All sections collapsed.");
  }

  function showFinding(item) {
    state.audit.finding = item;
    activateSection("audit");
    showView("view-finding");
    $("finding-severity").textContent = `${item.severity} · ${item.confidence}`;
    $("finding-severity").className = "chip";
    $("finding-severity").dataset.sev = item.severity;
    $("finding-title").textContent = item.title;

    const body = $("finding-body");
    body.replaceChildren();
    const card = (title, children, key) =>
      body.append(reportCard(title, children, { collapsible: true, key: key || title }));

    // Issue detail: what is true about this target.
    const observed = [markedInto(el("p", "prose"), item.detail, item.highlights)];
    const legend = highlightLegend(item.highlights);
    if (legend) observed.push(legend);
    card("Issue detail", observed);

    // Issue background: how this class of weakness works, target independent.
    if (item.background) {
      card("Issue background", [markedInto(el("div", "prose prewrap"), item.background, item.highlights)]);
    }
    if (item.method) card("How this was found", [el("p", "method-note", item.method)]);
    if (item.impact) {
      card("Impact", [markedInto(el("div", "prose prewrap"), item.impact, item.highlights)]);
    }
    if (item.limitations) {
      card("Limitations", [el("div", "prose prewrap caution", item.limitations)]);
    }

    const facts = el("dl", "facts");
    for (const [label, value] of [
      ["Endpoint", item.endpoint], ["Parameter", item.parameter],
      ["Classification", item.owasp], ["Weakness", item.cwe], ["Check", item.id],
      ["Confidence", item.confidence], ["Changed data", item.mutating ? "yes" : "no"],
    ]) {
      if (!value) continue;
      const row = el("div");
      row.append(el("dt", "", label), el("dd", "", value));
      facts.append(row);
    }
    card("Classification", [facts]);

    const table = evidenceTable(item.evidence, item.highlights);
    if (table) card("Evidence", [table]);

    if (item.proof?.length) {
      const blocks = item.proof.map((exchange, index) => proofBlock(index + 1, exchange, item.highlights));
      card(`Proof of concept · ${item.proof.length} request${item.proof.length === 1 ? "" : "s"}`,
        blocks, "Proof of concept");
    }
    if (item.commands && !item.proof?.length) {
      card("Check it yourself", [
        el("p", "hint", "This finding comes from the contract, so there is no request to replay. "
          + "These commands print the same part of the document."),
        commandBlock(item.commands, item.highlights),
      ]);
    }
    if (item.remediation) {
      card("Remediation", [el("div", "prose prewrap", item.remediation)]);
    }
    if (item.remediation_background) {
      card("Remediation background", [el("div", "prose prewrap", item.remediation_background)]);
    }
    if (item.references?.length) {
      const list = el("div", "ref-list");
      for (const reference of item.references) {
        const link = el("a", "", reference.title);
        link.href = reference.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        list.append(link);
      }
      card("References", [list]);
    }
    renderFindings();
    $("finding-title").focus();
    announce(`Showing finding: ${item.title}.`);
  }

  function renderAuditReport() {

    const body = $("audit-report-body");

    body.replaceChildren();

    const audit = state.audit;

    if (!audit.total && !audit.findings.length) {

      body.append(el("p", "pane-empty",

        "No audit has run yet. Choose a profile on the left and select Run audit."));

      return;

    }

    const tally = severityTally(audit.findings);

    const grid = el("div", "tally");

    for (const name of SEVERITIES) {

      const cell = el("div", "tally-cell");

      cell.dataset.sev = name;

      cell.append(el("div", "v", tally[name] || 0), el("div", "k", name));

      grid.append(cell);

    }

    body.append(reportCard("Severity", [grid]));



    const owasp = {};

    for (const item of audit.findings) if (item.owasp) owasp[item.owasp] = (owasp[item.owasp] || 0) + 1;

    const entries = Object.entries(owasp).sort((a, b) => b[1] - a[1]);

    if (entries.length) {

      const max = entries[0][1];

      const rows = entries.map(([name, count]) => {

        const row = el("div", "owasp-row");

        const bar = el("span", "bar");

        bar.style.width = `${Math.max(3, Math.round((count / max) * 90))}px`;

        row.append(bar, el("span", "label", name), el("span", "n", count));

        return row;

      });

      body.append(reportCard("Classification", rows));

    }



    const confirmed = audit.findings.filter((item) => item.confidence === "confirmed").length;

    const coverage = el("dl", "facts");

    for (const [label, value] of [

      ["Profile", `${auditProfile()}: ${PROFILE_NOTES[auditProfile()]}`],

      ["Endpoints audited", `${audit.done} of ${audit.total}`],

      ["Requests sent", String(audit.requests)],

      ["Findings", `${audit.findings.length} (${confirmed} confirmed)`],

      ["Second identity", Object.keys(identityB()).length

        ? "supplied" : "not supplied, so authorization findings stay unconfirmed"],

      ["Surface sweep", audit.discovery

        ? `${(audit.discovery.shadow || []).length} undocumented, ${(audit.discovery.exposed || []).length} exposed`

        : "not run"],

    ]) {

      const row = el("div");

      row.append(el("dt", "", label), el("dd", "", value));

      coverage.append(row);

    }

    body.append(reportCard("Coverage", [coverage]));



    if (audit.notes.length) {

      const list = el("ul", "note-list");

      for (const note of [...new Set(audit.notes)]) list.append(el("li", "", note));

      body.append(reportCard("What did not run", [list]));

    }

  }



  function auditProgress() {

    const audit = state.audit;

    const percent = audit.total ? Math.round((audit.done / audit.total) * 100) : 0;

    $("audit-progress").hidden = !audit.total;

    $("audit-progress").setAttribute("aria-valuenow", String(percent));

    $("audit-progress").firstElementChild.style.width = `${percent}%`;

    $("audit-foot").textContent = audit.running

      ? `${audit.done}/${audit.total} · ${audit.requests} requests`

      : audit.total ? `${audit.findings.length} findings · ${audit.requests} requests` : "Not run";

    $("audit-state").hidden = !audit.total;

    $("audit-state").textContent = audit.running ? "running" : audit.cancelled ? "stopped" : "finished";

    $("audit-state").className = `chip${audit.running || audit.cancelled ? " warn" : ""}`;

  }



  function absorb(result, label) {

    state.audit.requests += result.requests_sent || 0;

    for (const note of result.notes || []) state.audit.notes.push(`${label}: ${note}`);

    for (const item of result.findings || []) {

      // Host-scoped findings (TLS, headers, CORS middleware) describe the whole

      // origin, so they must not reappear once per endpoint audited.

      const key = item.scope === "host"

        ? `${item.id}|${item.parameter || ""}`

        : `${item.id}|${item.endpoint}|${item.parameter || ""}`;

      if (state.audit.findings.some((existing) => existing.key === key)) continue;

      state.audit.findings.push({ ...item, key });

    }

    const order = ["confirmed", "probable", "possible"];

    state.audit.findings.sort((a, b) =>

      SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)

      || order.indexOf(a.confidence) - order.indexOf(b.confidence)

      || a.title.localeCompare(b.title));

  }



  async function runAudit() {

    if (state.busy || state.audit.running || !state.spec) return;

    message("work-error", "");

    const profile = auditProfile();

    if (profile === "writes" && !$("allow-writes").checked) {

      activateSection("audit");

      toast("Turn on Allow writes in the top bar before running write probes.");

      return;

    }

    let connection;

    try { connection = connectionPayload(); }

    catch (error) { toast(errorText(error)); return; }



    const operations = auditScope();

    const payload = {

      spec: state.spec,

      base_url: connection.base_url,

      profile,

      identities: { primary: connection.headers, secondary: identityB() },

      allow_mutating: connection.allow_mutating,

      verify_tls: connection.verify_tls,

      timeout: connection.timeout,

    };



    state.audit = {
      findings: [], running: true, cancelled: false, done: 0, total: operations.length,
      requests: 0, notes: [], discovery: null, finding: null,
      log: [], logEntry: null, logTruncated: false,
      startedAt: new Date().toISOString(),
    };

    activateSection("audit");

    showView("view-audit-report");

    $("cancel-audit").hidden = false;

    $("cancel-audit").disabled = false;

    $("cancel-audit").textContent = "Stop after current";

    setBusy(true);

    $("run-audit").disabled = true;

    renderFindings();

    renderAuditReport();
    renderLog();

    auditProgress();



    try {

      if ($("audit-inventory").checked) {

        $("session-state").textContent = "Auditing: surface sweep";

        try {

          const sweep = await api("/api/audit/inventory", { ...payload, profile: "readonly" });

          state.audit.discovery = sweep.discovery;

          absorb(sweep, "Surface sweep");
          absorbLog(sweep, "surface sweep");

        } catch (error) {

          state.audit.notes.push(`Surface sweep: ${errorText(error)}`);

        }

        renderFindings();

        renderAuditReport();

        auditProgress();

      }

      for (const op of operations) {

        if (state.audit.cancelled) break;

        $("session-state").textContent = `Auditing ${state.audit.done + 1} of ${operations.length}`;

        try {

          const result = await api("/api/audit", { ...payload, operation_id: op.id });

          absorb(result, `${op.method} ${op.path}`);
          absorbLog(result, `${op.method} ${op.path}`);

        } catch (error) {

          state.audit.notes.push(`${op.method} ${op.path}: ${errorText(error)}`);

        }

        state.audit.done++;

        renderFindings();

        renderAuditReport();

        auditProgress();

        announce(`Audited ${state.audit.done} of ${operations.length}.`);

      }

    } finally {

      state.audit.running = false;

      $("cancel-audit").hidden = true;

      setBusy(false);

      updateProfileNote();

      renderFindings();

      renderAuditReport();

      auditProgress();

      announce(state.audit.cancelled

        ? `Audit stopped with ${state.audit.findings.length} findings.`

        : `Audit finished with ${state.audit.findings.length} findings.`);

    }

  }



  function exportAudit() {

    if (!state.audit.findings.length) return;

    const payload = {

      application: "Namazu",

      export: "security-audit",

      exported_at: new Date().toISOString(),

      started_at: state.audit.startedAt,

      api: { title: state.spec?.title, version: state.spec?.version,

             base_url: redactUrl($("base-url").value) },

      scope: {

        profile: auditProfile(),

        endpoints_audited: state.audit.done,

        endpoints_in_scope: state.audit.total,

        requests_sent: state.audit.requests,

        surface_sweep: state.audit.discovery,

        second_identity: Object.keys(identityB()).length > 0,

      },

      summary: { total: state.audit.findings.length, severity: severityTally(state.audit.findings) },

      notes: [...new Set(state.audit.notes)],

      findings: state.audit.findings.map(({ key, ...item }) => item),

      note: "Proof-of-concept requests have credential headers and query values masked. Response "

          + "excerpts may still contain sensitive data; review before sharing.",

    };

    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));

    const link = el("a");

    link.href = url;

    link.download = `namazu-audit-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;

    document.body.append(link);

    link.click();

    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);

    toast("Audit exported. Review it before sharing.");

    announce("Audit exported. Review request and response content before sharing.");

  }



  function wireAudit() {

    $("audit-profile").addEventListener("change", () => {

      prefs.write("audit-profile", auditProfile());

      updateProfileNote();

    });

    $("add-identity-b").addEventListener("click", () => { identityKv.addRow(); identityKv.focusLast(); });

    $("run-audit").addEventListener("click", runAudit);

    $("cancel-audit").addEventListener("click", () => {

      state.audit.cancelled = true;

      $("cancel-audit").disabled = true;

      $("cancel-audit").textContent = "Stopping…";

      announce("The audit will stop once the current endpoint finishes.");

    });

    $("finding-search").addEventListener("input", renderFindings);

    $("severity-filter").addEventListener("change", renderFindings);

    $("confidence-filter").addEventListener("change", renderFindings);

    $("audit-report").addEventListener("click", () => {

      state.audit.finding = null;

      activateSection("audit");

      showView("view-audit-report");

      renderFindings();

    });

    $("expand-all").addEventListener("click", () => setAllSections(true));
    $("collapse-all").addEventListener("click", () => setAllSections(false));
    $("finding-back").addEventListener("click", () => {

      state.audit.finding = null;

      showView("view-audit-report");

      renderFindings();

    });

    for (const id of ["export-audit", "export-audit-top"]) {

      $(id).addEventListener("click", exportAudit);

    }

  }



  /* ───────────────────────── OAuth 2 ───────────────────────── */

  const oauthState = { token: null, pollTimer: 0, window: null };



  function oauthGrant() { return $("oauth-grant").value; }



  function oauthVisible() {

    const isOauth = $("auth-mode").value === "oauth2";

    const grant = oauthGrant();

    $("auth-oauth-top").hidden = !isOauth;

    $("auth-oauth").hidden = !isOauth;

    $("oauth-authorize-field").hidden = grant !== "authorization_code";

    $("oauth-password-fields").hidden = grant !== "password";

    $("oauth-refresh-field").hidden = grant !== "refresh_token";

    $("oauth-probe").hidden = grant !== "authorization_code";

    $("oauth-redirect-note").textContent = grant === "authorization_code"

      ? `Register ${location.origin}/oauth/callback as a redirect URI for this client. Namazu opens the `

        + "authorization page in a new tab and collects the code when the browser comes back."

      : "This grant runs entirely from the Namazu server; no browser redirect is involved.";

  }



  function oauthConfig() {

    return {

      grant: oauthGrant(),

      issuer: $("oauth-issuer").value.trim() || null,

      authorization_endpoint: $("oauth-authorize-url").value.trim() || null,

      token_endpoint: $("oauth-token-url").value.trim() || null,

      client_id: $("oauth-client-id").value.trim(),

      client_secret: $("oauth-client-secret").value,

      scope: $("oauth-scope").value.trim(),

      audience: $("oauth-audience").value.trim(),

      username: $("oauth-username").value,

      password: $("oauth-password").value,

      refresh_token: $("oauth-refresh-token").value,

      auth_style: $("oauth-client-auth").value,

      use_pkce: $("oauth-pkce").checked,

      verify_tls: $("verify-tls").checked,

      timeout: Number($("request-timeout").value) || 15,

    };

  }



  function oauthStatus(text, kind = "unknown") {

    $("oauth-status").textContent = text || "";

    $("oauth-status").className = `verdict${kind === "ok" ? "" : kind === "bad" ? " invalid" : " unknown"}`;

    $("oauth-status").hidden = !text;

  }



  function renderTokenFacts(token) {

    const list = $("oauth-token-list");

    list.replaceChildren();

    const rows = [

      ["Type", token.token_type],

      ["Expires in", token.expires_in ? `${token.expires_in}s` : "not stated"],

      ["Scope", token.scope || "not stated"],

      ["Refresh token", token.refresh_token ? "issued" : "none"],

    ];

    if (token.jwt) {

      rows.push(["Algorithm", token.jwt.algorithm], ["Subject", token.jwt.subject || "-"],

        ["Issuer", token.jwt.issuer || "-"], ["Audience", stringify(token.jwt.audience ?? "-")]);

      if (token.jwt.privilege_claims && Object.keys(token.jwt.privilege_claims).length) {

        rows.push(["Privilege claims", stringify(token.jwt.privilege_claims)]);

      }

      if (token.jwt.weaknesses?.length) {

        rows.push(["Token weaknesses", token.jwt.weaknesses.map((w) => w.id).join(", ")]);

      }

    }

    for (const [label, value] of rows) {

      if (value === undefined || value === null || value === "") continue;

      const row = el("div");

      row.append(el("dt", "", label), el("dd", "", String(value)));

      list.append(row);

    }

    $("oauth-token-facts").hidden = false;

  }



  function applyToken(token, target) {

    oauthState.token = token;

    if (target === "secondary") {

      identityKv.setAll({ [token.header_name]: token.header_value });

      activateSection("audit");

      toast("Token assigned to the second identity.");

    } else {

      $("auth-mode").value = "oauth2";

      headerKv.addRow(token.header_name, token.header_value);

      updateHeaderCount();

      toast("Token applied to this session's requests.");

    }

    renderTokenFacts(token);

    markRequestDirty();

  }



  async function getToken(target = "primary") {

    const config = oauthConfig();

    if (config.grant === "authorization_code") return authorizationCode(target);

    oauthStatus("Requesting a token…");

    try {

      const token = await api("/api/oauth/token", config);

      applyToken(token, target);

      oauthStatus(`Token received. ${token.expires_in ? `Valid for ${token.expires_in}s.` : ""}`, "ok");

    } catch (error) {

      oauthStatus(errorText(error), "bad");

    }

  }



  async function authorizationCode(target) {

    clearInterval(oauthState.pollTimer);

    oauthStatus("Starting the authorization request…");

    let started;

    try {

      started = await api("/api/oauth/authorize", oauthConfig());

    } catch (error) {

      oauthStatus(errorText(error), "bad");

      return;

    }

    oauthState.window = window.open(started.authorize_url, "namazu-oauth", "width=620,height=760");

    oauthStatus(oauthState.window

      ? "Complete the sign-in in the authorization window. Namazu is waiting for the redirect."

      : "The popup was blocked. Open the authorization URL manually, then return here.");

    if (!oauthState.window) {

      const link = el("a", "", "Open the authorization page");

      link.href = started.authorize_url;

      link.target = "_blank";

      link.rel = "noopener";

      $("oauth-status").append(" ", link);

    }



    const deadline = Date.now() + 5 * 60 * 1000;

    oauthState.pollTimer = setInterval(async () => {

      if (Date.now() > deadline) {

        clearInterval(oauthState.pollTimer);

        oauthStatus("The authorization request timed out. Start it again.", "bad");

        return;

      }

      let result;

      try {

        result = await api("/api/oauth/collect", { session: started.session });

      } catch { return; }

      if (result.status === "pending") return;

      clearInterval(oauthState.pollTimer);

      try { oauthState.window?.close(); } catch { /* the tab may already be gone */ }

      if (result.status === "complete") {

        applyToken(result.token, target);

        oauthStatus("Authorization complete. The token is now in use.", "ok");

      } else if (result.status === "error") {

        oauthStatus(result.error || "The authorization failed.", "bad");

      } else {

        oauthStatus("The authorization session expired. Start it again.", "bad");

      }

    }, 1500);

  }



  async function discoverOauth() {

    oauthStatus("Reading the authorization server metadata…");

    try {

      const result = await api("/api/oauth/discover", { ...oauthConfig(), spec: state.spec });

      const meta = result.metadata;

      if (meta) {

        if (meta.authorization_endpoint) $("oauth-authorize-url").value = meta.authorization_endpoint;

        if (meta.token_endpoint) $("oauth-token-url").value = meta.token_endpoint;

        const pkce = (meta.code_challenge_methods_supported || []).join(", ") || "not advertised";

        $("oauth-discovery-note").textContent =

          `${meta.issuer || "Server"} · grants: ${(meta.grant_types_supported || []).join(", ") || "not stated"}`

          + ` · PKCE: ${pkce}`;

        oauthStatus("Endpoints filled in from the server's metadata.", "ok");

      } else {

        oauthStatus("No metadata document was found at that issuer.", "bad");

      }

    } catch (error) {

      oauthStatus(errorText(error), "bad");

    }

  }



  function fillOauthPresets() {

    const select = $("oauth-preset");

    select.replaceChildren(el("option", "", "Choose a documented scheme…"));

    select.firstElementChild.value = "";

    const schemes = state.spec?.security_schemes || {};

    for (const [name, scheme] of Object.entries(schemes)) {

      if (String(scheme?.type || "").toLowerCase() !== "oauth2") continue;

      for (const [flowName, flow] of Object.entries(scheme.flows || {})) {

        const option = el("option", "", `${name} · ${flowName}`);

        option.value = JSON.stringify({

          grant: { authorizationCode: "authorization_code", clientCredentials: "client_credentials",

                   password: "password", implicit: "authorization_code" }[flowName] || "authorization_code",

          authorization_endpoint: flow.authorizationUrl || "",

          token_endpoint: flow.tokenUrl || "",

          scope: Object.keys(flow.scopes || {}).join(" "),

          implicit: flowName === "implicit",

        });

        select.append(option);

      }

    }

    $("auth-oauth-top").querySelector("#oauth-preset").disabled = select.childElementCount < 2;

  }



  function applyPreset() {

    const raw = $("oauth-preset").value;

    if (!raw) return;

    const preset = JSON.parse(raw);

    $("oauth-grant").value = preset.grant;

    if (preset.authorization_endpoint) $("oauth-authorize-url").value = preset.authorization_endpoint;

    if (preset.token_endpoint) $("oauth-token-url").value = preset.token_endpoint;

    if (preset.scope) $("oauth-scope").value = preset.scope;

    oauthVisible();

    oauthStatus(preset.implicit

      ? "This scheme documents the implicit flow. Namazu will use authorization code + PKCE instead. "

        + "If it works, the implicit grant can be retired."

      : "", preset.implicit ? "unknown" : "unknown");

    if (!preset.implicit) oauthStatus("");

  }



  async function probeAuthorizationServer() {

    oauthStatus("Testing the authorization server…");

    try {

      const result = await api("/api/oauth/probe", oauthConfig());

      const findings = result.findings || [];

      if (!findings.length) {

        oauthStatus("The authorization server rejected every probe. No findings.", "ok");

        return;

      }

      for (const item of findings) {

        const key = `${item.id}|${item.endpoint}|${item.parameter || ""}`;

        if (!state.audit.findings.some((existing) => existing.key === key)) {

          state.audit.findings.push({ ...item, key });

        }

      }

      renderFindings();

      renderAuditReport();

      oauthStatus(`${findings.length} authorization-server finding(s) added to the audit.`, "bad");

      activateSection("audit");

    } catch (error) {

      oauthStatus(errorText(error), "bad");

    }

  }



  function wireOauth() {

    $("oauth-grant").addEventListener("change", oauthVisible);

    $("oauth-preset").addEventListener("change", applyPreset);

    $("oauth-discover").addEventListener("click", discoverOauth);

    $("oauth-get-token").addEventListener("click", () => getToken("primary"));

    $("oauth-use-b").addEventListener("click", () => getToken("secondary"));

    $("oauth-probe").addEventListener("click", probeAuthorizationServer);

    oauthVisible();

  }



  /* ───────────────────────── export ───────────────────────── */

  function redactHeaders(headers) {

    return Object.fromEntries(Object.entries(headers || {}).map(([key, value]) =>

      [key, /authorization|cookie|token|api.?key|secret/i.test(key) ? "[REDACTED]" : value]));

  }

  function redactUrl(value) {

    try {

      const url = new URL(value);

      url.username = "";

      url.password = "";

      for (const name of [...url.searchParams.keys()]) {

        if (/token|api.?key|secret|password|authorization/i.test(name)) url.searchParams.set(name, "[REDACTED]");

      }

      return url.toString();

    } catch { return value; }

  }

  function exportEntries(entries, kind) {

    if (!entries.length) return;

    const copy = JSON.parse(JSON.stringify(entries));

    for (const entry of copy) {

      if (entry.result?.request) {

        entry.result.request.headers = redactHeaders(entry.result.request.headers);

        entry.result.request.url = redactUrl(entry.result.request.url);

      }

      if (entry.result?.response) entry.result.response.headers = redactHeaders(entry.result.response.headers);

    }

    const payload = {

      application: "Namazu",

      export: kind,

      exported_at: new Date().toISOString(),

      api: { title: state.spec?.title, version: state.spec?.version, base_url: redactUrl($("base-url").value) },

      note: "Recognized credential headers and query parameters are redacted. Request and response bodies may contain sensitive data; review before sharing.",

      results: copy,

    };

    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));

    const link = el("a");

    link.href = url;

    link.download = `namazu-${kind}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;

    document.body.append(link);

    link.click();

    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);

    toast("Export written. Review it before sharing.");

    announce("Results exported. Review request and response content before sharing.");

  }



  /* ───────────────────────── splitters ───────────────────────── */

  function dragHandle(handle, onMove, vertical = () => false) {

    handle.addEventListener("pointerdown", (event) => {

      if (event.button !== 0) return;

      event.preventDefault();

      handle.setPointerCapture(event.pointerId);

      document.body.classList.add(vertical() ? "resizing-v" : "resizing");

      const move = (moveEvent) => onMove(moveEvent);

      const stop = () => {

        handle.removeEventListener("pointermove", move);

        handle.removeEventListener("pointerup", stop);

        handle.removeEventListener("pointercancel", stop);

        document.body.classList.remove("resizing", "resizing-v");

      };

      handle.addEventListener("pointermove", move);

      handle.addEventListener("pointerup", stop);

      handle.addEventListener("pointercancel", stop);

    });

  }

  function wireSplitters() {

    const panelSplitter = $("panel-splitter");

    dragHandle(panelSplitter, (event) => {

      const railWidth = document.querySelector(".rail").getBoundingClientRect().width;

      setPanelWidth(event.clientX - $("shell").getBoundingClientRect().left - railWidth, true);

    });

    panelSplitter.addEventListener("keydown", (event) => {

      const step = event.key === "ArrowLeft" ? -16 : event.key === "ArrowRight" ? 16 : 0;

      if (!step) return;

      event.preventDefault();

      setPanelWidth($("list-panel").getBoundingClientRect().width + step, true);

    });



    const opSplitter = $("op-splitter");

    const stacked = () => $("op-split").classList.contains("stacked");

    dragHandle(opSplitter, (event) => {

      const rect = $("op-split").getBoundingClientRect();

      const ratio = stacked()

        ? (event.clientY - rect.top) / rect.height

        : (event.clientX - rect.left) / rect.width;

      setRequestBasis(ratio * 100, true);

    }, stacked);

    opSplitter.addEventListener("keydown", (event) => {

      const keys = stacked() ? ["ArrowUp", "ArrowDown"] : ["ArrowLeft", "ArrowRight"];

      if (!keys.includes(event.key)) return;

      event.preventDefault();

      const rect = $("op-split").getBoundingClientRect();

      const size = stacked() ? rect.height : rect.width;

      const current = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--req-basis")) || 50;

      setRequestBasis(current + (event.key === keys[0] ? -1 : 1) * (2400 / size), true);

    });

  }



  /* ───────────────────────── wiring ───────────────────────── */

  function wireEvents() {

    for (const button of document.querySelectorAll(".rail-btn")) {

      button.addEventListener("click", () => activateSection(button.dataset.section));

    }

    $("context-button").addEventListener("click", () => activateSection("source"));

    $("theme-toggle").addEventListener("click", () => {

      const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";

      setTheme(theme, true);

      announce(`${theme === "dark" ? "Dark" : "Light"} mode enabled.`);

    });

    $("theme-select").addEventListener("change", () => setTheme($("theme-select").value, true));

    $("layout-toggle").addEventListener("click", () => setLayout($("op-split").classList.contains("stacked") ? "cols" : "rows", true));

    $("notice-close").addEventListener("click", () => { $("notice").hidden = true; });



    $("import-form").addEventListener("submit", (event) => { event.preventDefault(); importSpec(); });

    $("sample-import").addEventListener("click", () => importSpec(true));

    $("empty-import").addEventListener("click", () => { activateSection("source"); $("spec-url").focus(); });

    $("empty-sample").addEventListener("click", () => importSpec(true));

    $("source-back").addEventListener("click", () => activateSection("endpoints"));

    for (const button of document.querySelectorAll("[data-import-mode]")) {

      button.addEventListener("click", () => importMode(button.dataset.importMode));

    }

    $("add-import-header").addEventListener("click", () => { importKv.addRow(); importKv.focusLast(); });

    $("spec-file").addEventListener("change", async (event) => {

      const file = event.target.files[0];

      if (!file) return;

      if (file.size > 8 * 1024 * 1024) { message("import-error", "Choose a specification smaller than 8 MB."); return; }

      try {

        $("raw-spec").value = await file.text();

        importMode("raw");

        announce(`Loaded ${file.name}. Choose Import to continue.`);

      } catch {

        message("import-error", "The file could not be read. Try choosing it again.");

      }

    });



    $("endpoint-search").addEventListener("input", renderEndpoints);

    $("method-filter").addEventListener("change", renderEndpoints);

    $("group-mode").addEventListener("change", () => { prefs.write("group-mode", $("group-mode").value); renderEndpoints(); });

    $("schema-search").addEventListener("input", renderSchemas);

    $("select-visible").addEventListener("click", () => {

      for (const op of visibleOperations()) state.selected.add(op.id);

      renderEndpoints();

      renderQueue();

    });

    for (const id of ["clear-selection", "clear-queue"]) {

      $(id).addEventListener("click", () => { state.selected.clear(); renderEndpoints(); renderQueue(); });

    }



    $("base-url").addEventListener("input", () => { state.baseOverride = true; markRequestDirty(); updateStatusBar(); });

    $("base-reset").addEventListener("click", () => {

      state.baseOverride = false;

      $("base-url").value = state.operation?.servers?.[0] || state.spec?.base_url || "";

      markRequestDirty();

      updateStatusBar();

      announce("Base URL restored from the contract.");

    });



    for (const button of document.querySelectorAll("[data-req-tab]")) {

      button.addEventListener("click", () => requestTab(button.dataset.reqTab));

    }

    for (const button of document.querySelectorAll("[data-response-tab]")) {

      button.addEventListener("click", () => responseTab(button.dataset.responseTab));

    }



    $("add-header").addEventListener("click", () => { headerKv.addRow(); headerKv.focusLast(); });

    $("bulk-headers").addEventListener("click", () => {

      $("header-bulk").value = headerKv.text();

      $("header-bulk-wrap").hidden = false;

      $("header-bulk").focus();

    });

    $("cancel-bulk").addEventListener("click", () => { $("header-bulk-wrap").hidden = true; $("bulk-headers").focus(); });

    $("apply-bulk").addEventListener("click", () => {

      try {

        headerKv.fromText($("header-bulk").value);

        $("header-bulk-wrap").hidden = true;

        $("bulk-headers").focus();

        toast("Headers updated.");

      } catch (error) { toast(errorText(error)); }

    });

    $("auth-mode").addEventListener("change", renderAuthState);

    for (const id of ["bearer-token", "basic-user", "basic-pass", "apikey-name", "apikey-value"]) {

      $(id).addEventListener("input", renderAuthState);

    }



    $("regenerate").addEventListener("click", () => prepareRequest(true));

    $("prepare-request").addEventListener("click", () => prepareRequest(false));

    $("send-request").addEventListener("click", sendRequest);

    $("content-type").addEventListener("change", () => prepareRequest(true));

    $("request-body").addEventListener("input", () => { markRequestDirty(); updateBodyMeta(); });

    $("parameter-fields").addEventListener("input", markRequestDirty);

    $("format-body").addEventListener("click", () => {

      const raw = $("request-body").value;

      if (!raw.trim()) return;

      try {

        $("request-body").value = JSON.stringify(JSON.parse(raw), null, 2);

        updateBodyMeta();

        toast("Body formatted.");

      } catch { toast("The body is not valid JSON, so it was left unchanged."); }

    });



    $("copy-url").addEventListener("click", () => copyText($("prepared-url").textContent, "Prepared URL"));

    $("copy-response").addEventListener("click", () => copyText($("response-body").textContent, "Response body"));

    $("copy-operation").addEventListener("click", () => copyText($("operation-schema").textContent, "Operation definition"));

    $("copy-schema").addEventListener("click", () => copyText($("schema-content").textContent, "Schema"));

    $("wrap-toggle").addEventListener("click", () => setWrap($("wrap-toggle").getAttribute("aria-pressed") !== "true", true));



    $("run-suite").addEventListener("click", runSuite);

    $("cancel-suite").addEventListener("click", () => {

      state.run.cancelled = true;

      $("cancel-suite").disabled = true;

      $("cancel-suite").textContent = "Stopping…";

      announce("The run will stop once the current request finishes.");

    });

    $("download-results").addEventListener("click", () => exportEntries(state.run.rows, "run"));

    $("export-history").addEventListener("click", () => exportEntries(state.history, "history"));

    $("clear-history").addEventListener("click", () => {

      state.history = [];

      state.savedEntry = null;

      renderHistory();

      announce("History cleared.");

    });

    $("history-limit").addEventListener("change", () => {

      prefs.write("history-limit", $("history-limit").value);

      const limit = Number($("history-limit").value) || 100;

      if (state.history.length > limit) state.history.length = limit;

      renderHistory();

    });

    $("auto-prepare").addEventListener("change", () => prefs.write("auto-prepare", $("auto-prepare").checked ? "1" : "0"));

    $("allow-writes").addEventListener("change", () => syncWrites());

    $("allow-writes-mirror").addEventListener("change", () => syncWrites("mirror"));

    $("verify-tls").addEventListener("change", updateStatusBar);

    $("request-timeout").addEventListener("input", updateStatusBar);

    $("reset-layout").addEventListener("click", () => {

      for (const key of ["panel-w", "req-basis", "layout", "wrap"]) prefs.clear(key);

      setPanelWidth(290);

      setRequestBasis(50);

      setLayout("cols");

      setWrap(true);

      toast("Layout reset.");

    });



    for (const list of document.querySelectorAll("[role=tablist]")) {

      list.addEventListener("keydown", (event) => {

        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;

        const tabs = [...list.querySelectorAll("[role=tab]")];

        const index = tabs.indexOf(document.activeElement);

        if (index < 0) return;

        event.preventDefault();

        const next = event.key === "Home" ? 0

          : event.key === "End" ? tabs.length - 1

            : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;

        tabs[next].focus();

        tabs[next].click();

      });

    }



    document.addEventListener("keydown", (event) => {

      const modifier = event.ctrlKey || event.metaKey;

      if (modifier && event.key === "Enter") {

        if (state.operation && !$("view-operation").hidden) { event.preventDefault(); sendRequest(); }

        return;

      }

      if (modifier && event.key.toLowerCase() === "k") {

        event.preventDefault();

        activateSection("endpoints");

        $("endpoint-search").focus();

        $("endpoint-search").select();

        return;

      }

      if (modifier && event.key.toLowerCase() === "g") {

        if (!state.operation || $("view-operation").hidden) return;

        event.preventDefault();

        prepareRequest(true);

        return;

      }

      if (event.key === "Escape") {

        if (!$("header-bulk-wrap").hidden) { $("header-bulk-wrap").hidden = true; $("bulk-headers").focus(); return; }

        if (document.activeElement === $("endpoint-search") || document.activeElement === $("schema-search")) document.activeElement.blur();

      }

    });

  }



  /* ───────────────────────── start ───────────────────────── */

  function start() {

    setTheme(prefs.read("theme", "dark"));

    setLayout(prefs.read("layout", "cols"));

    setPanelWidth(Number(prefs.read("panel-w", 290)) || 290);

    setRequestBasis(Number(prefs.read("req-basis", 50)) || 50);

    setWrap(prefs.read("wrap", "1") !== "0");

    $("auto-prepare").checked = prefs.read("auto-prepare", "1") !== "0";

    $("history-limit").value = prefs.read("history-limit", "100");

    $("group-mode").value = prefs.read("group-mode", "tag");

    $("audit-profile").value = prefs.read("audit-profile", "readonly");

    identityKv.setAll({});

    updateIdentityState();

    updateProfileNote();

    $("about-line").textContent = "Namazu · local workbench · no account, no database";

    importKv.setAll({});

    headerKv.setAll({});

    renderAuthState();

    updateHeaderCount();

    requestTab("params");

    responseTab("body");

    renderEndpoints();

    renderSchemas();

    renderHistory();

    renderRun();

    renderQueue();

    renderFindings();

    renderAuditReport();

    updateSelection();

    updateStatusBar();

    importMode("url");

    activateSection("source");

    wireSplitters();

    wireEvents();

    wireAudit();

    wireOauth();
    wireLog();

    $("spec-url").focus();

  }



  start();

})();

