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
             log: [], logEntry: null, logTruncated: false, statuses: [],
             coverage: {}, baselines: [], replays: {}, correlation: null },
    // Per operation: a saved request known to work, and what a successful
    // response looks like. Both are what turn a baseline that never reached a
    // resource into one that did. Persisted, because an operator works out the
    // right example once and should not do it again next session.
    examples: {},
    sequence: { steps: [], result: null },
    matrix: { rows: [], result: null },
  };

  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  // What the server uses when Requests in flight is left on the default.
  const PROFILE_CONCURRENCY = { passive: 1, readonly: 4, thorough: 6, writes: 4 };
  const PROFILE_NOTES = {
    passive: "One request per endpoint. Everything else is read from the contract and that single response.",
    readonly: "Adds authorization, CORS, TLS, method and input probes. Only GET, HEAD and OPTIONS are sent; nothing is written.",
    thorough: "Everything read-only, with more parameters probed per endpoint and a short rate-limit burst. More requests per endpoint.",
    writes: "Adds mass-assignment, write-authorization and request-body injection probes. Every one of these creates or modifies data on the target, and the report says how many.",
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
    /** Headers the transport sets itself, and refuses to be handed. */
    const MANAGED = new Set(["host", "content-length", "transfer-encoding",
                             "connection", "proxy-authorization", "upgrade"]);

    function fromText(value) {
      const entries = {};
      const dropped = [];
      for (const line of String(value).split("\n")) {
        if (!line.trim()) continue;
        // A devtools paste carries HTTP/2 pseudo-headers, which are not
        // headers at all and have no value half worth keeping.
        if (line.trim().startsWith(":")) {
          dropped.push(line.trim().split(":")[1] || "pseudo-header");
          continue;
        }
        const split = line.indexOf(":");
        if (split < 1) throw new Error(`Use “Name: value” on each line. Could not read “${line.trim().slice(0, 40)}”.`);
        const name = line.slice(0, split).trim();
        if (MANAGED.has(name.toLowerCase())) {
          dropped.push(name);
          continue;
        }
        entries[name] = line.slice(split + 1).trim();
      }
      setAll(entries);
      return dropped;
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
    access: { view: "view-access" },
    source: { view: "view-source" },
    settings: { view: "view-settings" },
  };
  const VIEWS = ["view-empty", "view-operation", "view-schema", "view-runner", "view-source",
    "view-settings", "view-audit-report", "view-finding", "view-audit-log", "view-access"];



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

  async function api(path, payload, method = "POST") {
    const options = { method, headers: { "Content-Type": "application/json" }, credentials: "same-origin" };
    if (method !== "GET") options.body = JSON.stringify(payload);
    const response = await fetch(path, options);
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
      const payload = { ...routePayload(), headers: importKv.read(),
                        timeout: numericTimeout("import-timeout"),
                        verify_tls: $("import-verify-tls").checked };
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
      loadExamples();
      loadAccess();
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
      ...routePayload(),
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
    renderBaselineEditor();

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



  /* ─────────────── traffic: history, request, response ─────────────── */
  const MAX_LOG = 4000;
  // Pane widths as a percentage of the row, so a resized window keeps the
  // ratio an operator chose rather than the pixel count.
  const PANE_DEFAULTS = { a: 38, b: 30 };
  const PANE_MIN = 12;
  const REQUEST_TABS = [["pretty", "Pretty"], ["raw", "Raw"], ["curl", "curl"]];
  const RESPONSE_TABS = [["pretty", "Pretty"], ["raw", "Raw"]];
  // Enough reason phrases to make a reconstructed status line read like one.
  const STATUS_TEXT = {
    200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 301: "Moved Permanently",
    302: "Found", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect",
    308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable", 409: "Conflict",
    410: "Gone", 413: "Content Too Large", 415: "Unsupported Media Type",
    422: "Unprocessable Content", 429: "Too Many Requests", 500: "Internal Server Error",
    501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
  };
  // The filtered rows in display order. The arrow keys walk this, not the DOM.
  let logShown = [];

  function renderLog() {
    const rows = state.audit.log;
    $("log-count").textContent = rows.length;
    $("report-traffic-count").textContent = rows.length;
    $("report-traffic-count").hidden = !rows.length;
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
    logShown = shown;

    const body = $("log-rows");
    body.replaceChildren();
    if (!shown.length) {
      const row = el("tr");
      const cell = el("td", "log-empty", rows.length ? "No request matches this filter."
        : "No requests yet. Run an audit to populate the history.");
      cell.colSpan = 7;
      row.append(cell);
      body.append(row);
      $("log-shown").textContent = rows.length ? `0 of ${rows.length} requests` : "";
      selectLogEntry(null);
      return;
    }
    for (const entry of shown) {
      const row = el("tr", "log-row");
      row.dataset.key = entry.key;
      row.tabIndex = -1;
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
      row.addEventListener("click", () => {
        selectLogEntry(entry);
        // Focus the list, not the row, so the arrow keys carry on from
        // whichever request was clicked rather than needing a tab first.
        $("log-table-wrap").focus({ preventScroll: true });
      });
      body.append(row);
    }
    $("log-shown").textContent = shown.length === rows.length
      ? `${rows.length} requests`
      : `${shown.length} of ${rows.length} requests`;
    // The panes always describe a row the table is showing, so a filter that
    // hides the selection moves it rather than leaving a stale request open.
    const held = shown.find((entry) => entry.key === state.audit.logEntry?.key);
    selectLogEntry(held || shown[0]);
  }

  function shortUrl(url) {
    try {
      const parsed = new URL(url);
      return parsed.pathname + parsed.search;
    } catch { return url; }
  }

  function selectLogEntry(entry, scroll = false) {
    state.audit.logEntry = entry;
    for (const row of $("log-rows").children) {
      const active = Boolean(entry) && row.dataset.key === entry.key;
      row.classList.toggle("active", active);
      if (active && scroll) row.scrollIntoView({ block: "nearest" });
    }
    renderRequestPane(entry);
    renderResponsePane(entry);
  }

  /** Move the selection by `step` rows through the filtered history. */
  function stepLogEntry(step) {
    if (!logShown.length) return;
    const at = logShown.findIndex((entry) => entry.key === state.audit.logEntry?.key);
    const next = at < 0 ? 0 : Math.min(Math.max(at + step, 0), logShown.length - 1);
    selectLogEntry(logShown[next], true);
  }

  function currentTab(key, tabs) {
    const stored = prefs.read(key, tabs[0][0]);
    return tabs.some(([value]) => value === stored) ? stored : tabs[0][0];
  }

  /** The pane's own tab strip. Returns the tab that should be rendered. */
  function paneTabs(container, tabs, key, redraw) {
    const active = currentTab(key, tabs);
    container.replaceChildren();
    for (const [value, label] of tabs) {
      const button = el("button", `cmd-tab${value === active ? " active" : ""}`, label);
      button.type = "button";
      button.addEventListener("click", () => { prefs.write(key, value); redraw(); });
      container.append(button);
    }
    return active;
  }

  function headerCase(name) {
    return String(name).split("-")
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1)).join("-");
  }

  function headerTable(headers, fallback) {
    const table = el("div", "header-table");
    const entries = Object.entries(headers || {});
    for (const [name, value] of entries) {
      table.append(el("div", "hk", headerCase(name)), el("div", "hv", value));
    }
    if (!entries.length) table.append(el("div", "hk", "-"), el("div", "hv", fallback || "none"));
    return table;
  }

  function rawRequest(entry) {
    let target = entry.url;
    try {
      const parsed = new URL(entry.url);
      target = parsed.pathname + parsed.search;
    } catch { /* not parseable: show the whole URL on the request line */ }
    const lines = [`${entry.method} ${target || "/"} HTTP/1.1`];
    for (const [name, value] of Object.entries(entry.request_headers || {})) {
      lines.push(`${headerCase(name)}: ${value}`);
    }
    return `${lines.join("\n")}\n\n${entry.request_body || ""}`;
  }

  function rawResponse(entry) {
    if (entry.error) return `No response: ${entry.error}`;
    const reason = STATUS_TEXT[entry.status] ? ` ${STATUS_TEXT[entry.status]}` : "";
    const lines = [`HTTP/1.1 ${entry.status}${reason}`];
    for (const [name, value] of Object.entries(entry.response_headers || {})) {
      lines.push(`${headerCase(name)}: ${value}`);
    }
    return `${lines.join("\n")}\n\n${entry.body_excerpt || ""}`;
  }

  // The raw views are built from the parsed exchange, so the reader is told
  // not to treat them as a capture of the bytes that crossed the wire.
  const RAW_NOTE = "Reconstructed from the captured exchange. Header order and casing are Namazu's, "
    + "not the bytes on the wire, and credential headers are masked.";

  /** How much of the body this entry carries, when the server sent more. */
  function bodyNote(entry) {
    const held = (entry.body_excerpt || "").replace(/…$/, "").length;
    const total = entry.body_length || 0;
    if (total <= held) return "";
    return `The history keeps the first ${held.toLocaleString()} of ${total.toLocaleString()} characters.`;
  }

  function renderRequestPane(entry) {
    const body = $("log-request-body");
    body.replaceChildren();
    $("log-request-copy").hidden = !entry;
    if (!entry) {
      $("log-request-tabs").replaceChildren();
      body.append(el("p", "pane-note", "Select a request on the left to inspect it."));
      return;
    }
    const tab = paneTabs($("log-request-tabs"), REQUEST_TABS, "log-request-tab",
                         () => renderRequestPane(entry));
    if (tab === "curl") {
      body.append(commandBlock(entry.commands || { bash: entry.curl }, []));
      body.append(el("p", "pane-note",
        "Credentials are masked. Put the real value back before running it."));
      return;
    }
    if (tab === "raw") {
      const text = rawRequest(entry);
      body.append(markedInto(el("pre", "raw-http"), text, bodyHighlights(text), { limit: 4 }));
      body.append(el("p", "pane-note", RAW_NOTE));
      return;
    }
    const head = el("div", "log-status");
    head.append(methodBadge(entry.method));
    head.append(el("span", "mono", entry.url));
    head.append(el("span", "chip", entry.identity));
    if (entry.mutating) head.append(el("span", "chip warn", "wrote data"));
    body.append(head);
    body.append(el("p", "hint pad", `${entry.endpoint} · ${entry.label}`));
    body.append(el("p", "proof-label", "request headers"));
    body.append(headerTable(entry.request_headers, "no headers recorded"));
    if (entry.request_body) {
      body.append(el("p", "proof-label", "request body"));
      body.append(el("pre", "code-block wrap", prettyBody(entry.request_body)));
    } else {
      body.append(el("p", "pane-note", "This request has no body."));
    }
  }

  function renderResponsePane(entry) {
    const body = $("log-response-body");
    body.replaceChildren();
    $("log-response-copy").hidden = !entry;
    if (!entry) {
      $("log-response-tabs").replaceChildren();
      body.append(el("p", "pane-note", "Nothing to show yet."));
      return;
    }
    const tab = paneTabs($("log-response-tabs"), RESPONSE_TABS, "log-response-tab",
                         () => renderResponsePane(entry));
    if (tab === "raw") {
      const text = rawResponse(entry);
      body.append(markedInto(el("pre", "raw-http"), text, bodyHighlights(text), { limit: 4 }));
      const note = bodyNote(entry);
      body.append(el("p", "pane-note", note ? `${RAW_NOTE} ${note}` : RAW_NOTE));
      return;
    }
    const head = el("div", "log-status");
    head.append(entry.error ? pill("error", "fail")
      : pill(`HTTP ${entry.status}${STATUS_TEXT[entry.status] ? ` ${STATUS_TEXT[entry.status]}` : ""}`,
             statusKind(entry.status)));
    head.append(el("span", "mono dim", `${humanBytes(entry.body_length || 0)} · ${
      Number.isFinite(entry.elapsed_ms) ? `${Math.round(entry.elapsed_ms)} ms` : "no timing"}`));
    if (entry.truncated) head.append(el("span", "chip warn", "capped at 512 KB"));
    body.append(head);
    if (entry.error) {
      body.append(el("p", "pane-note", `The request did not complete: ${entry.error}.`));
      return;
    }
    body.append(el("p", "proof-label", "response headers"));
    body.append(headerTable(entry.response_headers, "no headers returned"));
    if (entry.body_excerpt) {
      body.append(el("p", "proof-label", `response body · ${humanBytes(entry.body_length || 0)}`));
      const text = prettyBody(entry.body_excerpt);
      body.append(markedInto(el("pre", "code-block wrap"), text, bodyHighlights(text), { limit: 4 }));
      const note = bodyNote(entry);
      if (note) body.append(el("p", "pane-note", note));
    } else {
      body.append(el("p", "pane-note", "The response has an empty body."));
    }
  }

  /* pane sizing */

  // Below this width three columns cannot hold a path and a body, so the panes
  // stack and the gutters stop being handles. The breakpoint is in style.css too.
  function stackedPanes() { return window.matchMedia("(max-width: 1250px)").matches; }

  function paneWidth(which) {
    const value = Number(prefs.read(`log-pane-${which}`, PANE_DEFAULTS[which]));
    if (!Number.isFinite(value)) return PANE_DEFAULTS[which];
    return Math.min(Math.max(value, PANE_MIN), 100 - 2 * PANE_MIN);
  }

  function applyPanes() {
    const panes = $("log-panes");
    panes.style.setProperty("--pane-a", `${paneWidth("a")}%`);
    panes.style.setProperty("--pane-b", `${paneWidth("b")}%`);
  }

  function resizePane(which, percent) {
    const other = paneWidth(which === "a" ? "b" : "a");
    // Whatever is left over belongs to the response pane, which gets a floor too.
    prefs.write(`log-pane-${which}`,
                Math.min(Math.max(percent, PANE_MIN), 100 - other - PANE_MIN));
    applyPanes();
  }

  function wireGutter(gutter, which) {
    gutter.addEventListener("pointerdown", (event) => {
      if (stackedPanes()) return;
      event.preventDefault();
      const rect = $("log-panes").getBoundingClientRect();
      // Gutter B starts where pane A ends, so its drag is measured from there.
      const offset = which === "a" ? 0 : paneWidth("a");
      const move = (moved) => {
        resizePane(which, ((moved.clientX - rect.left) / rect.width) * 100 - offset);
      };
      const release = () => {
        gutter.classList.remove("dragging");
        gutter.removeEventListener("pointermove", move);
        gutter.removeEventListener("pointerup", release);
        gutter.removeEventListener("pointercancel", release);
        if (gutter.hasPointerCapture(event.pointerId)) gutter.releasePointerCapture(event.pointerId);
      };
      gutter.classList.add("dragging");
      gutter.setPointerCapture(event.pointerId);
      gutter.addEventListener("pointermove", move);
      gutter.addEventListener("pointerup", release);
      gutter.addEventListener("pointercancel", release);
    });
    gutter.addEventListener("keydown", (event) => {
      const step = event.key === "ArrowLeft" ? -2 : event.key === "ArrowRight" ? 2 : 0;
      if (!step || stackedPanes()) return;
      event.preventDefault();
      resizePane(which, paneWidth(which) + step);
    });
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

  function showTraffic() {
    state.audit.finding = null;
    activateSection("audit");
    showView("view-audit-log");
    applyPanes();
    renderLog();
  }

  function showAuditReport() {
    state.audit.finding = null;
    showView("view-audit-report");
    renderFindings();
  }

  function wireLog() {
    $("log-search").addEventListener("input", renderLog);
    $("log-filter").addEventListener("change", renderLog);
    $("export-log").addEventListener("click", exportLog);
    $("audit-log").addEventListener("click", showTraffic);
    $("report-traffic").addEventListener("click", showTraffic);
    $("report-here").addEventListener("click", showAuditReport);
    $("log-back").addEventListener("click", showAuditReport);
    $("log-here").addEventListener("click", () => $("log-table-wrap").focus());
    $("log-request-copy").addEventListener("click", () => {
      if (state.audit.logEntry) copyText(rawRequest(state.audit.logEntry), "Request");
    });
    $("log-response-copy").addEventListener("click", () => {
      if (state.audit.logEntry) copyText(rawResponse(state.audit.logEntry), "Response");
    });
    $("log-reset-panes").addEventListener("click", () => {
      for (const which of ["a", "b"]) prefs.clear(`log-pane-${which}`);
      applyPanes();
    });
    wireGutter($("log-gutter-a"), "a");
    wireGutter($("log-gutter-b"), "b");
    // One request at a time, the way a history list is read.
    $("log-table-wrap").addEventListener("keydown", (event) => {
      const moves = { ArrowDown: 1, ArrowUp: -1, PageDown: 10, PageUp: -10 };
      if (event.key in moves) {
        event.preventDefault();
        stepLogEntry(moves[event.key]);
      } else if (event.key === "Home" && logShown.length) {
        event.preventDefault();
        selectLogEntry(logShown[0], true);
      } else if (event.key === "End" && logShown.length) {
        event.preventDefault();
        selectLogEntry(logShown[logShown.length - 1], true);
      }
    });
    applyPanes();
  }
  /* ───────────────────────── security audit ───────────────────────── */

  const identityKv = createKv("identity-b-rows", { noun: "Header", onChange: () => updateIdentityState() });



  function identityB() { return identityKv.safeRead(); }

  /**
   * An identity the engine can keep alive. A header is a snapshot; an OAuth
   * configuration lets the server mint a replacement when the token expires,
   * which is what a run across dozens of operations needs.
   */
  function renewableIdentity(headers) {
    if ($("auth-mode").value !== "oauth2") return headers;
    const config = oauthConfig();
    // Client credentials and password can re-mint from what the operator
    // typed. Every other grant needs a refresh token, whether it came back
    // from the browser flow or was pasted into the field.
    const carried = oauthState.refreshToken || config.refresh_token;
    const renewable = config.grant === "client_credentials" || config.grant === "password"
      || Boolean(carried);
    if (!config.token_endpoint || !renewable) return headers;
    return {
      headers,
      oauth: {
        grant: carried && config.grant === "authorization_code"
          ? "refresh_token" : config.grant,
        token_endpoint: config.token_endpoint,
        client_id: config.client_id,
        client_secret: config.client_secret,
        scope: config.scope,
        audience: config.audience,
        username: config.username,
        password: config.password,
        refresh_token: carried,
        auth_style: config.auth_style,
      },
    };
  }

  function updateIdentityState() {
    const count = Object.keys(identityB()).length;

    $("identity-b-state").textContent = count ? `${count} header${count === 1 ? "" : "s"}` : "not set";
  }

  /** Empty means "announce yourself as Namazu", which the server decides. */
  function userAgent() {
    const value = $("user-agent").value.trim();
    return value || null;
  }

  /** Whether requests should avoid naming the tool. See namazu/signature.py. */
  function quietMode() { return $("outbound-mode").value === "quiet"; }

  const OUTBOUND_NOTES = {
    announced: "The user agent names Namazu, and every probe marker, header and path says so too. "
      + "Both sides of the engagement can pick the test out of a log afterwards.",
    quiet: "The user agent becomes an ordinary browser string and every probe marker is derived from "
      + "a random token the report names, so the traffic cannot be attributed to this tool. The "
      + "probes themselves do not change: an injection payload still looks like one. Use it to test "
      + "whether monitoring notices a scan, or when a WAF refuses an unfamiliar client by name.",
  };

  function renderOutboundMode() {
    const mode = $("outbound-mode").value;
    $("outbound-note").textContent = OUTBOUND_NOTES[mode] || "";
    prefs.write("outbound-mode", mode);
  }

  /** How requests leave the machine: the same route for every endpoint.
   *
   * One builder on purpose. These fields were listed by hand at each call
   * site, and the audit payload had drifted: it carried verify_tls but not the
   * user agent, so a value set to get past a WAF applied to contract import
   * and single requests and not to the hundreds of requests an audit sends.
   */
  function routePayload() {
    const text = (id) => $(id).value.trim() || null;
    return {
      verify_tls: $("verify-tls").checked,
      user_agent: userAgent(),
      quiet: quietMode(),
      proxy: text("proxy-url"),
      ca_bundle: text("ca-bundle"),
      client_cert: text("client-cert"),
      client_key: text("client-key"),
      // Not trimmed: whitespace can be part of a passphrase.
      client_key_password: $("client-key-password").value || null,
    };
  }

  function auditProfile() { return $("audit-profile").value; }

  /** Null means "let the profile decide", which is what the server does with it. */
  function auditConcurrency() {
    const chosen = parseInt($("audit-concurrency").value, 10);
    return Number.isFinite(chosen) ? chosen : null;
  }

  function describeConcurrency() {
    const chosen = auditConcurrency();
    const workers = chosen === null ? PROFILE_CONCURRENCY[auditProfile()] || 1 : chosen;
    $("concurrency-note").textContent = workers === 1
      ? "One request at a time. The slowest setting, and the gentlest on the target."
      : `Up to ${workers} probes in flight at once. The same requests go out either way; only the wall clock changes.`;
  }

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
      const tag = sourceTag(item);
      if (tag) meta.append(tag);
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
    const source = findingSource(item);
    $("finding-severity").textContent = source
      ? `${item.severity} · ${item.confidence} · ${source}`
      : `${item.severity} · ${item.confidence}`;
    $("finding-severity").className = "chip";
    $("finding-severity").dataset.sev = item.severity;
    $("finding-title").textContent = item.title;
    const axes = $("finding-axes");
    axes.replaceChildren();
    const chips = evidenceChips(item);
    if (chips) axes.append(chips);

    const body = $("finding-body");
    body.replaceChildren();
    const card = (title, children, key) =>
      body.append(reportCard(title, children, { collapsible: true, key: key || title }));

    // Issue detail: what is true about this target.
    const observed = [markedInto(el("p", "prose"), item.detail, item.highlights)];
    const legend = highlightLegend(item.highlights);
    if (legend) observed.push(legend);
    card("Issue detail", observed);

    const assessed = evidenceCard(item);
    if (assessed) card("What this establishes", assessed);

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
    if (item.cases?.length) {
      card(`Captured cases · ${item.cases.length}`,
        [el("p", "hint", "Each case carries the request and response as recorded, and can be "
          + "sent again. Replay establishes whether the behaviour happens again; it does not "
          + "establish that the behaviour is a weakness."),
         ...item.cases.map((aCase, index) => caseBlock(item, aCase, index))],
        "Captured cases");
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

  /**
   * A whole run of 404s is almost never forty dead operations. It is the base
   * URL missing the API's own base path, so say that instead of reporting
   * every endpoint as a zombie.
   */
  function runDiagnostics() {
    const audit = state.audit;
    const statuses = audit.statuses || [];
    // Two is the floor: a single 404 is a plausible zombie operation, but two
    // out of two is a base URL that does not reach the API.
    if (statuses.length < 2) return null;
    const notFound = statuses.filter((status) => status === 404).length;
    const unauthorised = statuses.filter((status) => status === 401 || status === 403).length;
    const base = $("base-url").value.trim();
    const servers = [...($("server-options").children || [])].map((option) => option.value);

    if (notFound / statuses.length >= 0.8) {
      const suggestion = servers.find((server) => server && server !== base);
      return {
        kind: "bad",
        text: `${notFound} of ${statuses.length} operations returned 404. That usually means the base `
          + `URL is missing the path the API is served under, rather than the operations being absent. `
          + `The contract paths are appended to the base URL exactly as written.`
          + (suggestion ? ` The contract lists ${suggestion}; the run used ${base || "(empty)"}.` : ""),
      };
    }
    if (unauthorised / statuses.length >= 0.8) {
      return {
        kind: "bad",
        text: `${unauthorised} of ${statuses.length} operations returned 401 or 403. The audit is `
          + `running unauthenticated or with a credential the API rejected. Configure OAuth 2 under `
          + `Auth, or add the credential header, then run again. Findings from this run describe an `
          + `API you were never let into.`,
      };
    }
    return null;
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

    const diagnosis = runDiagnostics();
    if (diagnosis) {
      body.append(reportCard("Check the run setup",
        [el("div", "prose caution prewrap", diagnosis.text)]));
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
        ? "supplied" : "not supplied, so cross-identity access was not tested at all"],
      ["Surface sweep", audit.discovery
        ? `${(audit.discovery.shadow || []).length} undocumented, ${(audit.discovery.exposed || []).length} exposed`
        : "not run"],
    ]) {
      const row = el("div");
      row.append(el("dt", "", label), el("dd", "", value));
      coverage.append(row);
    }

    body.append(reportCard("Run totals", [coverage]));

    const baselines = baselineCard();
    if (baselines) {
      body.append(reportCard("Baselines", baselines, { collapsible: true, key: "Baselines" }));
    }
    const checks = coverageCard();
    if (checks) {
      body.append(reportCard("What was tested", checks,
        { collapsible: true, key: "What was tested" }));
    }
    if (audit.correlation?.notes?.length) {
      const list = el("ul", "note-list");
      for (const note of audit.correlation.notes) list.append(el("li", "", note));
      body.append(reportCard(
        `Duplicates · ${audit.correlation.merged} merged`,
        [el("p", "hint", "Two sources are merged only when their captured exchanges agree on "
          + "the operation, the response status and the specific thing observed. Where one side "
          + "has no exchange to compare, both are kept and cross-referenced."), list],
        { collapsible: true, key: "Duplicates" }));
    }

    if (audit.notes.length) {
      const list = el("ul", "note-list");

      for (const note of [...new Set(audit.notes)]) list.append(el("li", "", note));

      body.append(reportCard("Run notes", [list]));
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



  /* ─────────────── second opinion: external scanners ─────────────── */

  // A finding id prefix is the authoritative tag: external.py builds every one
  // of these as "<tool>.<template or check>", and nothing else in the
  // catalogue uses a tool name as its prefix.
  const EXTERNAL_TOOLS = ["nuclei", "schemathesis"];

  function findingSource(item) {
    const id = String(item?.id || "");
    return EXTERNAL_TOOLS.find((tool) => id.startsWith(`${tool}.`)) || "";
  }

  function sourceTag(item) {
    const source = findingSource(item);
    if (!source) return null;
    const tag = el("span", "src", source);
    tag.title = `Reported by ${source}, not verified by Namazu.`;
    return tag;
  }

  async function loadTools() {
    const status = $("tools-state");
    status.textContent = "checking…";
    let tools;
    try { tools = await api("/api/tools", null, "GET"); }
    catch (error) { status.textContent = "unavailable"; message("work-error", errorText(error)); return; }
    const list = $("tool-list");
    list.replaceChildren();
    const ready = Object.entries(tools).filter(([, info]) => info.available);
    status.textContent = ready.length ? `${ready.length} available` : "none installed";
    for (const [name, info] of Object.entries(tools)) {
      const row = el("div", "tool-row");
      row.append(el("span", "tool-name", name));
      if (info.version) row.append(el("span", "tool-ver", info.version));
      if (info.available) {
        const run = el("button", "btn", "Run");
        run.type = "button";
        run.dataset.tool = name;
        run.addEventListener("click", () => runExternalTool(name, run));
        row.append(run);
      } else {
        const hint = el("span", "tool-ver", "not installed");
        hint.title = info.install || "";
        row.append(hint);
      }
      list.append(row);
      list.append(el("p", "tool-role", info.role || ""));
      const policy = info.capabilities?.write_policy;
      if (policy) list.append(el("p", "tool-role dim", policy));
    }
  }

  async function runExternalTool(name, button, chained = false) {
    if (!state.spec) { toast("Import a contract first."); return; }
    // The chained run is started from inside the audit's own completion, so the
    // running flag is still the audit that asked for it.
    if (state.audit.running && !chained) { toast("Wait for the audit to finish."); return; }
    let connection;
    try { connection = connectionPayload(); }
    catch (error) { toast(errorText(error)); return; }
    const target = connection.base_url || state.spec.base_url || $("base-url").value.trim();
    if (!target) { toast("Set a base URL before running an external tool."); return; }

    if (button) {
      button.disabled = true;
      button.textContent = "Running…";
    }
    announce(`${name} is running. This can take a few minutes.`);
    try {
      const result = await api("/api/tools/run", {
        spec: state.spec,
        base_url: target,
        tool: name,
        identities: { primary: connection.headers },
        allow_mutating: connection.allow_mutating,
        ...routePayload(),
        timeout: connection.timeout,
      });
      if (!result.ran) {
        toast(`${name} did not run.`);
        for (const note of result.notes || []) state.audit.notes.push(`${name}: ${note}`);
        renderAuditReport();
        return;
      }
      const before = state.audit.findings.length;
      absorb(result, name);
      const added = state.audit.findings.length - before;
      if (result.version) {
        state.audit.notes.push(`${name} ${result.version} ran${result.summary?.operations_tested
          ? `, testing ${result.summary.operations_tested} operation(s)` : ""}.`);
      }
      if (result.truncated) {
        state.audit.notes.push(`${name} reported more findings than Namazu keeps; the rest are `
          + "not shown.");
      }
      if (result.zap_coverage?.gaps?.length) {
        for (const gap of result.zap_coverage.gaps) {
          state.audit.notes.push(`${name} coverage: ${gap}`);
        }
      }
      activateSection("audit");
      renderFindings();
      renderAuditReport();
      toast(added
        ? `${name}: ${added} finding(s) added, tagged ${name}.`
        : `${name} ran and found nothing to add.`);
    } catch (error) {
      message("work-error", `${name}: ${errorText(error)}`);
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = "Run";
      }
    }
  }

  /** Every installed tool, in turn, after Namazu's own checks have finished. */
  async function runQueuedTools() {
    if (!$("tools-after-audit").checked) return;
    let tools;
    try { tools = await api("/api/tools", null, "GET"); }
    catch { return; }
    const ready = Object.entries(tools).filter(([, info]) => info.available).map(([name]) => name);
    if (!ready.length) {
      state.audit.notes.push("Second opinion: no external tool is installed, so none ran.");
      renderAuditReport();
      return;
    }
    for (const name of ready) {
      if (state.audit.cancelled) break;
      // Sequentially: each is a subprocess pointed at the same target, and
      // two of them at once is traffic the operator did not ask for.
      await runExternalTool(name, null, true);
    }
    // Correlation runs last, once every source has reported. Doing it per tool
    // would mean comparing a finding against only the sources that happened to
    // have run already.
    await correlateFindings();
  }

  // Deduplication happens on the server because the decision needs the
  // captured exchanges, and because "are these two the same defect" is a
  // judgement that should be testable rather than a line of browser code.
  async function correlateFindings() {
    if (state.audit.findings.length < 2) return;
    try {
      const result = await api("/api/correlate", {
        findings: state.audit.findings.map(({ key, ...item }) => item),
      });
      const keys = new Map(state.audit.findings.map((item) => [findingKey(item), item.key]));
      state.audit.findings = result.findings.map((item) => ({
        ...item, key: keys.get(findingKey(item)) || findingKey(item),
      }));
      state.audit.correlation = { merged: result.merged, notes: result.notes };
      if (result.merged) {
        announce(`${result.merged} duplicate finding(s) merged across sources.`);
      }
      renderFindings();
      renderAuditReport();
    } catch (error) {
      state.audit.notes.push(`Duplicate detection did not run: ${errorText(error)}`);
      renderAuditReport();
    }
  }

  function findingKey(item) {
    return item.scope === "host"
      ? `${item.id}|${item.parameter || ""}`
      : `${item.id}|${item.endpoint}|${item.parameter || ""}`;
  }

  /* ───────────────────── access testing ───────────────────── */

  const MATRIX_FIELDS = [
    ["identity", "primary", "text"],
    ["tenant", "", "text"],
    ["method", "GET", "method"],
    ["url", "", "text"],
    ["resource", "", "text"],
    ["marker", "", "text"],
    ["expect", "allow", "expect"],
  ];
  const SEQUENCE_FIELDS = [
    ["name", "", "text"],
    ["identity", "primary", "text"],
    ["method", "GET", "method"],
    ["url", "", "text"],
    ["body", "", "text"],
    ["extract", "", "text"],
    ["expect", "", "text"],
  ];
  const MATRIX_OUTCOME_LABEL = {
    "as-expected": "As expected",
    "unexpected-allow": "Reached it",
    "unexpected-deny": "Refused",
    inconclusive: "Inconclusive",
    blocked: "Blocked",
    error: "Error",
  };

  function renderAccess() {
    renderRowList("matrix-rows", state.matrix.rows, MATRIX_FIELDS, renderAccess);
    renderRowList("sequence-rows", state.sequence.steps, SEQUENCE_FIELDS, renderAccess, true);
  }

  // One row builder for both tables. They differ only in their columns and in
  // whether a step can be marked as creating something.
  function renderRowList(target, rows, fields, rerender, withCreates = false) {
    const host = $(target);
    host.replaceChildren();
    if (!rows.length) {
      host.append(el("p", "pane-empty", "No rows yet."));
      return;
    }
    rows.forEach((row, index) => {
      const line = el("div", withCreates ? "seq-row" : "matrix-row");
      for (const [name, fallback, kind] of fields) {
        if (kind === "method") {
          const select = el("select", "mini");
          select.setAttribute("aria-label", `${name} for row ${index + 1}`);
          for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]) {
            const option = el("option", "", method);
            option.value = method;
            if ((row[name] || fallback) === method) option.selected = true;
            select.append(option);
          }
          select.addEventListener("change", () => { row[name] = select.value; saveAccess(); });
          line.append(select);
          continue;
        }
        if (kind === "expect") {
          const select = el("select", "mini");
          select.setAttribute("aria-label", `expected access for row ${index + 1}`);
          for (const value of ["allow", "deny"]) {
            const option = el("option", "", value);
            option.value = value;
            if ((row[name] || fallback) === value) option.selected = true;
            select.append(option);
          }
          select.addEventListener("change", () => { row[name] = select.value; saveAccess(); });
          line.append(select);
          continue;
        }
        const input = el("input", "mini-input");
        input.type = "text";
        input.spellcheck = false;
        input.setAttribute("aria-label", `${name} for row ${index + 1}`);
        input.value = row[name] === undefined ? fallback : row[name];
        input.addEventListener("input", () => { row[name] = input.value; saveAccess(); });
        line.append(input);
      }
      if (withCreates) {
        const box = el("input");
        box.type = "checkbox";
        box.checked = Boolean(row.creates);
        box.setAttribute("aria-label", `step ${index + 1} creates something`);
        box.addEventListener("change", () => { row.creates = box.checked; saveAccess(); });
        line.append(box);
      }
      const remove = el("button", "link", "Remove");
      remove.type = "button";
      remove.addEventListener("click", () => {
        rows.splice(index, 1);
        saveAccess();
        rerender();
      });
      line.append(remove);
      host.append(line);
    });
  }

  function accessKey() {
    return `access:${state.spec?.title || "api"}:${$("base-url").value || ""}`;
  }

  function saveAccess() {
    try {
      prefs.write(accessKey(), JSON.stringify({
        matrix: state.matrix.rows, sequence: state.sequence.steps,
      }));
    } catch { /* a saved matrix is a convenience */ }
  }

  function loadAccess() {
    try {
      const raw = prefs.read(accessKey(), "");
      const held = raw ? JSON.parse(raw) : {};
      state.matrix.rows = Array.isArray(held.matrix) ? held.matrix : [];
      state.sequence.steps = Array.isArray(held.sequence) ? held.sequence : [];
    } catch {
      state.matrix.rows = [];
      state.sequence.steps = [];
    }
    renderAccess();
  }

  // A starting point rather than a guess at the answer: one allow row per
  // identity, which is the positive control, and one deny row aimed at the
  // same resource from the other identity. The URLs and markers are left for
  // the operator, because only they know which object belongs to whom.
  function matrixTemplate() {
    const operation = state.operation;
    if (!operation) {
      toast("Select an operation first, so the rows have something to aim at.");
      return;
    }
    const base = ($("base-url").value || state.spec?.base_url || "").replace(/\/$/, "");
    const url = `${base}${operation.path}`;
    const second = Object.keys(identityB()).length ? "secondary" : "";
    state.matrix.rows = [
      { identity: "primary", tenant: "", method: operation.method, url,
        resource: "an object this identity owns", marker: "", expect: "allow" },
      ...(second ? [{ identity: "secondary", tenant: "", method: operation.method, url,
                      resource: "an object this identity owns", marker: "", expect: "allow" }]
                 : []),
      ...(second ? [{ identity: "secondary", tenant: "", method: operation.method, url,
                      resource: "the first identity's object", marker: "", expect: "deny" }]
                 : []),
    ];
    saveAccess();
    renderAccess();
    toast(second
      ? "Three rows added. Fill in each URL and the marker that identifies its resource."
      : "One row added. Set a second identity in the Audit panel to test a boundary.");
  }

  function accessIdentities(connection) {
    // Named so a row or a step can address either, and the names match what
    // the report shows.
    const primary = renewableIdentity(connection.headers);
    const secondary = identityB();
    return {
      primary, secondary,
      ...(Object.keys(primary).length ? { "identity a": primary } : {}),
      ...(Object.keys(secondary).length ? { "identity b": secondary } : {}),
    };
  }

  async function runMatrix() {
    const rows = state.matrix.rows.filter((row) => (row.url || "").trim());
    if (!rows.length) { toast("Add a row with a URL first."); return; }
    let connection;
    try { connection = connectionPayload(); }
    catch (error) { toast(errorText(error)); return; }
    const button = $("run-matrix");
    button.disabled = true;
    button.textContent = "Running…";
    try {
      const result = await api("/api/matrix", {
        rows,
        identities: accessIdentities(connection),
        allow_mutating: connection.allow_mutating,
        ...routePayload(),
        timeout: connection.timeout,
      });
      state.matrix.result = result;
      renderMatrixResult();
      announce(`Permission matrix finished: ${result.summary?.rows || 0} rows.`);
    } catch (error) {
      toast(errorText(error));
    } finally {
      button.disabled = false;
      button.textContent = "Run matrix";
    }
  }

  function renderMatrixResult() {
    const host = $("matrix-result");
    host.replaceChildren();
    const result = state.matrix.result;
    if (!result) return;
    const parts = [];
    const problems = result.summary?.problems || [];
    if (problems.length) {
      parts.push(el("p", "prose caution",
        `${problems.length} row(s) did not match the expectation.`));
    }
    const list = el("div", "cov-list");
    for (const row of result.rows || []) {
      const entry = el("div", "cov-row");
      entry.dataset.state = row.outcome === "as-expected" ? "completed"
        : row.outcome === "inconclusive" || row.outcome === "blocked" ? "inconclusive"
        : "blocked";
      const label = el("div", "cov-name");
      label.append(el("span", "t",
        `${row.identity} ${row.expect} ${row.resource || row.operation || row.url}`));
      label.append(el("span", "w", row.reason || ""));
      entry.append(label);
      const right = el("div", "cov-right");
      const chip = el("span", "chip");
      chip.dataset.cov = entry.dataset.state;
      chip.textContent = MATRIX_OUTCOME_LABEL[row.outcome] || row.outcome;
      right.append(chip);
      if (row.status) right.append(el("span", "n", String(row.status)));
      if (row.marker_seen === true) right.append(el("span", "n", "marker seen"));
      if (row.marker_seen === false) right.append(el("span", "n", "no marker"));
      entry.append(right);
      list.append(entry);
    }
    parts.push(list);
    if (result.controls) {
      const controls = Object.entries(result.controls)
        .map(([name, outcome]) => `${name}: ${outcome}`).join(", ");
      parts.push(el("p", "hint", `Positive controls: ${controls || "none"}.`));
    }
    if (result.note) parts.push(el("p", "hint", result.note));
    host.append(reportCard("Matrix result", parts));
  }

  function parseExtract(text) {
    const out = {};
    for (const line of String(text || "").split(/[\n,]/)) {
      const [name, pointer] = line.split("=");
      if (name?.trim() && pointer?.trim()) out[name.trim()] = pointer.trim();
    }
    return out;
  }

  async function runSequence() {
    const steps = state.sequence.steps
      .filter((step) => (step.url || "").trim())
      .map((step, index) => ({
        name: step.name || `step ${index + 1}`,
        method: step.method || "GET",
        url: step.url,
        identity: step.identity || "primary",
        ...(step.body ? { body: step.body } : {}),
        ...(Object.keys(parseExtract(step.extract)).length
          ? { extract: parseExtract(step.extract) } : {}),
        ...(step.expect ? { expect: { status: String(step.expect) } } : {}),
        creates: Boolean(step.creates),
      }));
    if (!steps.length) { toast("Add a step with a URL first."); return; }
    let connection;
    try { connection = connectionPayload(); }
    catch (error) { toast(errorText(error)); return; }
    const writes = steps.some((step) => !["GET", "HEAD", "OPTIONS"].includes(step.method));
    if (writes && !connection.allow_mutating) {
      toast("This sequence sends a state-changing request. Turn on Allow writes first.");
      return;
    }
    const button = $("run-sequence");
    button.disabled = true;
    button.textContent = "Running…";
    try {
      const result = await api("/api/sequence", {
        steps,
        identities: accessIdentities(connection),
        allow_mutating: connection.allow_mutating,
        ...routePayload(),
        timeout: connection.timeout,
      });
      state.sequence.result = result;
      renderSequenceResult();
      announce(`Sequence ${result.outcome}.`);
    } catch (error) {
      toast(errorText(error));
    } finally {
      button.disabled = false;
      button.textContent = "Run sequence";
    }
  }

  function renderSequenceResult() {
    const host = $("sequence-result");
    host.replaceChildren();
    const result = state.sequence.result;
    if (!result) return;
    const parts = [];
    if (result.reason) parts.push(el("p", "prose caution", result.reason));
    const list = el("div", "cov-list");
    for (const step of result.steps || []) {
      const entry = el("div", "cov-row");
      entry.dataset.state = step.outcome === "ok" ? "completed" : "blocked";
      const label = el("div", "cov-name");
      label.append(el("span", "t", step.name));
      if (step.detail) label.append(el("span", "w", step.detail));
      entry.append(label);
      const right = el("div", "cov-right");
      const chip = el("span", "chip");
      chip.dataset.cov = entry.dataset.state;
      chip.textContent = step.outcome;
      right.append(chip);
      if (step.status) right.append(el("span", "n", String(step.status)));
      if (step.extracted?.length) {
        right.append(el("span", "n", `took ${step.extracted.join(", ")}`));
      }
      entry.append(right);
      list.append(entry);
    }
    parts.push(list);
    if (result.variables?.length) {
      // Names only. An extracted value is frequently a session token, and the
      // server does not send the values back for that reason.
      parts.push(el("p", "hint", `Variables carried forward: ${result.variables.join(", ")}. `
        + "Their values are not shown, because an extracted value is often a credential."));
    }
    if (result.created?.length) {
      const created = el("ul", "note-list");
      for (const item of result.created) {
        created.append(el("li", "", `${item.step}: ${item.state} at ${item.url}. ${item.why}`));
      }
      parts.push(el("div", "case-missing-label", "What this run left behind"), created);
    }
    if (result.cleanup) parts.push(el("p", "prose caution", result.cleanup));
    host.append(reportCard("Sequence result", parts));
  }

  function wireAccess() {
    $("add-matrix-row").addEventListener("click", () => {
      state.matrix.rows.push({ identity: "primary", method: "GET", expect: "allow" });
      saveAccess();
      renderAccess();
    });
    $("clear-matrix").addEventListener("click", () => {
      state.matrix.rows = [];
      state.matrix.result = null;
      saveAccess();
      renderAccess();
      $("matrix-result").replaceChildren();
    });
    $("add-sequence-row").addEventListener("click", () => {
      state.sequence.steps.push({ identity: "primary", method: "GET" });
      saveAccess();
      renderAccess();
    });
    $("clear-sequence").addEventListener("click", () => {
      state.sequence.steps = [];
      state.sequence.result = null;
      saveAccess();
      renderAccess();
      $("sequence-result").replaceChildren();
    });
    $("matrix-template").addEventListener("click", matrixTemplate);
    $("run-matrix").addEventListener("click", runMatrix);
    $("run-sequence").addEventListener("click", runSequence);
  }

  /* ───────────────────── saved baselines and expectations ───────────────────── */

  // Persisted per operation id, keyed by the specification's own base URL so
  // two environments of the same API do not share an example that only exists
  // in one of them.
  function examplesKey() {
    return `examples:${state.spec?.title || "api"}:${$("base-url").value || ""}`;
  }

  function loadExamples() {
    try {
      const raw = prefs.read(examplesKey(), "");
      state.examples = raw ? JSON.parse(raw) : {};
    } catch { state.examples = {}; }
    renderBaselineEditor();
  }

  function saveExamples() {
    try { prefs.write(examplesKey(), JSON.stringify(state.examples)); }
    catch { /* a saved example is a convenience, not state the audit needs */ }
  }

  function renderBaselineEditor() {
    const block = $("baseline-block");
    if (!block) return;
    const operation = state.operation;
    block.hidden = !operation;
    if (!operation) return;
    const saved = state.examples[operation.id] || {};
    const example = saved.example || {};
    const expectation = saved.expectation || {};
    $("baseline-url").value = example.url || "";
    $("baseline-body").value = typeof example.body === "string"
      ? example.body
      : (example.body === undefined || example.body === null ? "" : stringify(example.body));
    $("baseline-status").value = expectation.status || "";
    $("baseline-negative").checked = Boolean(expectation.negative);
    $("baseline-contains").value = expectation.body_contains || "";
    const parts = [];
    if (example.url || example.body !== undefined) parts.push("saved request");
    if (expectation.status || expectation.body_contains) parts.push("assertions");
    if (expectation.negative) parts.push("negative test");
    $("baseline-state").textContent = parts.length ? parts.join(" + ") : "generated";
    const invented = generatedInputs(operation);
    $("baseline-saved-note").textContent = parts.length
      ? `Applies to ${operation.method} ${operation.path}.`
      : invented.length
        ? `The contract documents no example for ${invented.join(", ")}, so the generated `
          + "request will carry placeholder values for them."
        : "";
  }

  // The same rule the server applies, so the panel can warn before a run
  // rather than only explaining afterwards. See namazu/audit/baseline.py.
  function generatedInputs(operation) {
    const out = [];
    for (const parameter of operation?.parameters || []) {
      if (parameter.in !== "path" && parameter.in !== "query") continue;
      if (!parameter.name) continue;
      const schema = parameter.schema || {};
      const documented = parameter.example !== undefined || parameter.examples
        || schema.example !== undefined || schema.default !== undefined
        || schema.enum || schema.const !== undefined || schema.examples;
      if (!documented) out.push(`${parameter.in}.${parameter.name}`);
    }
    return out;
  }

  function saveBaseline() {
    const operation = state.operation;
    if (!operation) return;
    const url = $("baseline-url").value.trim();
    const bodyText = $("baseline-body").value.trim();
    const status = $("baseline-status").value.trim();
    const contains = $("baseline-contains").value.trim();
    const negative = $("baseline-negative").checked;

    const example = {};
    if (url) example.url = url;
    if (bodyText) {
      // A JSON body is sent as a structure so the server treats it the way the
      // generated one is treated; anything else goes as the text typed.
      try { example.body = JSON.parse(bodyText); }
      catch { example.body = bodyText; }
    }
    if (url || bodyText) example.label = "a saved example request";

    const expectation = {};
    if (status) expectation.status = status;
    if (contains) expectation.body_contains = contains;
    if (negative) expectation.negative = true;

    if (!Object.keys(example).length && !Object.keys(expectation).length) {
      delete state.examples[operation.id];
    } else {
      state.examples[operation.id] = {
        ...(Object.keys(example).length ? { example } : {}),
        ...(Object.keys(expectation).length ? { expectation } : {}),
      };
    }
    saveExamples();
    renderBaselineEditor();
    if (negative && !status) {
      toast("Saved. A negative test needs a status to assert, or there is nothing to check.");
    } else {
      toast("Saved for this operation.");
    }
  }

  function baselineFromRun() {
    const last = state.history[0];
    if (!last) {
      toast("Send a request on the Request tab first, then take it from there.");
      return;
    }
    $("baseline-url").value = last.url || "";
    if (last.request?.body !== undefined && last.request.body !== null) {
      $("baseline-body").value = stringify(last.request.body);
    }
    if (Number.isFinite(last.status)) $("baseline-status").value = String(last.status);
    toast("Taken from the last run. Review it, then save.");
  }

  function clearBaseline() {
    const operation = state.operation;
    if (!operation) return;
    delete state.examples[operation.id];
    saveExamples();
    for (const id of ["baseline-url", "baseline-body", "baseline-status", "baseline-contains"]) {
      $(id).value = "";
    }
    $("baseline-negative").checked = false;
    renderBaselineEditor();
  }

  /* ───────────────────── opening a saved audit ───────────────────── */

  // Reading an export has to tolerate one written by a different version:
  // fields this build has never heard of, and fields it expects that are not
  // there. Refusing to open a report is a worse failure than losing a field.
  function importAudit(text, filename) {
    let payload;
    try { payload = JSON.parse(text); }
    catch (error) { toast(`That file is not JSON: ${errorText(error)}`); return; }
    if (!payload || typeof payload !== "object" || !Array.isArray(payload.findings)) {
      toast("That file does not look like a Namazu audit export.");
      return;
    }
    const findings = payload.findings.filter((item) => item && typeof item === "object");
    state.audit = {
      findings: findings.map((item) => ({ ...item, key: findingKey(item) })),
      running: false, cancelled: false,
      done: payload.scope?.endpoints_audited || 0,
      total: payload.scope?.endpoints_in_scope || 0,
      requests: payload.scope?.requests_sent || 0,
      notes: Array.isArray(payload.notes) ? payload.notes.slice() : [],
      discovery: payload.scope?.surface_sweep || null,
      finding: null, log: [], logEntry: null, logTruncated: false, statuses: [],
      coverage: {}, baselines: [], replays: payload.replays || {},
      correlation: payload.duplicates || null,
      startedAt: payload.started_at || null,
      imported: { file: filename, exported_at: payload.exported_at || "" },
    };
    // Coverage written by this version comes back as a list; anything else is
    // left empty rather than guessed at, and the note says so.
    for (const entry of payload.coverage?.checks || []) {
      if (!entry || !entry.check) continue;
      state.audit.coverage[entry.check] = {
        check: entry.check, title: entry.title || entry.check, what: entry.what || "",
        states: entry.states || { [entry.state || "skipped"]: 1 },
        findings: entry.findings || 0,
        blockedOn: entry.blocked_on || [], reasons: entry.reasons || [],
        remediation: entry.remediation || "",
      };
    }
    for (const row of payload.coverage?.baselines || []) {
      if (row && typeof row === "object") state.audit.baselines.push(row);
    }
    const missing = [];
    if (!payload.coverage) missing.push("coverage");
    if (!payload.evidence_levels) missing.push("the evidence legend");
    if (missing.length) {
      state.audit.notes.push(
        `This export was written before Namazu recorded ${missing.join(" and ")}, so that part `
        + "of the report is not shown. Its findings are read as they were written, and any that "
        + "carry no evidence axes are classified from their check id rather than invented.");
    }
    const unknown = Object.keys(payload).filter((name) => !KNOWN_EXPORT_KEYS.has(name));
    if (unknown.length) {
      state.audit.notes.push(
        `This export carries fields this version does not recognise, which were kept out of the `
        + `way rather than discarded: ${unknown.join(", ")}.`);
    }

    activateSection("audit");
    showView("view-audit-report");
    $("export-audit").disabled = false;
    if ($("export-audit-top")) $("export-audit-top").disabled = false;
    renderSeverityBar();
    renderFindings();
    renderAuditReport();
    renderLog();
    auditProgress();
    toast(`Opened ${findings.length} finding(s) from ${filename}.`);
    announce(`Opened a saved audit with ${findings.length} findings.`);
  }

  const KNOWN_EXPORT_KEYS = new Set([
    "application", "export", "exported_at", "started_at", "api", "scope", "summary",
    "notes", "findings", "note", "coverage", "replays", "duplicates", "evidence_levels",
  ]);

  /* ───────────────────── evidence, coverage and replay ───────────────────── */

  // Wording for the four axes, kept here rather than taken from the server so
  // the page explains itself even when a finding was read from an export
  // written by a different version.
  const CATEGORY_LABEL = {
    security: "Security weakness",
    hardening: "Hardening concern",
    contract: "Contract defect",
    reliability: "Reliability defect",
    informational: "Informational observation",
  };
  const ORIGIN_LABEL = {
    "static-declaration": "Read from the specification",
    "runtime-observation": "Observed in a response",
    "external-report": "Reported by another tool",
  };
  const VERIFICATION_LABEL = {
    unverified: "Not verified",
    observed: "Observed once",
    reproduced: "Reproduced on replay",
    "impact-demonstrated": "Impact demonstrated",
  };
  const REPLAY_LABEL = {
    reproduced: "Reproduced",
    "not-reproduced": "Not reproduced",
    intermittent: "Intermittent",
    blocked: "Blocked",
    error: "Error",
  };
  const COVERAGE_LABEL = {
    completed: "Ran",
    blocked: "Blocked",
    skipped: "Not in this profile",
    inconclusive: "Inconclusive",
    "not-applicable": "Nothing to test",
    attempted: "Started",
  };

  function assessmentOf(item) { return item.assessment || {}; }

  // The chips under a finding's title. Deliberately four separate chips rather
  // than one line: the whole point is that these say different things and a
  // reader should not be able to collapse them into "how bad is it".
  function evidenceChips(item) {
    const row = el("div", "axes");
    const axis = (kind, text, title) => {
      if (!text) return;
      const chip = el("span", "axis", text);
      chip.dataset.kind = kind;
      if (title) chip.title = title;
      row.append(chip);
    };
    const assessment = assessmentOf(item);
    axis("category", CATEGORY_LABEL[assessment.category] || assessment.category,
      assessment.category_meaning);
    axis("origin", ORIGIN_LABEL[assessment.origin] || assessment.origin,
      assessment.origin_meaning);
    axis("verification", VERIFICATION_LABEL[assessment.verification] || assessment.verification,
      assessment.verification_meaning);
    return row.childElementCount ? row : null;
  }

  function evidenceCard(item) {
    const assessment = assessmentOf(item);
    if (!assessment.category) return null;
    const parts = [];
    if (assessment.confirmed_claim) {
      const claim = el("div", "claim");
      claim.append(el("div", "claim-label", `What “${item.confidence}” means here`),
        el("p", "prose", assessment.confirmed_claim));
      parts.push(claim);
    }
    const facts = el("dl", "facts");
    const rows = [
      ["Kind of defect", CATEGORY_LABEL[assessment.category] || assessment.category,
        assessment.category_meaning],
      ["Evidence came from", ORIGIN_LABEL[assessment.origin] || assessment.origin,
        assessment.origin_meaning],
      ["Taken as far as", VERIFICATION_LABEL[assessment.verification] || assessment.verification,
        assessment.verification_meaning],
    ];
    if (assessment.proposed_severity) {
      rows.push(["Severity", `${item.severity}, lowered from ${assessment.proposed_severity}`,
        assessment.severity_reason]);
    }
    if (assessment.severity_rule && assessment.severity_rule !== "as-assessed") {
      rows.push(["Severity rule", assessment.severity_rule, assessment.severity_reason]);
    }
    for (const entry of assessment.source_severity || []) {
      rows.push([`${entry.tool} rated it`,
        entry.confidence ? `${entry.severity} (confidence ${entry.confidence})` : entry.severity,
        "The other tool's own rating, kept as it was rather than overwritten."]);
    }
    if (assessment.mapping_basis) {
      rows.push(["Why this classification", assessment.mapping_basis, ""]);
    }
    for (const [label, value, note] of rows) {
      if (!value) continue;
      const row = el("div");
      const term = el("dt", "", label);
      if (note) term.title = note;
      row.append(term, el("dd", "", value));
      facts.append(row);
    }
    parts.push(facts);
    if (item.provenance?.length > 1) {
      parts.push(el("p", "hint", `Merged from ${item.provenance.length} sources: `
        + `${item.provenance.join(", ")}.`));
    }
    if (item.duplicate_of) {
      parts.push(el("p", "prose caution", `This may be the same defect as ${item.duplicate_of}. `
        + "The evidence on one side was not complete enough to be sure, so both are kept."));
    }
    return parts;
  }

  /* ── captured cases and replay ── */

  function caseBlock(item, aCase, index) {
    const wrap = el("div", "case");
    const head = el("div", "case-head");
    head.append(el("span", "case-label", aCase.label || `Case ${index + 1}`));
    const status = el("span", "chip");
    status.dataset.status = String(aCase.status || 0);
    status.textContent = aCase.status ? String(aCase.status) : (aCase.error || "no response");
    head.append(status);
    if (aCase.source && aCase.source !== "namazu") {
      head.append(el("span", "src", aCase.tool_version
        ? `${aCase.source} ${aCase.tool_version}` : aCase.source));
    }
    wrap.append(head);

    wrap.append(el("pre", "raw-http", `${aCase.method} ${aCase.url}`));
    const facts = el("dl", "facts tight");
    for (const [label, value] of [
      ["Sent as", aCase.identity_ref],
      ["Recorded", aCase.recorded_at],
      ["Response size", aCase.body_length ? `${aCase.body_length} characters` : ""],
      ["Correlation", Object.entries(aCase.correlation || {})
        .map(([name, value]) => `${name}: ${value}`).join(", ")],
      ["Seed", aCase.seed],
      ["Schema", aCase.schema_hash],
      ["Changes data", aCase.mutating ? "yes" : "no"],
    ]) {
      if (!value) continue;
      const row = el("div");
      row.append(el("dt", "", label), el("dd", "", String(value)));
      facts.append(row);
    }
    wrap.append(facts);
    if (aCase.body_excerpt) wrap.append(el("pre", "raw-http", aCase.body_excerpt));

    // Named gaps. A reader should never have to work out that something is
    // absent from the fact that it is absent.
    if (aCase.missing?.length) {
      const list = el("ul", "note-list");
      for (const note of aCase.missing) list.append(el("li", "", note));
      wrap.append(el("div", "case-missing-label", "Not captured"), list);
    }
    if (aCase.redacted?.length) {
      wrap.append(el("p", "hint", `Masked before recording: ${aCase.redacted.join(", ")}. `
        + "Replay resolves these from the identity configured on the Auth tab; the placeholder "
        + "is never sent as a credential."));
    }

    const key = `${item.key || item.id}|${index}`;
    const controls = el("div", "case-actions");
    const button = el("button", "ghost", "Replay");
    button.type = "button";
    button.addEventListener("click", () => replayCase(item, aCase, key, button, wrap));
    controls.append(button);
    const attempts = el("select", "mini");
    attempts.setAttribute("aria-label", "Replay attempts");
    for (const count of [1, 2, 3, 5]) {
      const option = el("option", "", `${count} attempt${count === 1 ? "" : "s"}`);
      option.value = String(count);
      if (count === 2) option.selected = true;
      attempts.append(option);
    }
    attempts.dataset.key = key;
    controls.append(attempts);
    if (aCase.mutating) {
      controls.append(el("span", "hint",
        "This case changes data, so replay needs Allow writes."));
    }
    wrap.append(controls);
    const outcome = el("div", "replay-outcome");
    outcome.dataset.key = key;
    if (state.audit.replays[key]) outcome.replaceChildren(replayView(state.audit.replays[key]));
    wrap.append(outcome);
    return wrap;
  }

  function replayView(result) {
    const box = el("div", "replay");
    const head = el("div", "replay-head");
    const verdict = el("span", "chip");
    verdict.dataset.replay = result.outcome;
    verdict.textContent = REPLAY_LABEL[result.outcome] || result.outcome;
    head.append(verdict);
    head.append(el("span", "hint",
      `${result.matched} of ${result.attempts} attempt${result.attempts === 1 ? "" : "s"} matched`));
    box.append(head);
    box.append(el("p", "prose", result.reason || ""));
    if (result.failed_assertions?.length) {
      const list = el("ul", "note-list");
      for (const note of result.failed_assertions) list.append(el("li", "", note));
      box.append(list);
    }
    // Said every time. A reproduced response is a fact about the target, not a
    // judgement about how serious it is.
    box.append(el("p", "hint", result.note || ""));
    return box;
  }

  async function replayCase(item, aCase, key, button, wrap) {
    const select = wrap.querySelector(`select[data-key="${CSS.escape(key)}"]`);
    const attempts = Number(select?.value || 2);
    let connection;
    try { connection = connectionPayload(); }
    catch (error) { toast(errorText(error)); return; }
    button.disabled = true;
    const original = button.textContent;
    button.textContent = "Replaying";
    try {
      const result = await api("/api/replay", {
        case: aCase,
        identities: { primary: renewableIdentity(connection.headers), secondary: identityB() },
        attempts,
        allow_mutating: connection.allow_mutating,
        ...routePayload(),
        timeout: connection.timeout,
      });
      state.audit.replays[key] = result;
      const target = wrap.querySelector(`.replay-outcome[data-key="${CSS.escape(key)}"]`);
      if (target) target.replaceChildren(replayView(result));
      // Replay can raise a finding to "reproduced", and nothing higher: it
      // establishes the behaviour, never its security impact.
      if (result.outcome === "reproduced") {
        const assessment = assessmentOf(item);
        if (assessment.verification === "observed" || assessment.verification === "unverified") {
          assessment.verification = "reproduced";
          assessment.verification_meaning = VERIFICATION_LABEL.reproduced;
          renderFindings();
        }
      }
      announce(`Replay ${result.outcome} after ${result.attempts} attempts.`);
    } catch (error) {
      toast(errorText(error));
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  }

  /* ── the coverage report ── */

  function coverageCard() {
    const held = Object.values(state.audit.coverage);
    if (!held.length) return null;
    const parts = [];
    const counts = {};
    for (const entry of held) {
      const name = coverageState(entry);
      counts[name] = (counts[name] || 0) + 1;
    }
    const tally = el("div", "cov-tally");
    for (const name of COVERAGE_ORDER) {
      if (!counts[name]) continue;
      const cell = el("div", "cov-cell");
      cell.dataset.state = name;
      cell.append(el("div", "v", String(counts[name])),
        el("div", "k", COVERAGE_LABEL[name] || name));
      tally.append(cell);
    }
    parts.push(tally);
    parts.push(el("p", "hint", "A check that ran and found nothing is shown as Ran, not as "
      + "passed. Nothing here is a statement that the target is sound."));

    const table = el("div", "cov-list");
    const order = [...held].sort((a, b) =>
      COVERAGE_ORDER.indexOf(coverageState(a)) - COVERAGE_ORDER.indexOf(coverageState(b))
      || a.title.localeCompare(b.title));
    for (const entry of order) {
      const name = coverageState(entry);
      const row = el("div", "cov-row");
      row.dataset.state = name;
      const label = el("div", "cov-name");
      label.append(el("span", "t", entry.title));
      if (entry.what) label.append(el("span", "w", entry.what));
      row.append(label);
      const right = el("div", "cov-right");
      const chip = el("span", "chip");
      chip.dataset.cov = name;
      chip.textContent = COVERAGE_LABEL[name] || name;
      right.append(chip);
      if (entry.findings) right.append(el("span", "n", `${entry.findings} found`));
      row.append(right);
      if (entry.reasons.length) {
        const why = el("div", "cov-why");
        why.append(el("p", "prose", entry.reasons[0]));
        if (entry.blockedOn.length) {
          why.append(el("p", "hint", `Affected: ${entry.blockedOn.slice(0, 6).join(", ")}`
            + (entry.blockedOn.length > 6 ? ` and ${entry.blockedOn.length - 6} more` : "")));
        }
        if (entry.remediation) why.append(el("p", "prose remedy", entry.remediation));
        row.append(why);
      }
      table.append(row);
    }
    parts.push(table);
    return parts;
  }

  function baselineCard() {
    const rows = state.audit.baselines;
    if (!rows.length) return null;
    const parts = [];
    const bad = rows.filter((row) => !row.usable);
    if (bad.length) {
      parts.push(el("p", "prose caution",
        `${bad.length} of ${rows.length} baseline requests did not establish a working request, `
        + "so the checks that depend on one are reported as blocked rather than clean."));
    }
    const list = el("div", "cov-list");
    for (const row of rows.slice(0, 40)) {
      const entry = el("div", "cov-row");
      entry.dataset.state = row.usable ? "completed" : "blocked";
      const label = el("div", "cov-name");
      label.append(el("span", "t", row.endpoint));
      label.append(el("span", "w", row.reason || ""));
      entry.append(label);
      const right = el("div", "cov-right");
      const chip = el("span", "chip");
      chip.dataset.cov = row.usable ? "completed" : "blocked";
      chip.textContent = row.outcome;
      right.append(chip);
      if (row.status) right.append(el("span", "n", String(row.status)));
      entry.append(right);
      if (!row.usable && row.remediation) {
        const why = el("div", "cov-why");
        why.append(el("p", "prose remedy", row.remediation));
        entry.append(why);
      }
      list.append(entry);
    }
    parts.push(list);
    return parts;
  }

  // Coverage is accumulated per endpoint rather than summed, because "blocked"
  // on one operation and "completed" on another are two different facts and a
  // single total would hide both. A check blocked anywhere is listed as
  // blocked, with every endpoint it was blocked on, because the reader needs
  // to know which routes were not covered rather than how many.
  function absorbCoverage(result, label) {
    if (result.baseline_verdict) {
      state.audit.baselines.push({
        endpoint: result.endpoint || label,
        outcome: result.baseline_outcome,
        status: result.baseline_status,
        reason: result.baseline_verdict.reason,
        remediation: result.baseline_verdict.remediation,
        usable: result.baseline_verdict.usable,
      });
    }
    for (const entry of result.coverage?.checks || []) {
      const held = state.audit.coverage[entry.check] || {
        check: entry.check, title: entry.title, what: entry.what,
        states: {}, findings: 0, blockedOn: [], reasons: [], remediation: "",
      };
      held.states[entry.state] = (held.states[entry.state] || 0) + 1;
      held.findings += entry.findings || 0;
      if (entry.state === "blocked" || entry.state === "inconclusive") {
        held.blockedOn.push(result.endpoint || label);
        if (entry.reason && !held.reasons.includes(entry.reason)) held.reasons.push(entry.reason);
        held.remediation = held.remediation || entry.remediation || "";
      }
      state.audit.coverage[entry.check] = held;
    }
  }

  const COVERAGE_ORDER = ["blocked", "inconclusive", "completed", "skipped", "not-applicable",
    "attempted"];

  // The worst state wins the label. A check completed on four endpoints and
  // blocked on a fifth has a gap, and reporting the majority state would bury
  // exactly the thing a reader needs.
  function coverageState(held) {
    for (const name of COVERAGE_ORDER) if (held.states[name]) return name;
    return "skipped";
  }

  function absorb(result, label) {
    state.audit.requests += result.requests_sent || 0;
    for (const note of result.notes || []) state.audit.notes.push(`${label}: ${note}`);
    absorbCoverage(result, label);
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
      identities: { primary: renewableIdentity(connection.headers), secondary: identityB() },
      allow_mutating: connection.allow_mutating,
      ...routePayload(),
      timeout: connection.timeout,
      concurrency: auditConcurrency(),
    };



    state.audit = {
      findings: [], running: true, cancelled: false, done: 0, total: operations.length,
      requests: 0, notes: [], discovery: null, finding: null,
      log: [], logEntry: null, logTruncated: false, statuses: [],
      coverage: {}, baselines: [], replays: {}, correlation: null,
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
          const saved = state.examples[op.id] || {};
          const result = await api("/api/audit", {
            ...payload, operation_id: op.id,
            ...(saved.example ? { example: saved.example } : {}),
            ...(saved.expectation ? { expectation: saved.expectation } : {}),
          });

          absorb(result, `${op.method} ${op.path}`);
          absorbLog(result, `${op.method} ${op.path}`);
          if (Number.isFinite(result.baseline_status)) state.audit.statuses.push(result.baseline_status);
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
    // After the finally block, so a tool failure cannot leave the audit itself
    // looking as though it is still running.
    if (!state.audit.cancelled) await runQueuedTools();
  }



  // Shipped inside every export. A severity is only arguable if the reader can
  // see the rules it came from.
  const EVIDENCE_LEVELS = {
    note: "Each finding carries four independent axes. Severity alone cannot distinguish a "
        + "confirmed reading of a specification from a confirmed security weakness.",
    category: CATEGORY_LABEL,
    origin: ORIGIN_LABEL,
    verification: VERIFICATION_LABEL,
    severity_rules: {
      "informational-is-info": "An observation that asserts no defect is not a severity.",
      "contract-defect-is-informational": "A disagreement between an implementation and its own "
        + "specification is a documentation defect until a security consequence is demonstrated.",
      "reliability-defect-is-low": "An unhandled path is a reliability defect until something is "
        + "shown to come of it.",
      "hardening-without-impact-is-medium": "A missing control with no demonstrated route to "
        + "abuse cannot outrank a weakness that was shown.",
      "static-declaration-is-low": "A specification states an intention, not behaviour.",
      "unreproduced-external-report-is-medium": "Another tool's unreproduced report is a lead; "
        + "Namazu did not re-send the request.",
      "critical-needs-demonstrated-impact": "Critical is reserved for a weakness whose "
        + "consequence was demonstrated.",
    },
    seeds: "Integers wider than 2**53-1, such as a schemathesis seed, are written as decimal "
         + "strings. A JSON number would be rounded by any JavaScript reader and would no "
         + "longer be the seed.",
  };

  function categoryTally(findings) {
    const out = {};
    for (const item of findings) {
      const name = assessmentOf(item).category || "unclassified";
      out[name] = (out[name] || 0) + 1;
    }
    return out;
  }

  function verificationTally(findings) {
    const out = {};
    for (const item of findings) {
      const name = assessmentOf(item).verification || "unknown";
      out[name] = (out[name] || 0) + 1;
    }
    return out;
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
      summary: { total: state.audit.findings.length, severity: severityTally(state.audit.findings),
                 category: categoryTally(state.audit.findings),
                 verification: verificationTally(state.audit.findings) },
      // What was tested and what was not, in the export rather than only on
      // screen. A report that lists three findings and does not say that forty
      // checks were blocked is the failure this whole structure exists to fix.
      coverage: {
        checks: Object.values(state.audit.coverage).map((entry) => ({
          check: entry.check, title: entry.title, what: entry.what,
          state: coverageState(entry), states: entry.states, findings: entry.findings,
          blocked_on: entry.blockedOn, reasons: entry.reasons,
          remediation: entry.remediation,
        })),
        baselines: state.audit.baselines,
        note: "A check shown as completed ran and reached a conclusion. It is not a statement "
            + "that the target is sound, and a blocked check is not one either.",
      },
      replays: state.audit.replays,
      duplicates: state.audit.correlation,
      notes: [...new Set(state.audit.notes)],
      findings: state.audit.findings.map(({ key, ...item }) => item),
      evidence_levels: EVIDENCE_LEVELS,
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
    $("oauth-redirect-uri").addEventListener("input", () => {
      prefs.write("oauth-redirect-uri", $("oauth-redirect-uri").value.trim());
      oauthVisible();
    });
    $("outbound-mode").addEventListener("change", renderOutboundMode);
    $("user-agent").addEventListener("change", () => {
      prefs.write("user-agent", $("user-agent").value.trim());
    });
    $("audit-concurrency").addEventListener("change", () => {
      describeConcurrency();
      prefs.write("audit-concurrency", $("audit-concurrency").value);
    });
    $("audit-profile").addEventListener("change", () => {
      describeConcurrency();

      prefs.write("audit-profile", auditProfile());
      updateProfileNote();
    });
    $("add-identity-b").addEventListener("click", () => { identityKv.addRow(); identityKv.focusLast(); });
    $("baseline-save").addEventListener("click", saveBaseline);
    $("baseline-from-run").addEventListener("click", baselineFromRun);
    $("baseline-clear").addEventListener("click", clearBaseline);
    $("import-audit").addEventListener("click", () => $("import-audit-file").click());
    $("import-audit-file").addEventListener("change", async (event) => {
      const file = event.target.files?.[0];
      if (!file) return;
      try { importAudit(await file.text(), file.name); }
      catch (error) { toast(`That file could not be read: ${errorText(error)}`); }
      // Cleared so choosing the same file again still fires a change event.
      event.target.value = "";
    });
    $("run-audit").addEventListener("click", runAudit);
    $("cancel-audit").addEventListener("click", () => {
      state.audit.cancelled = true;
      $("cancel-audit").disabled = true;
      $("cancel-audit").textContent = "Stopping…";
      announce("The audit will stop once the current endpoint finishes.");
    });
    $("tools-after-audit").checked = prefs.read("tools-after-audit", "") === "1";
    $("tools-after-audit").addEventListener("change", () => {
      prefs.write("tools-after-audit", $("tools-after-audit").checked ? "1" : "0");
      // Opening the block is what normally loads the list; ticking the box
      // without opening it would otherwise run tools never shown as available.
      if ($("tools-after-audit").checked && !$("second-opinion-block").dataset.loaded) {
        $("second-opinion-block").dataset.loaded = "1";
        loadTools();
      }
    });
    $("second-opinion-block").addEventListener("toggle", (event) => {
      if (event.target.open && !event.target.dataset.loaded) {
        event.target.dataset.loaded = "1";
        loadTools();
      }
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

  // refreshToken is kept so a long audit can renew server-side without
  // reopening the browser flow. Which identity a token belongs to is passed to
  // applyToken as an argument rather than parked here.
  const oauthState = { token: null, pollTimer: 0, window: null, refreshToken: "" };



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
    const chosen = $("oauth-redirect-uri").value.trim() || `${location.origin}/oauth/callback`;
    $("oauth-redirect-field").hidden = grant !== "authorization_code";
    $("oauth-redirect-uri").placeholder = `${location.origin}/oauth/callback`;
    $("oauth-redirect-note").textContent = grant === "authorization_code"
      ? `Register ${chosen} for this client. Namazu opens the authorization page in a new tab and `
        + "collects the code when the browser comes back, so this has to be a URL that reaches "
        + "Namazu. If the authorization page answers with a block page from a security service, "
        + "the redirect URI is the usual cause: an http:// URL containing “localhost” "
        + "inside a query parameter matches a common WAF rule. Try the same port on 127.0.0.1, "
        + "registering that form too."
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
      ...routePayload(),
      timeout: Number($("request-timeout").value) || 15,
      redirect_uri: $("oauth-redirect-uri").value.trim() || null,
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
    // Kept so a long audit renews server-side instead of carrying a snapshot
    // that lapses partway through. Scoped to the primary identity on purpose:
    // the second identity is a different account, and its refresh token must
    // never end up minting tokens for the first.
    if (target !== "secondary" && token.refresh_token) {
      oauthState.refreshToken = token.refresh_token;
    }

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
    // Substituting code + PKCE for a documented implicit flow is the right
    // thing to try and a bad thing to do quietly. A client registered for
    // implicit usually permits no other grant and lists only the redirect URI
    // of the page it was built for, so the substituted request is refused and
    // the refusal looks like anything but a swapped grant.
    if (preset.implicit) {
      const uri = $("oauth-redirect-uri").value.trim() || `${location.origin}/oauth/callback`;
      oauthStatus(
        "This scheme documents the implicit flow, which Namazu does not send. It will request "
        + "authorization code + PKCE instead. That reaches a token only if this client also "
        + `permits the code grant and lists ${uri} among its registered redirect URIs. A client `
        + "registered for implicit alone will refuse the request, and the refusal can arrive as a "
        + "login page or a block page rather than an OAuth error. To test the client as it stands, "
        + "authorise in the API's own documentation page and paste the access token under Bearer "
        + "token.");
    } else {
      oauthStatus("");
    }
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
        const dropped = headerKv.fromText($("header-bulk").value);
        $("header-bulk-wrap").hidden = true;
        $("bulk-headers").focus();
        toast(dropped.length
          ? `Headers updated. Namazu sets ${[...new Set(dropped)].join(", ")} itself, so those lines were left out.`
          : "Headers updated.");
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
    $("audit-concurrency").value = prefs.read("audit-concurrency", "");
    $("user-agent").value = prefs.read("user-agent", "");
    $("outbound-mode").value = prefs.read("outbound-mode", "announced") === "quiet"
      ? "quiet" : "announced";
    renderOutboundMode();
    $("oauth-redirect-uri").value = prefs.read("oauth-redirect-uri", "");
    describeConcurrency();

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
    wireAccess();
    wireOauth();
    wireLog();
    $("spec-url").focus();
  }



  start();
})();

