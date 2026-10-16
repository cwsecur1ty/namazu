/* Bruno source review uses the existing server parser. This view never executes requests. */
(function (root) {
  "use strict";
  const node = (tag, text, cls) => { const item = document.createElement(tag); if (text != null) item.textContent = text; if (cls) item.className = cls; return item; };
  root.NamazuBrunoImport = {
    create(host) {
      const panel = node("section", null, "bruno-import-flow"); panel.id = "bruno-import-flow";
      const steps = node("ol", null, "bruno-steps"); steps.setAttribute("aria-label", "Import progress");
      const choose = node("section"), review = node("section"), complete = node("section"), message = node("p", "Choose a local source. Nothing is sent to an API during import.", "hint");
      message.id = "bruno-source-status"; message.setAttribute("role", "status");
      const alert = node("p", "", "msg error"); alert.setAttribute("role", "alert"); alert.hidden = true;
      const state = {stage: "choose", job: null, pending: null, busy: false, epoch: 0, picks: new Map(), environments: new Map(), workspaceEnvironment: "", expanded: new Set(), limit: 160, query: "", issues: false, dirty: false, result: null, applied: null, nativePending: false};
      const action = (text, fn, cls = "btn") => { const button = node("button", text, cls); button.type = "button"; button.onclick = () => guard(fn); return button; };
      async function guard(fn) { alert.hidden = true; try { await fn(); } catch (error) { alert.textContent = error.message || "Import could not finish. Your workspace is unchanged."; alert.hidden = false; } }
      function busy(value) { state.busy = value; panel.setAttribute("aria-busy", String(value)); choose.inert = review.inert = value; cancel.hidden = !value; }
      function stage(value) { state.stage = value; render(); }
      const zip = node("input"), folder = node("input"), files = node("input");
      for (const input of [zip, folder, files]) { input.type = "file"; input.hidden = true; }
      zip.id = "bruno-source-zip"; zip.accept = ".zip"; folder.id = "bruno-source-folder"; folder.multiple = true; folder.setAttribute("webkitdirectory", "");
      files.id = "bruno-source-files"; files.accept = ".bru,.json,.yml,.yaml"; files.multiple = true;
      const options = node("div", null, "bruno-source-options");
      function pick(kind, input) {
        if (root.NamazuNative?.version === 1 && root.NamazuNative.invoke("pick-bruno-" + kind)) { state.nativePending = true; message.textContent = "Choose a local " + kind + " in the system dialog."; return; }
        input.click();
      }
      const folderButton = action("Open Bruno workspace or collection folder", () => pick("folder", folder)); folderButton.id = "bruno-choose-folder";
      const zipButton = action("Import Bruno workspace ZIP", () => pick("archive", zip)); zipButton.id = "bruno-choose-zip";
      options.append(folderButton, zipButton);
      choose.append(node("h3", "Choose your Bruno source"), node("p", "Use the existing folder, or export a workspace ZIP from Bruno. Review collections and environments before adding anything."), options);
      const secondary = node("div", null, "bruno-actions");
      secondary.append(action("Choose individual files", () => files.click()), action("Import CLI execution results", () => host.legacy("bruno-results")));
      const drop = node("div", "Drop a workspace ZIP or supported files here", "bruno-drop"); drop.tabIndex = 0; drop.setAttribute("role", "button"); drop.setAttribute("aria-label", "Choose or drop Bruno files");
      drop.onclick = () => files.click(); drop.onkeydown = event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); files.click(); } };
      drop.ondragover = event => { event.preventDefault(); drop.classList.add("dragging"); };
      drop.ondragleave = () => drop.classList.remove("dragging");
      drop.ondrop = event => { event.preventDefault(); drop.classList.remove("dragging"); guard(() => read(event.dataTransfer.files)); };
      const help = node("details", null, "bruno-export-help"); help.append(node("summary", "How to export a workspace from Bruno"));
      const instructions = node("ol"); for (const text of ["Open your workspace in Bruno.", "Open the top … menu and choose Export Workspace.", "Save the ZIP, then select or drop it here."]) instructions.append(node("li", text));
      const guide = node("a", "Official Bruno workspace export guide"); guide.href = "https://docs.usebruno.com/get-started/import-export-data/import-export-workspace"; guide.target = "_blank"; guide.rel = "noopener noreferrer";
      help.append(instructions, guide, node("p", "Exporting is optional when you have the original folder. A collection export contains request definitions; a CLI JSON report contains historical execution results. Environment secrets are masked and never become active credentials automatically."));
      choose.append(secondary, drop, help, zip, folder, files);
      const reviewTop = node("div", null, "bruno-review-top"), search = node("input"), onlyIssues = node("input"), issueLabel = node("label", "Show warnings only");
      search.type = "search"; search.id = "bruno-source-search"; search.placeholder = "Find a collection, folder or request"; search.setAttribute("aria-label", "Search import preview");
      search.oninput = () => { state.query = search.value; state.limit = 160; renderTree(); };
      onlyIssues.type = "checkbox"; onlyIssues.id = "bruno-source-issues"; onlyIssues.onchange = () => { state.issues = onlyIssues.checked; renderTree(); }; issueLabel.prepend(onlyIssues);
      reviewTop.append(search, issueLabel);
      const tree = node("div", null, "bruno-source-tree"); tree.id = "bruno-source-tree";
      const reviewSummary = node("p", "", "bruno-source-summary"), warningList = node("ul", null, "bruno-source-warnings"), metrics = node("p", "", "hint"); metrics.id = "bruno-source-timings";
      const globalBox = node("label", "Workspace environment", "bruno-source-settings"), globalEnvironment = node("select"); globalEnvironment.id = "bruno-workspace-environment"; globalEnvironment.setAttribute("aria-label", "Workspace environment"); globalBox.append(globalEnvironment);
      globalEnvironment.onchange = () => { state.workspaceEnvironment = globalEnvironment.value; changed(); };
      const reviewActions = node("div", null, "bruno-import-footer");
      const parse = action("Review selected collections", () => resolve()); parse.id = "bruno-source-review";
      const commit = action("Import reviewed selection", () => commitImport(), "btn primary"); commit.id = "bruno-source-import";
      reviewActions.append(action("Choose another source", () => stage("choose")), parse, commit);
      review.append(node("h3", "Review what will be imported"), reviewSummary, globalBox, reviewTop, warningList, tree, metrics, reviewActions);
      const cancel = action("Cancel import preparation", () => cancelJob()); cancel.id = "bruno-source-cancel"; cancel.hidden = true;
      panel.append(steps, message, alert, cancel, choose, review, complete);
      async function base64(file) {
        const bytes = new Uint8Array(await file.arrayBuffer()); let value = "";
        for (let offset = 0; offset < bytes.length; offset += 32768) value += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
        return btoa(value);
      }
      async function read(fileList) {
        const chosen = [...fileList]; if (!chosen.length) return;
        if (chosen.length === 1 && chosen[0].name.toLowerCase().endsWith(".zip")) {
          if (chosen[0].size > 16 * 1024 * 1024) throw Error("Choose a workspace ZIP up to 16 MiB.");
          return discover({zip_base64: await base64(chosen[0]), filename: chosen[0].name});
        }
        if (chosen.length === 1 && chosen[0].name.toLowerCase().endsWith(".json")) {
          const value = JSON.parse(await chosen[0].text());
          if (Array.isArray(value) && value.some(row => Array.isArray(row?.results) || row?.request || row?.response)) return host.report(chosen[0]);
        }
        const accepted = chosen.filter(file => /\.(bru|json|ya?ml)$/i.test(file.name));
        if (!accepted.length) throw Error("Choose a Bruno folder, workspace ZIP, .bru definitions or CLI JSON report.");
        if (accepted.length > 10000 || accepted.some(file => file.size > 256 * 1024) || accepted.reduce((sum, file) => sum + file.size, 0) > 32 * 1024 * 1024) throw Error("This source exceeds the local preview limits: 10,000 files, 256 KiB per definition and 32 MiB in total. Choose a smaller source.");
        const payload = await Promise.all(accepted.map(async file => ({path: file.webkitRelativePath || file.name, content: await file.text()})));
        return discover({files: payload});
      }
      for (const input of [zip, folder, files]) input.onchange = () => guard(async () => { const picked = [...input.files]; input.value = ""; await read(picked); });
      async function poll(jobId, terminal, epoch) {
        while (epoch === state.epoch) {
          const job = await host.api(`/api/bruno/sources/${encodeURIComponent(jobId)}`, null, "GET");
          if (epoch !== state.epoch) return null;
          state.pending = job;
          const progress = job.progress || {}; message.textContent = `${job.status}: ${progress.files_seen || 0} files, ${progress.collections || job.collections?.length || 0} collections, ${progress.parsed_collections || 0} parsed. No API requests sent.`;
          if (["failed", "cancelled"].includes(job.status)) {
            if (job.status === "failed" && state.job?.id === job.id) { state.job = job; state.dirty = true; render(); }
            throw Error(job.status === "cancelled" ? "Import preparation cancelled. Your workspace and drafts are unchanged." : (job.errors || []).map(value => typeof value === "string" ? value : value.message || value.code).join(" ") || "Source preparation failed. Choose another source or review its errors.");
          }
          if (terminal.includes(job.status)) return job;
          await new Promise(resolve => setTimeout(resolve, 180));
        }
        return null;
      }
      async function discover(payload) {
        const epoch = ++state.epoch; busy(true);
        try {
          const created = await host.api("/api/bruno/sources", payload);
          const identifier = created.id || created.job_id;
          if (epoch !== state.epoch) { await host.api(`/api/bruno/sources/${identifier}/cancel`, {}); return; }
          state.pending = {id: identifier};
          const job = await poll(identifier, ["discovered", "reviewed"], epoch);
          if (!job) return; adopt(job); stage("review");
        } finally { if (epoch === state.epoch) { state.pending = null; busy(false); } }
      }
      function adopt(job) {
        state.job = job; state.dirty = job.status !== "reviewed"; state.limit = 160; state.picks.clear(); state.environments.clear();
        state.workspaceEnvironment = job.workspace_environment || ""; state.expanded.clear();
        if (job.collections?.length === 1) state.expanded.add(job.collections[0].source_id);
        for (const collection of job.collections || []) {
          if (collection.selected !== false) state.picks.set(collection.source_id, collection.request_ids ? new Set(collection.request_ids) : null);
          state.environments.set(collection.source_id, collection.environment ?? (collection.environments?.length ? "__choose__" : ""));
        }
      }
      function selection() {
        return (state.job?.collections || []).filter(collection => state.picks.has(collection.source_id)).map(collection => {
          const environment = state.environments.get(collection.source_id) || "";
          if (environment === "__choose__") throw Error(`Choose an environment, or explicitly choose no environment, for ${collection.title}.`);
          const ids = state.picks.get(collection.source_id);
          return {source_id: collection.source_id, environment, ...(ids ? {request_ids: [...ids]} : {})};
        });
      }
      async function resolve() {
        const selections = selection(); if (!selections.length) throw Error("Select at least one collection or request.");
        const epoch = ++state.epoch; state.pending = {id: state.job.id}; busy(true);
        try {
          await host.api(`/api/bruno/sources/${state.job.id}/review`, {selections, workspace_environment: state.workspaceEnvironment});
          const job = await poll(state.job.id, ["reviewed"], epoch); if (!job) return;
          state.job = job; state.dirty = false; render();
        } finally { if (epoch === state.epoch) { state.pending = null; busy(false); } }
      }
      function changed() { state.dirty = true; commit.disabled = true; renderSummary(); }
      function selectedIds(collection) { const picked = state.picks.get(collection.source_id); return picked || new Set((collection.requests || []).map(row => row.id)); }
      function selectRows(collection, rows, checked) { const picked = new Set(state.picks.has(collection.source_id) ? selectedIds(collection) : []); for (const row of rows) checked ? picked.add(row.id) : picked.delete(row.id); if (picked.size) state.picks.set(collection.source_id, picked); else state.picks.delete(collection.source_id); changed(); renderTree(); }
      function renderSummary() {
        const selected = (state.job?.collections || []).filter(collection => state.picks.has(collection.source_id));
        const count = selected.reduce((sum, collection) => sum + (state.picks.get(collection.source_id)?.size ?? collection.request_count ?? collection.requests?.length ?? 0), 0);
        const destination = root.NamazuDesktop.identityContext?.().workspace?.title || "a new Namazu workspace";
        reviewSummary.textContent = `${selected.length} collections selected, ${count} request definitions. Destination: ${destination}. Imported credentials remain inactive. ${state.dirty ? "Review the current selection before importing." : "Review complete. Ready to import."}`;
        parse.disabled = !selected.length || state.job?.status === "completed"; commit.disabled = state.dirty || state.job?.status !== "reviewed" || !state.job?.review_id || !selected.length;
      }
      function renderTree() {
        const started = performance.now(), scroll = tree.scrollTop; tree.replaceChildren(); let shown = 0, matching = 0;
        const query = state.query.trim().toLowerCase();
        for (const collection of state.job?.collections || []) {
          const allRows = collection.requests || [], selected = state.picks.has(collection.source_id), picked = selectedIds(collection);
          const rows = allRows.filter(row => (!query || `${collection.title} ${row.folder || ""} ${row.name || ""} ${row.id} ${row.request?.method || ""} ${row.request?.url || ""}`.toLowerCase().includes(query)) && (!state.issues || row.blockers?.length || row.warnings?.length));
          if (query && !rows.length && !collection.title.toLowerCase().includes(query)) continue;
          const group = node("details", null, "bruno-source-collection"); group.dataset.sourceId = collection.source_id;
          group.open = state.expanded.has(collection.source_id) || Boolean(query);
          group.ontoggle = () => { if (group.isConnected) group.open ? state.expanded.add(collection.source_id) : state.expanded.delete(collection.source_id); };
          const header = node("summary"), check = node("input"); check.type = "checkbox"; check.checked = selected; check.indeterminate = selected && state.picks.get(collection.source_id)?.size < allRows.length;
          check.setAttribute("aria-label", `Select collection ${collection.title}`); check.onclick = event => event.stopPropagation();
          check.onchange = () => { if (check.checked) state.picks.set(collection.source_id, null); else state.picks.delete(collection.source_id); changed(); renderTree(); };
          header.append(check, node("strong", collection.title), node("span", `${collection.request_count ?? allRows.length} requests`, "hint")); group.append(header);
          const settings = node("div", null, "bruno-source-settings"), environment = node("select"); environment.setAttribute("aria-label", `Environment for ${collection.title}`);
          for (const [value, label] of [["__choose__", "Choose environment"], ["", "No environment"], ...(collection.environments || []).map(value => [typeof value === "string" ? value : value.name, typeof value === "string" ? value : value.name])]) { const option = node("option", label); option.value = value; environment.append(option); }
          environment.value = state.environments.get(collection.source_id) ?? ""; environment.onchange = () => { state.environments.set(collection.source_id, environment.value); changed(); };
          const envLabel = node("label", "Environment"); envLabel.append(environment);
          settings.append(envLabel, node("small", `${collection.format || "Bruno"} | ${collection.root || "Individual source files"}`)); group.append(settings);
          for (const warning of [...(collection.warnings || []), ...(collection.errors || [])]) group.append(node("p", typeof warning === "string" ? warning : warning.message || warning.code, "hint"));
          const folders = new Map();
          for (const row of rows) {
            matching++; if (shown >= state.limit) continue; shown++;
            let parent = group, path = "";
            for (const part of (row.folder || "").split("/").filter(Boolean)) {
              path += "/" + part;
              if (!folders.has(path)) {
                const folder = node("details", null, "bruno-source-folder"), folderKey = collection.source_id + path; folder.open = Boolean(query) || state.expanded.has(folderKey);
                folder.ontoggle = () => { if (folder.isConnected) folder.open ? state.expanded.add(folderKey) : state.expanded.delete(folderKey); };
                const summary = node("summary"), toggle = node("input"); toggle.type = "checkbox";
                const descendants = allRows.filter(item => ("/" + (item.folder || "") + "/").startsWith(path + "/"));
                toggle.checked = selected && descendants.every(item => picked.has(item.id)); toggle.indeterminate = selected && !toggle.checked && descendants.some(item => picked.has(item.id));
                toggle.setAttribute("aria-label", `Select folder ${collection.title}${path}`); toggle.onclick = event => event.stopPropagation(); toggle.onchange = () => selectRows(collection, descendants, toggle.checked);
                summary.append(toggle, node("span", part)); folder.append(summary); parent.append(folder); folders.set(path, folder);
              }
              parent = folders.get(path);
            }
            const item = node("div", null, "bruno-source-request"), toggle = node("input"); toggle.type = "checkbox"; toggle.checked = selected && picked.has(row.id); toggle.setAttribute("aria-label", `Select request ${row.name || row.id}`); toggle.onchange = () => selectRows(collection, [row], toggle.checked);
            const description = node("div"); description.append(node("span", row.request?.method || "HTTP", "desktop-method"), node("span", row.name || row.id));
            description.append(node("small", row.request?.url || row.id));
            if (row.authentication_mode && !["none", "inherit"].includes(row.authentication_mode)) description.append(node("small", `${row.authentication_mode} authentication requires explicit configuration.`));
            for (const warning of [...(row.blockers || []), ...(row.warnings || [])]) description.append(node("small", typeof warning === "string" ? warning : warning.message || warning.code, "bruno-row-warning"));
            const detail = node("details"); detail.append(node("summary", "Inspect definition")); detail.ontoggle = () => { if (detail.open && detail.childElementCount === 1) detail.append(node("pre", JSON.stringify(row, null, 2))); }; description.append(detail);
            item.append(toggle, description); parent.append(item);
          }
          if (!allRows.length) group.append(node("p", "Choose an environment and review this collection to inspect requests and resolve variables.", "hint"));
          tree.append(group);
        }
        if (!tree.childElementCount) tree.append(node("p", "No collections or requests match. Clear the search or warning filter.", "hint"));
        if (matching > shown) tree.append(action(`Show next ${Math.min(160, matching - shown)} of ${matching - shown} more requests`, () => { state.limit += 160; renderTree(); }));
        tree.scrollTop = scroll; panel.dataset.renderedRequests = String(shown); panel.dataset.previewRenderMs = String(Math.round(performance.now() - started)); renderSummary();
      }
      function render() {
        steps.replaceChildren(); for (const [value, label] of [["choose", "Choose source"], ["review", "Review selection"], ["complete", "Import"]]) { const item = node("li", label); item.setAttribute("aria-current", state.stage === value ? "step" : "false"); steps.append(item); }
        choose.hidden = state.stage !== "choose"; review.hidden = state.stage !== "review"; complete.hidden = state.stage !== "complete";
        if (state.stage === "review") {
          globalBox.hidden = !state.job?.workspace_environments?.length; globalEnvironment.replaceChildren();
          for (const value of ["", ...(state.job?.workspace_environments || [])]) { const name = typeof value === "string" ? value : value.name; const option = node("option", name || "No workspace environment"); option.value = name; globalEnvironment.append(option); }
          globalEnvironment.value = state.workspaceEnvironment;
          warningList.replaceChildren(...[...(state.job?.warnings || []), ...(state.job?.errors || [])].map(warning => node("li", typeof warning === "string" ? warning : warning.message || warning.code)));
          const times = state.job?.timings || {}; metrics.textContent = `Discovery ${Math.round(times.discovery_ms || 0)} ms. Parsing ${Math.round(times.parsing_ms || 0)} ms. Import ${Math.round(times.import_ms || 0)} ms. Preview renders at most ${state.limit} requests.`;
          renderTree();
        }
      }
      async function commitImport() {
        if (state.dirty || !state.job?.review_id) throw Error("Review the current selection before importing.");
        const epoch = ++state.epoch; state.pending = {id: state.job.id}; busy(true);
        try {
          const destination = await root.NamazuDesktop.brunoDestination(); if (epoch !== state.epoch) return;
          const response = await host.api(`/api/bruno/sources/${state.job.id}/import`, {workspace_id: destination.id, review_id: state.job.review_id});
          const job = response.status === "completed" ? response : await poll(state.job.id, ["completed"], epoch); if (!job) return;
          await finishImport(job);
        } finally { if (epoch === state.epoch) { state.pending = null; busy(false); } }
      }
      async function finishImport(job) {
          if (state.applied === job.id) return;
          state.applied = job.id; state.result = job.result || job; state.job = job; await root.NamazuDesktop.acceptBrunoSources(state.result);
          complete.replaceChildren(node("h3", "Import complete"), node("p", `${state.result.collection_ids?.length || 0} collections are in ${state.result.workspace?.title || "your Namazu workspace"}; ${state.result.duplicates?.length || 0} identical snapshots already present. Existing contracts, tabs, drafts and identities were retained. No requests were executed.`));
          const actions = node("div", null, "bruno-actions");
          actions.append(action("Open requests", () => { host.close(); return root.NamazuDesktop.openImportedRequests(state.result.collection_ids || []); }, "btn primary"),
            action("Choose environment", () => { host.close(); return root.NamazuDesktop.openEnvironments(); }),
            action("Configure authentication", () => { host.close(); return root.NamazuIdentities?.open(); }),
            action("Review unresolved inputs", () => { state.issues = true; onlyIssues.checked = true; stage("review"); }));
          complete.append(actions, action("Import another source", () => stage("choose"))); stage("complete");
          message.textContent = `Import finished in ${Math.round(job.timings?.import_ms || 0)} ms. Zero API requests sent.`;
      }
      async function cancelJob() {
        const pending = state.pending; state.epoch++;
        try {
          const cancelled = pending?.id ? await host.api(`/api/bruno/sources/${pending.id}/cancel`, {}) : null;
          if (cancelled?.status === "completed") { await finishImport(cancelled); return; }
          if (state.job?.id === pending?.id) { state.job.status = "cancelled"; state.job.review_id = null; state.dirty = true; stage("choose"); }
          message.textContent = "Import preparation cancelled. Existing workspace data is unchanged.";
        } finally { state.pending = null; busy(false); }
      }
      root.addEventListener("namazu-native-bruno-source", event => guard(async () => {
        if (event.detail?.version !== 1) return;
        const expected = state.nativePending; state.nativePending = false;
        if (!expected) { if (event.detail?.jobId) await host.api(`/api/bruno/sources/${encodeURIComponent(event.detail.jobId)}/cancel`, {}); return; }
        if (!event.detail?.jobId) { if (event.detail?.status === "cancelled") message.textContent = "Source selection cancelled."; else if (event.detail?.status === "failed") throw Error("The local source could not be opened. Choose another folder or ZIP."); return; }
        const epoch = ++state.epoch; state.pending = {id: event.detail.jobId}; busy(true);
        try { const job = await poll(event.detail.jobId, ["discovered", "reviewed"], epoch); if (job) { adopt(job); stage("review"); } } finally { if (epoch === state.epoch) { state.pending = null; busy(false); } }
      }));
      render();
      return {panel, open() { panel.hidden = false; render(); }, close() { state.nativePending = false; if (state.busy) guard(cancelJob); }, choose() { stage("choose"); }, state};
    },
  };
})(window);
