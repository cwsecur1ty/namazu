/* Header navigation is shared; native commands exist only in the trusted desktop document. */
(function (root) {
  "use strict";
  const $ = id => document.getElementById(id);
  root.NamazuDesktopHeader = {
    create(host) {
      const menu = $("desktop-menu"), chooser = $("desktop-import-dialog");
      const compact = matchMedia("(max-width: 1180px)");
      let context = {}, timer, stopped = false, nativeTheme;
      const closeMenu = () => { if (menu.open) menu.close(); };
      function native(action) { if (root.NamazuNative?.version === 1) root.NamazuNative.invoke(action); }
      function nativeState() {
        const capability = root.NamazuNative?.version === 1;
        document.body.classList.toggle("desktop-native", capability);
        $("desktop-window-controls").hidden = !capability;
        $("desktop-native-menu").hidden = !capability;
        const state = root.NamazuNative?.state || {}, maximize = document.querySelector('[data-native-action="maximize"]');
        maximize.setAttribute("aria-label", state.maximized ? "Restore Namazu window" : "Maximise Namazu");
        maximize.title = state.maximized ? "Restore window" : "Maximise";
        maximize.firstElementChild.textContent = state.maximized ? "❐" : "□";
        $("desktop-native-diagnostic").hidden = !state.diagnostic;
        $("desktop-native-placement-warning").textContent = state.placementWarning || "";
        $("desktop-native-placement-warning").hidden = !state.placementWarning;
      }
      function arrange() {
        const destination = $(compact.matches ? "desktop-menu-context-slot" : "desktop-header-context-slot");
        destination.append($("desktop-header-context"));
      }
      function update(value) {
        context = value;
        $("desktop-workspace").title = value.workspace || "Open a workspace";
        $("desktop-environment").title = `Environment: ${value.environment || "Contract targets"}`;
        $("desktop-target").textContent = value.target || "No target selected";
        $("desktop-target").title = value.target ? `Active target: ${value.target}` : "Open a request to inspect its target";
        $("desktop-target").setAttribute("aria-label", $("desktop-target").title);
        $("desktop-identity").setAttribute("aria-label", `Identity: ${value.identity || "none"}. ${value.identitySource || "No identity configured"}`);
        $("desktop-menu-context-description").textContent = `${value.workspace || "No workspace selected"}\nEnvironment: ${value.environment || "Contract targets"}\nTarget: ${value.target || "not selected"}\nIdentity: ${value.identity || "none"} (${value.identitySource || "no identity configured"})`;
        $("desktop-theme").textContent = document.documentElement.dataset.theme === "light" ? "Use dark theme" : "Use light theme";
        const theme = document.documentElement.dataset.theme === "light" ? "theme-light" : "theme-dark";
        if (root.NamazuNative?.version === 1 && nativeTheme !== theme) { nativeTheme = theme; native(theme); }
      }
      async function poll() {
        if (stopped) return;
        try {
          const state = await host.api("/api/desktop/status", null, "GET");
          const active = state.active_runs + state.active_requests + (state.active_authentications || 0);
          const kind = state.stopping ? "stopping" : active ? "running" : state.interrupted ? "interrupted" : "ready";
          const label = kind === "running" ? `Running ${active}` : kind === "stopping" ? "Stopping" : kind === "interrupted" ? "Interrupted" : "Ready";
          $("desktop-execution-state").dataset.state = kind;
          $("desktop-execution-label").textContent = label;
          const detail = kind === "interrupted" ? "Interrupted evidence is retained. Nothing was replayed; open history to inspect it." : kind === "stopping" ? "New dispatch is stopping. Requests already in flight may still complete." : active ? `${state.active_runs} audits, ${state.active_requests} ordinary requests and ${state.active_authentications || 0} authentication actions active across this application.` : "Ready. No active requests.";
          $("desktop-execution-state").title = detail;
          $("desktop-execution-state").setAttribute("aria-label", `Execution state: ${label}. ${detail}`);
          $("desktop-stop-work").hidden = !active;
          $("desktop-stop-work").disabled = Boolean(state.stopping);
        } catch {
          $("desktop-execution-state").dataset.state = "disconnected";
          $("desktop-execution-label").textContent = "Disconnected";
          $("desktop-execution-state").title = "Local service unavailable. Current drafts remain in this window; request outcomes may be unknown.";
          $("desktop-execution-state").setAttribute("aria-label", $("desktop-execution-state").title);
        }
        if (!stopped) timer = setTimeout(poll, 2000);
      }
      function openImport() { closeMenu(); if (!chooser.open) chooser.showModal(); }
      $("desktop-menu-open").onclick = () => { if (!menu.open) menu.showModal(); };
      document.querySelectorAll("[data-close-dialog]").forEach(button => { button.onclick = () => $(button.dataset.closeDialog).close(); });
      document.querySelectorAll("[data-import-kind]").forEach(button => { button.onclick = () => { chooser.close(); host.guard(() => host.importKind(button.dataset.importKind)); }; });
      document.querySelectorAll("[data-native-action]").forEach(button => { button.onclick = () => native(button.dataset.nativeAction); });
      $("desktop-native-menu").onclick = () => { closeMenu(); native("menu"); };
      $("desktop-menu-settings").onclick = () => { closeMenu(); host.guard(() => host.settings()); };
      $("desktop-menu-workspace-close").onclick = () => { closeMenu(); host.guard(host.closeWorkspace); };
      $("desktop-target").onclick = () => { closeMenu(); host.guard(host.target); };
      $("desktop-execution-state").onclick = () => host.guard(host.history);
      $("desktop-stop-work").onclick = () => host.guard(async () => { await host.api("/api/desktop/stop", {}); clearTimeout(timer); await poll(); });
      $("desktop-stop-work").title = "Stop new dispatch for all active Namazu work; retain in-flight evidence";
      for (const id of ["desktop-environments", "desktop-theme", "desktop-sidebar-toggle", "desktop-identity", "desktop-environment"]) $(id).addEventListener(id === "desktop-environment" ? "change" : "click", closeMenu);
      compact.addEventListener("change", arrange);
      root.addEventListener("namazu-native-state", () => { nativeState(); update(context); });
      root.addEventListener("pagehide", () => { stopped = true; clearTimeout(timer); }, {once: true});
      arrange(); nativeState(); poll();
      return {update, openImport};
    },
  };
})(window);
