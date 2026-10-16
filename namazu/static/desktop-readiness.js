/* Startup receipt for the native host. Only fixed diagnostics leave this page. */
(function (root) {
  "use strict";
  function create(window, document) {
    const codes = new Set(["none", "asset-load-failed", "script-error", "initialization-failed", "dependencies-missing", "styles-missing", "controls-unbound", "render-not-visible", "build-id-invalid"]);
    const requiredGlobals = ["NamazuSetup", "NamazuAuditResults", "NamazuAuditResultsView", "NamazuAssessmentView", "NamazuReadiness", "NamazuBruno", "NamazuBrunoImport", "NamazuIdentities", "NamazuWorkbench", "NamazuWorkspaces", "NamazuDesktopModel", "NamazuDesktopTesting", "NamazuDesktopHeader", "NamazuDesktop"];
    const styles = ["style.css", "setup.css", "results-ux.css", "bruno.css", "workspaces.css", "desktop-workbench.css", "desktop-header.css", "desktop-identities.css"];
    let initialized = false, painted = false, failure = "none";
    const element = id => document.getElementById(id);
    function buildId() {
      const value = document.querySelector('meta[name="namazu-build-id"]')?.content || "";
      return value === "source" || /^namazu-[a-f0-9]{24}$/.test(value) ? value : "invalid";
    }
    function visible(node, width = 1, height = 1) {
      if (!node || node.hidden || node.closest("[hidden]")) return false;
      const style = window.getComputedStyle(node), box = node.getBoundingClientRect();
      for (let parent = node.parentElement; parent; parent = parent.parentElement) {
        if (Number(window.getComputedStyle(parent).opacity) === 0) return false;
      }
      return style.display !== "none" && style.visibility === "visible" && Number(style.opacity) > 0
        && box.width >= width && box.height >= height && box.right > 0 && box.bottom > 0
        && box.left < window.innerWidth && box.top < window.innerHeight;
    }
    function reachable(node) {
      if (!visible(node, 12, 12) || node.disabled || node.closest("[inert]")) return false;
      const box = node.getBoundingClientRect(), hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
      return Boolean(hit && (hit === node || node.contains(hit)));
    }
    function stylesheet(name) {
      const link = document.querySelector(`link[rel="stylesheet"][href="/static/${name}"]`);
      try { return Boolean(link?.sheet?.cssRules?.length); } catch { return false; }
    }
    function snapshot() {
      const workbench = element("desktop-workbench"), toolbar = document.querySelector(".desktop-toolbar");
      const checks = {
        assets: styles.every(stylesheet),
        dependencies: requiredGlobals.every(name => Boolean(window[name])) && Boolean(window.NamazuWorkspaces?.instance),
        initialized,
        layout: visible(workbench, 240, 160) && visible(toolbar, 240, 28)
          && window.getComputedStyle(workbench).display === "grid" && window.getComputedStyle(toolbar).display === "flex",
        controls: ["desktop-home", "desktop-import", "desktop-menu-open"].every(id => {
          const node = element(id); return reachable(node) && typeof node.onclick === "function";
        }) && reachable(element("desktop-workspace")) && typeof element("desktop-workspace")?.onchange === "function",
        view: [...document.querySelectorAll(".desktop-main > section")].some(node => visible(node, 120, 80) && node.childElementCount > 0 && node.textContent.trim().length > 0),
      };
      const id = buildId();
      let code = failure;
      if (code === "none" && id === "invalid") code = "build-id-invalid";
      if (code === "none" && initialized) {
        if (!checks.dependencies) code = "dependencies-missing";
        else if (!checks.assets) code = "styles-missing";
        else if (!checks.layout || !checks.view) code = "render-not-visible";
        else if (!checks.controls) code = "controls-unbound";
      }
      return {version: 1, status: code !== "none" ? "failed" : initialized && painted ? "ready" : "loading", code, buildId: id, checks};
    }
    function fail(code) {
      if (failure === "none") failure = codes.has(code) && code !== "none" ? code : "initialization-failed";
      const workbench = element("desktop-workbench");
      if (workbench) { workbench.dataset.ready = "false"; workbench.inert = true; }
      return snapshot();
    }
    async function complete() {
      initialized = true;
      await new Promise(resolve => window.requestAnimationFrame(() => window.requestAnimationFrame(resolve)));
      painted = true;
      const result = snapshot();
      if (result.status !== "ready") { fail(result.code); throw Error("The workbench could not finish rendering. Reload Namazu to retry."); }
      return result;
    }
    window.addEventListener("error", event => {
      const target = event.target;
      if (target?.tagName === "SCRIPT" || target?.tagName === "LINK" && target.rel === "stylesheet") fail("asset-load-failed");
      else if (!painted) fail("script-error");
    }, true);
    window.addEventListener("unhandledrejection", () => { if (!painted) fail("script-error"); });
    return Object.freeze({snapshot, complete, fail});
  }
  if (typeof module !== "undefined" && module.exports) module.exports = {create};
  if (typeof document !== "undefined") Object.defineProperty(root, "NamazuStartup", {value: create(root, document), writable: false, configurable: false});
})(typeof window === "undefined" ? globalThis : window);
