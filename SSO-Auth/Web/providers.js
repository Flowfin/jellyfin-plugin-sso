// The controller of the Providers page (#1527): both provider workspaces, their editors, the aggregate check and the readiness panel.
//
// The same shape as the other four and no behaviour of its own. Why the core arrives through a computed
// dynamic import, why the try and the catch cover different throws, and why these lines are repeated per
// page instead of shared are all written once, in overview.js.
const SSO_CORE_PAGE = "SSO-Auth-core.js";

/**
 * The Providers page.
 *
 * @param {Element} view The page element Jellyfin hands the controller.
 */
export default function initSsoProvidersPage(view) {
  // The try and the catch cover DIFFERENT throws and both are needed. ApiClient.getUrl throws
  // SYNCHRONOUSLY on a missing server address, while the argument is still being evaluated, so at that
  // moment no promise exists for a rejection handler to see - which is the same hazard the core's own
  // localize() documents and guards. The .catch covers the two asynchronous ones: an import that does not
  // arrive, and a controller that throws while it wires the page. That second one is why this is
  // .then(...).catch(...) and not .then(onOk, onFail): a rejection handler passed as the second argument
  // does not see a throw from the first, and a controller throwing mid-wiring is exactly the state the
  // notice exists for.
  try {
    import(ApiClient.getUrl("web/ConfigurationPage", { name: SSO_CORE_PAGE }))
      .then((core) => core.pageControllers.providers(view))
      .catch(() => reportDeadPage(view));
  } catch {
    reportDeadPage(view);
  }
}

/**
 * Says on the page itself that it did not finish loading.
 *
 * A fully rendered settings page whose controls do nothing is the worst state an administrator can be
 * handed: it looks like it works and silently discards what is typed into it. Built with createElement
 * and textContent (#221) rather than written into an element the markup was supposed to carry, so it
 * still appears on a page whose own markup is not what this expects.
 *
 * @param {Element} view The page element Jellyfin hands the controller.
 */
function reportDeadPage(view) {
  const notice = document.createElement("p");
  notice.classList.add("fieldDescription");
  notice.textContent =
    "This settings page could not finish loading, so its controls will not do anything and nothing typed into them would be saved. Reload the page; if it keeps happening the plugin's assets are not being served, and the server log will say why.";
  view.prepend(notice);
}
