// The controller of the Overview page; all five page modules share this shape (#1527).
// The core is imported dynamically because Jellyfin serves page scripts from its own URL base, so a
// relative static import would miss; ApiClient.getUrl builds the server-rooted URL (#913).
// The name below must match the page name registered in SSOPlugin.GetPages.
const SSO_CORE_PAGE = "SSO-Auth-core.js";

/**
 * The Overview page.
 *
 * @param {Element} view The page element Jellyfin hands the controller.
 */
export default function initSsoConfigurationPage(view) {
  // getUrl can throw synchronously before any promise exists; the .catch covers a failed import and a controller throw.
  try {
    import(ApiClient.getUrl("web/ConfigurationPage", { name: SSO_CORE_PAGE }))
      .then((core) => core.pageControllers.overview(view))
      .catch(() => reportDeadPage(view));
  } catch {
    reportDeadPage(view);
  }
}

/**
 * Shows a notice on the page that it did not finish loading, built with createElement and textContent (#221).
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
