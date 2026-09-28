// The controller of the Accounts page (#1527): who is linked to which provider, and the account-link transfer pair.
// The same shape as the other page modules; the reasoning is written once, in overview.js.
const SSO_CORE_PAGE = "SSO-Auth-core.js";

/**
 * The Accounts page.
 *
 * @param {Element} view The page element Jellyfin hands the controller.
 */
export default function initSsoAccountsPage(view) {
  // getUrl can throw synchronously before any promise exists; the .catch covers a failed import and a controller throw.
  try {
    import(ApiClient.getUrl("web/ConfigurationPage", { name: SSO_CORE_PAGE }))
      .then((core) => core.pageControllers.accounts(view))
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
