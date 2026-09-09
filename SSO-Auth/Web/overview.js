// The controller of the Overview page, and the one that carries the reasoning all five share (#1527).
// Every configuration page of this plugin is this same shape: load the core, hand it the view, say so if
// that does not work. Nothing else is in a page module - the behaviour is all in sso-core.js.
//
// WHY THE CORE ARRIVES THROUGH A DYNAMIC IMPORT AND NOT A STATIC ONE. Jellyfin serves a plugin's page
// script from its own URL base - `/web/ConfigurationPage?name=<registered name>` - so a relative
// specifier in a static import resolves against THAT url and asks the server for a file it does not have.
// There is no bundler in this tree to rewrite one either. ApiClient.getUrl builds the server-rooted URL
// including the deployment's base path, which is why the specifier is computed rather than written down.
// It is the same route, for the same reason, that the localization module has been loaded by since #913,
// and it answers 200 with a JavaScript content type, which is what an ES module import requires.
//
// WHY EACH PAGE REPEATS THESE LINES. Without a bundler there is no module the five could share them from
// - a shared loader would itself have to be imported, which is the very problem being solved. The four
// other modules carry the same shape and a pointer here rather than a second copy of this reasoning.
//
// The name below is part of the plugin's URL contract exactly as the page names in SSOPlugin.GetPages
// are: it is what the server matches on, and changing it here without changing it there breaks the load.
const SSO_CORE_PAGE = "SSO-Auth-core.js";

/**
 * The Overview page.
 *
 * @param {Element} view The page element Jellyfin hands the controller.
 */
export default function initSsoConfigurationPage(view) {
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
      .then((core) => core.pageControllers.overview(view))
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
