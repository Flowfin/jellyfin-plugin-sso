// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * The clickable part of the stage-0 mock (#1526).
 *
 * WHY THE FIELDS ARE RENDERED AND NOT TYPED. The mock has to show that every
 * control of today's page has a home, and a hand-typed copy of 123 controls
 * drifts against the page the first time one is added. Each container names a
 * tab and an accordion and is filled from fields.js, which
 * tools/ui-mock-fields.js reconciles against the page - so a field that moved
 * appears here or fails that check, and cannot do neither.
 *
 * WHY A CONTROL IS LABELLED BY ITS ID. The label text of the real page is
 * rewritten by stage 1 and translated by stage 3, so copying it here would
 * create a second copy to keep in step for no gain. The id is what FIELDS.md
 * reconciles on, it is shown beside a readable form of itself, and neither can
 * drift from the other because both are derived from the same string.
 */

"use strict";

(function () {
  var TABS = [
    { name: "Overview", href: "overview.html" },
    { name: "Providers", href: "providers.html" },
    { name: "Accounts", href: "accounts.html" },
    { name: "Policies", href: "policies.html" },
    { name: "Server", href: "server.html" },
  ];

  /** A readable form of a control id, derived rather than re-typed. */
  function readable(id) {
    var s = id
      .replace(/^saml-/, "")
      .replace(/^profile-/, "")
      .replace(/^Tmpl-/, "")
      .replace(/^Oid/, "")
      .replace(/^Saml/, "");
    s = s.replace(/[-_]/g, " ");
    s = s.replace(/([a-z0-9])([A-Z])/g, "$1 $2");
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function control(field) {
    if (field.type === "checkbox") return el("input");
    if (field.type === "select") return el("select");
    if (field.type === "textarea") return el("textarea");
    var i = el("input");
    i.type = field.type === "file" ? "file" : field.type;
    return i;
  }

  /* The tab strip, in the markup the dashboard builds for its own sections. */
  function renderTabs(here) {
    var host = document.querySelector(".sso-mock-tabs");
    if (!host) return;
    var tabs = el("div", "tabs-viewmenubar");
    tabs.setAttribute("is", "emby-tabs");
    var slider = el("div", "emby-tabs-slider");
    slider.style.whiteSpace = "nowrap";
    TABS.forEach(function (t, i) {
      var a = el("a", "emby-tab-button");
      a.setAttribute("is", "emby-linkbutton");
      a.setAttribute("data-index", String(i));
      a.href = t.href;
      if (t.href === here) a.setAttribute("aria-current", "page");
      a.appendChild(el("div", "emby-button-foreground", t.name));
      slider.appendChild(a);
    });
    tabs.appendChild(slider);
    host.appendChild(tabs);
  }

  function help(field) {
    if (field.note) return field.note;
    if (field.risk === "insecure")
      return "Marked insecure on the page today: it switches a defence off and is audited when it is on.";
    if (field.risk === "sensitive")
      return "Marked sensitive on the page today: it changes who ends up with an account.";
    return (
      'Moved here from "' + (field.block || "no block") + '" on the page today.'
    );
  }

  /* Fills every [data-mock-fields="Tab/Accordion"] from fields.js. */
  function renderFields(protocol) {
    var all = window.SSO_MOCK_FIELDS || [];
    var placed = 0;
    var hosts = document.querySelectorAll("[data-mock-fields]");
    Array.prototype.forEach.call(hosts, function (host) {
      var parts = host.getAttribute("data-mock-fields").split("/");
      var wanted = all.filter(function (f) {
        return f.tab === parts[0] && f.accordion === parts[1];
      });
      if (protocol && parts[0] === "Providers") {
        wanted = wanted.filter(function (f) {
          return (f.id.indexOf("saml-") === 0 ? "SAML" : "OpenID") === protocol;
        });
      }
      host.textContent = "";
      if (!wanted.length) {
        host.appendChild(
          el(
            "p",
            "sso-mock-help",
            "This protocol carries no control under this heading.",
          ),
        );
        return;
      }
      wanted.forEach(function (f) {
        var wrap = el(
          "div",
          "sso-mock-field" +
            (f.type === "checkbox" ? " sso-mock-checkbox" : ""),
        );
        var label = el("label");
        var input = control(f);
        input.id = "mock-" + f.id;
        input.setAttribute("data-field", f.id);
        input.disabled = true;
        if (f.type === "checkbox") {
          label.appendChild(input);
          label.appendChild(el("span", "", readable(f.id)));
        } else {
          label.htmlFor = input.id;
          label.appendChild(document.createTextNode(readable(f.id)));
        }
        label.appendChild(el("span", "sso-mock-id", f.id));
        wrap.appendChild(label);
        if (f.type !== "checkbox") wrap.appendChild(input);
        wrap.appendChild(el("div", "sso-mock-help", help(f)));
        host.appendChild(wrap);
        placed += 1;
      });
    });
    var counter = document.querySelector("[data-mock-count]");
    if (counter) {
      counter.textContent =
        placed +
        " of " +
        all.length +
        " controls of the current page are on this screen; the rest are on the other tabs, and FIELDS.md says which.";
    }
  }

  function wireAccordions() {
    var groups = document.querySelectorAll("[data-mock-openall]");
    Array.prototype.forEach.call(groups, function (button) {
      button.addEventListener("click", function () {
        var open = button.getAttribute("data-open") !== "yes";
        button.setAttribute("data-open", open ? "yes" : "no");
        button.textContent = open
          ? "Collapse every section"
          : "Open every section";
        Array.prototype.forEach.call(
          document.querySelectorAll(".sso-mock-accordion"),
          function (d) {
            d.open = open;
          },
        );
      });
    });
  }

  /*
   * The protocol is also readable from the address, as `?protocol=SAML`, so the
   * SAML half of the editor is a link somebody can be sent rather than a click
   * they have to be told to make - and so a run that renders the page can reach
   * both halves.
   */
  function wireProtocol() {
    var picker = document.querySelector("[data-mock-protocol]");
    if (!picker) {
      renderFields(null);
      return;
    }
    var asked = /[?&]protocol=SAML/i.test(window.location.search)
      ? "SAML"
      : null;
    if (asked) picker.value = asked;
    var apply = function () {
      renderFields(picker.value);
    };
    picker.addEventListener("change", apply);
    apply();
  }

  function wireWizard() {
    var wizard = document.querySelector("[data-mock-wizard]");
    if (!wizard) return;
    var steps = wizard.querySelectorAll(".sso-mock-step");
    var panels = wizard.querySelectorAll("[data-mock-step-panel]");
    var at = 0;
    var show = function () {
      Array.prototype.forEach.call(steps, function (s, i) {
        if (i === at) s.setAttribute("aria-current", "step");
        else s.removeAttribute("aria-current");
        s.setAttribute("data-done", i < at ? "yes" : "no");
      });
      Array.prototype.forEach.call(panels, function (p, i) {
        p.classList.toggle("sso-mock-hidden", i !== at);
      });
    };
    Array.prototype.forEach.call(
      wizard.querySelectorAll("[data-mock-step-move]"),
      function (b) {
        b.addEventListener("click", function () {
          at = Math.min(
            panels.length - 1,
            Math.max(0, at + Number(b.getAttribute("data-mock-step-move"))),
          );
          show();
        });
      },
    );
    var opener = document.querySelector("[data-mock-wizard-open]");
    if (opener) {
      opener.addEventListener("click", function () {
        wizard.classList.remove("sso-mock-hidden");
        at = 0;
        show();
        wizard.scrollIntoView({ block: "start" });
      });
    }
    show();
  }

  /* The right column follows the focused field, which is the whole point of it. */
  function wireHelpRail() {
    var rail = document.querySelector("[data-mock-help-rail]");
    if (!rail) return;
    var idle = rail.textContent;
    document.addEventListener(
      "focusin",
      function (e) {
        var id = e.target.getAttribute && e.target.getAttribute("data-field");
        if (!id) return;
        var f = (window.SSO_MOCK_FIELDS || []).filter(function (x) {
          return x.id === id;
        })[0];
        rail.textContent = f ? readable(f.id) + " - " + help(f) : idle;
      },
      true,
    );
    document.addEventListener("mouseover", function (e) {
      var host = e.target.closest ? e.target.closest(".sso-mock-field") : null;
      if (!host) return;
      var input = host.querySelector("[data-field]");
      if (!input) return;
      var f = (window.SSO_MOCK_FIELDS || []).filter(function (x) {
        return x.id === input.getAttribute("data-field");
      })[0];
      if (f) rail.textContent = readable(f.id) + " - " + help(f);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    if (!window.ApiClient) document.body.classList.add("sso-mock-standalone");
    renderTabs(document.body.getAttribute("data-mock-page"));
    wireProtocol();
    wireAccordions();
    wireWizard();
    wireHelpRail();
  });
})();
