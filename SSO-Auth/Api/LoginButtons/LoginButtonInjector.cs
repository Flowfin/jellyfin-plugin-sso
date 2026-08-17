// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;

/// <summary>
/// Pure string logic that renders the SSO "Sign in with …" buttons and splices them into Jellyfin's
/// login-page branding disclaimer (#722). No I/O - <see cref="LoginButtonManager"/> owns the read/write of
/// the server's <c>BrandingOptions.LoginDisclaimer</c>; this type only transforms strings, so it is
/// exhaustively unit-testable, which matters because the output is rendered into an anonymous, pre-auth page.
/// </summary>
/// <remarks>
/// SECURITY - this output is HTML rendered on the login page for every visitor, so it is an XSS sink. Every
/// interpolated value is <see cref="WebUtility.HtmlEncode(string)"/>d and every provider name placed in a URL
/// is additionally <see cref="Uri.EscapeDataString(string)"/>d; the markup is assembled only from a fixed
/// template plus those encoded values - no admin string is ever passed through as raw HTML. The managed block
/// is fenced between unique marker comments so <see cref="Merge"/> can replace or remove exactly its own
/// region and never disturb an admin's surrounding disclaimer content, idempotently.
/// </remarks>
public static class LoginButtonInjector
{
    /// <summary>
    /// What an opening fence is RECOGNISED by, and the whole of it. Everything after this token, up to and
    /// including the <c>--&gt;</c> that closes the comment on the same line, is prose the matcher does not
    /// read (#1344).
    ///
    /// That split is the point. The opener is written into every installation's login disclaimer and is found
    /// again by an exact search on the next sync, so any edit to the literal that is matched orphans every
    /// block already on disk: the plugin stops recognising its own region, appends a second one beside it, and
    /// no later action - not disabling the buttons, not reconfiguring them - can remove the first. That is
    /// what a typographic pass over this tree did to the parenthetical below, and it shipped. Recognising
    /// only this token makes the parenthetical safe to rewrite, and the token itself carries nothing a
    /// typographic pass looks for: the hyphens in <c>SSO-LOGIN-BUTTONS</c> are already plain ASCII, which is
    /// the direction such a pass converts TOWARDS rather than away from.
    /// </summary>
    internal const string BeginMarkerPrefix = "<!-- SSO-LOGIN-BUTTONS:BEGIN";

    /// <summary>
    /// The opening fence this version WRITES. Older installations carry a different spelling of the
    /// parenthetical and are recognised all the same, because recognition is
    /// <see cref="BeginMarkerPrefix"/> and never this constant.
    /// </summary>
    internal const string BeginMarker = BeginMarkerPrefix + " (managed by jellyfin-plugin-sso - do not edit inside) -->";

    /// <summary>The closing fence of the plugin-managed region.</summary>
    internal const string EndMarker = "<!-- SSO-LOGIN-BUTTONS:END -->";

    /// <summary>The three characters that close an HTML comment, and so an opening fence.</summary>
    private const string CommentClose = "-->";

    /// <summary>
    /// What each button carries as an inline <c>style</c>, and why an inline style rather than a stylesheet.
    /// </summary>
    /// <remarks>
    /// <para>
    /// JELLYFIN RESTYLES THIS ANCHOR AFTER THE PLUGIN HAS WRITTEN IT. The login controller takes every link in
    /// the disclaimer and adds its own classes at runtime
    /// (<c>src/apps/legacy/controllers/session/login/index.js</c>):
    /// </para>
    /// <code>
    /// for (const elem of loginDisclaimer.querySelectorAll('a')) {
    ///     elem.rel = 'noopener noreferrer';
    ///     elem.target = '_blank';
    ///     elem.classList.add('button-link');
    ///     elem.setAttribute('is', 'emby-linkbutton');
    /// }
    /// </code>
    /// <para>
    /// `button-link` and `emby-button` have the same specificity and `button-link` is declared later in
    /// `emby-button.scss`, so it wins. What it takes away is exactly what makes a button look like one:
    /// </para>
    /// <code>
    /// .emby-button       { padding: 0.9em 1em; }   /* line 1  */
    /// .emby-button.block { margin: 0.25em 0; }     /* line 78 */
    /// .button-link       { margin: 0; padding: 0; }/* line 47, later, so it wins */
    /// .button-link:hover { text-decoration: underline; }
    /// </code>
    /// <para>
    /// So the shipped button renders with no padding and underlines on hover, which is what discussion #1342
    /// reported and worked around with nine declarations of Custom CSS. An inline style beats any class rule
    /// that does not carry <c>!important</c>, in every state including <c>:hover</c>, so the four declarations
    /// below restore what the runtime class removed and nothing more.
    /// </para>
    /// <para>
    /// IT SURVIVES SANITISING, which is the reason this is possible at all. The disclaimer is rendered through
    /// markdown-it and then DOMPurify before it reaches the page, and `style` is in DOMPurify 2.5.9's default
    /// attribute allow-list (`src/attrs.js`, the `html` set). The plugin pins nothing here: if a future Jellyfin
    /// narrows that list, the attribute is dropped and the button falls back to today's appearance rather than
    /// to a broken one.
    /// </para>
    /// <para>
    /// WHAT IT DELIBERATELY DOES NOT DO is make the button full width. `.loginDisclaimerContainer` is
    /// `display: flex` and `.loginDisclaimer` is a flex item, so the region shrinks to its content and
    /// `.emby-button.block`'s `width: 100%` resolves against a width that came from the content. Widening it
    /// means restyling Jellyfin's own containers, which are outside this plugin's fence, and this plugin's
    /// promise is that it manages its own region and leaves an admin's page alone. The wiki carries the
    /// two-line snippet for admins who want it.
    /// </para>
    /// </remarks>
    internal const string ButtonStyle =
        "margin:0.25em 0;padding:0.9em 1em;text-decoration:none;color:inherit";

    /// <summary>
    /// Renders the managed button block, or the empty string when there are no buttons. The returned string,
    /// when non-empty, always begins with <see cref="BeginMarker"/> and ends with <see cref="EndMarker"/>.
    /// </summary>
    /// <param name="buttons">The buttons to render, in order.</param>
    /// <returns>The fenced HTML block, or an empty string when <paramref name="buttons"/> is empty.</returns>
    public static string BuildBlock(IReadOnlyList<LoginButton> buttons)
    {
        ArgumentNullException.ThrowIfNull(buttons);
        if (buttons.Count == 0)
        {
            return string.Empty;
        }

        var sb = new StringBuilder();
        sb.Append(BeginMarker).Append('\n');
        sb.Append("<div class=\"sso-login-buttons\">").Append('\n');
        foreach (var button in buttons)
        {
            // Route segment is a fixed literal chosen by the enum - never interpolated from input.
            var segment = button.Protocol == LoginButtonProtocol.Saml ? "SAML" : "OID";

            // The provider name in the href is URL-encoded (path segment). Provider names are already
            // validated to exclude URI-reserved and control characters (#336), but encode regardless so a
            // future relaxation cannot turn this into an injection or a broken link.
            var href = "/sso/" + segment + "/start/" + Uri.EscapeDataString(button.Name);

            // Both the href attribute value and the visible label are HTML-encoded, so a name/label such as
            // `"><script>…` renders as inert text, never markup. HtmlEncode also encodes the quotes that
            // would otherwise break out of the attribute.
            sb.Append("  <a class=\"raised block emby-button sso-login-button\" style=\"")
                .Append(ButtonStyle)
                .Append("\" href=\"")
                .Append(WebUtility.HtmlEncode(href))
                .Append("\">")
                .Append(WebUtility.HtmlEncode(button.Text))
                .Append("</a>")
                .Append('\n');
        }

        sb.Append("</div>").Append('\n');
        sb.Append(EndMarker);
        return sb.ToString();
    }

    /// <summary>
    /// Splices <paramref name="block"/> into <paramref name="existingDisclaimer"/> idempotently: the FIRST
    /// managed region is replaced, every further managed region is removed, when none is present the block is
    /// appended, and an empty <paramref name="block"/> removes them all. Content outside the fences - an
    /// admin's own disclaimer - is preserved, aside from the blank-line separator a managed region introduces,
    /// which is collapsed on removal so repeated enable/disable cycles cannot accumulate whitespace.
    ///
    /// Removing the extra regions rather than only the first is what repairs an installation that was already
    /// left holding two blocks by the orphaning described at <see cref="BeginMarkerPrefix"/>: it converges to
    /// exactly one on the next sync, and to none when the buttons are turned off, from any number of them.
    /// </summary>
    /// <param name="existingDisclaimer">The current login disclaimer (may be null/empty).</param>
    /// <param name="block">The managed block from <see cref="BuildBlock"/> (empty to remove the region).</param>
    /// <returns>The merged disclaimer.</returns>
    public static string Merge(string? existingDisclaimer, string block)
    {
        ArgumentNullException.ThrowIfNull(block);
        var current = existingDisclaimer ?? string.Empty;
        var regions = FindRegions(current);

        if (regions.Count == 0)
        {
            if (block.Length == 0)
            {
                return current;
            }

            // Append with a single blank-line separator only when there is prior content to separate from.
            return current.Length == 0 ? block : current.TrimEnd('\n') + "\n\n" + block;
        }

        // Last to first, so an earlier region's offsets are still valid when its turn comes. Only the first
        // region keeps a block; the rest are orphans and are spliced out.
        for (var i = regions.Count - 1; i > 0; i--)
        {
            current = Splice(current, regions[i], string.Empty);
        }

        return Splice(current, regions[0], block);
    }

    /// <summary>
    /// Every well-formed managed region in <paramref name="current"/>, in order, as (start, end-exclusive)
    /// character offsets spanning the opening fence through the closing one.
    ///
    /// What is recognised: an opening fence is <see cref="BeginMarkerPrefix"/> followed by the first
    /// <c>--&gt;</c> that occurs BEFORE the next newline, and a region is such an opener followed by
    /// <see cref="EndMarker"/> somewhere after it.
    ///
    /// What is not, and each for its own reason. The prefix with no comment close on its line is not an
    /// opener: the fences this type writes are whole lines, so a search that crossed one would let a
    /// hand-typed fragment swallow the real opener below it and take the admin's own content with it when the
    /// region was replaced. An opener with no closing fence after it is not a region: a partial fence is never
    /// parsed, so surrounding content cannot be corrupted, and a fresh block appends cleanly instead. And the
    /// closing fence is searched for only AFTER an opener, so a stray END that a hand-edited disclaimer placed
    /// ahead of one is ignored rather than making the region look malformed on every sync - which would
    /// re-append a block each time, and because a login's canonical-link write also raises the config-changed
    /// event, would grow the disclaimer without bound, once per login.
    /// </summary>
    /// <param name="current">The disclaimer to scan.</param>
    /// <returns>The regions found, in document order; empty when there are none.</returns>
    private static List<(int Start, int End)> FindRegions(string current)
    {
        var regions = new List<(int Start, int End)>();
        var from = 0;

        while (from < current.Length)
        {
            var begin = current.IndexOf(BeginMarkerPrefix, from, StringComparison.Ordinal);
            if (begin < 0)
            {
                break;
            }

            var afterPrefix = begin + BeginMarkerPrefix.Length;
            var close = current.IndexOf(CommentClose, afterPrefix, StringComparison.Ordinal);
            var newline = current.IndexOf('\n', afterPrefix);
            if (close < 0 || (newline >= 0 && newline < close))
            {
                from = afterPrefix;
                continue;
            }

            var openerEnd = close + CommentClose.Length;
            var end = current.IndexOf(EndMarker, openerEnd, StringComparison.Ordinal);
            if (end < 0)
            {
                from = afterPrefix;
                continue;
            }

            var regionEnd = end + EndMarker.Length;
            regions.Add((begin, regionEnd));
            from = regionEnd;
        }

        return regions;
    }

    // Replaces one region's characters with a replacement, healing the seam when the replacement is empty:
    // the blank-line separator the insert introduced is collapsed, so repeated enable/disable cycles do not
    // accumulate whitespace, and a now-trailing gap is trimmed.
    private static string Splice(string current, (int Start, int End) region, string replacement)
    {
        var before = current[..region.Start];
        var after = current[region.End..];

        if (replacement.Length != 0)
        {
            return before + replacement + after;
        }

        var healed = before.TrimEnd('\n');
        var tail = after.TrimStart('\n');
        if (healed.Length == 0)
        {
            return tail;
        }

        return tail.Length == 0 ? healed : healed + "\n\n" + tail;
    }
}
