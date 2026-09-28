// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;

/// <summary>Pure string logic that renders the SSO sign-in buttons and splices them into Jellyfin's login-page branding disclaimer (#722); <see cref="LoginButtonManager"/> owns the I/O.</summary>
/// <remarks>The output is HTML rendered on the anonymous login page, so it is an XSS sink: every interpolated value is HTML-encoded, every provider name placed in a URL is additionally URL-escaped, and the markup is assembled only from a fixed template. The managed block is fenced between unique marker comments so <see cref="Merge"/> replaces or removes exactly its own region.</remarks>
public static class LoginButtonInjector
{
    /// <summary>What an opening fence is recognised by, and the whole of it; everything after this token up to the closing <c>--&gt;</c> on the same line is prose the matcher does not read (#1344).</summary>
    /// <remarks>The opener is found again by exact search on every sync, so an edit to the matched literal orphans every block already on disk, which a typographic pass once did; recognising only this ASCII token makes the rest safe to rewrite.</remarks>
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

    /// <summary>What each button carries as an inline <c>style</c>, restoring the padding and margin Jellyfin's runtime <c>button-link</c> class removes from every disclaimer link.</summary>
    /// <remarks>
    /// The login controller adds <c>button-link</c> to every anchor in the disclaimer after the plugin has written
    /// it, and that class wins over <c>emby-button</c>, leaving no padding and an underline on hover (#1342). An
    /// inline style beats any class rule without <c>!important</c>, survives DOMPurify's default allow-list, and
    /// falls back to today's appearance if a future host drops the attribute. It does not make the button full
    /// width, because that would restyle Jellyfin's own containers outside this plugin's fence:
    /// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#recipe-make-the-sso-buttons-full-width"/>.
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

    /// <summary>Splices <paramref name="block"/> into <paramref name="existingDisclaimer"/> idempotently: the first managed region is replaced, every further one is removed, none present appends the block, and an empty block removes them all.</summary>
    /// <remarks>Content outside the fences is preserved apart from the blank-line separator, which is collapsed on removal so repeated cycles cannot accumulate whitespace; removing the extra regions repairs an installation the orphaning at <see cref="BeginMarkerPrefix"/> left holding two.</remarks>
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

    /// <summary>Every well-formed managed region in <paramref name="current"/>, in order, as character offsets spanning the opening fence through the closing one.</summary>
    /// <remarks>
    /// An opener is <see cref="BeginMarkerPrefix"/> followed by the first <c>--&gt;</c> before the next newline,
    /// and a region is an opener followed by <see cref="EndMarker"/> after it. A prefix with no close on its line,
    /// an opener with no closing fence, and a stray END ahead of any opener are each ignored, so a hand-typed
    /// fragment cannot swallow the admin's content or make every sync re-append a block, which a login's
    /// canonical-link write would repeat without bound.
    /// </remarks>
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
