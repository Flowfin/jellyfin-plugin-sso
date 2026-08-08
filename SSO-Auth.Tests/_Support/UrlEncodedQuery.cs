// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Reads one value out of an <c>application/x-www-form-urlencoded</c> sequence, for tests asserting on a
/// redirect URL the plugin built. It exists once so that two tests asserting on the same parameter cannot
/// be asserting under different decoding rules, which is what the nine hand-written copies of this loop
/// allowed (#1046): they disagreed about how the sequence was reached out of the URL, and about what an
/// absent name means.
///
/// The sequence is sliced by hand rather than through <see cref="Uri"/>, so a relative or otherwise
/// malformed redirect fails the assertion the test was written for instead of throwing inside the parse.
/// Nothing here folds <c>+</c> to a space: no call site parses a form body today, and a decoding rule that
/// no caller asks for is one a later caller can inherit by accident.
/// </summary>
internal static class UrlEncodedQuery
{
    /// <summary>
    /// Returns the value for <paramref name="name"/>, or <c>null</c> when the sequence carries no such name.
    /// </summary>
    internal static string? Find(string url, string name)
    {
        foreach (var pair in SequenceOf(url).Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq > 0 && pair[..eq] == name)
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        return null;
    }

    /// <summary>
    /// Returns the value for <paramref name="name"/>, and throws when the sequence carries no such name.
    /// </summary>
    internal static string Require(string url, string name) =>
        Find(url, name) ?? throw new InvalidOperationException($"Query parameter '{name}' not found in {url}.");

    // Everything after the first '?' and before any fragment. A string without a '?' is read as a bare
    // sequence, which is what a caller holding one already passes.
    private static string SequenceOf(string url)
    {
        var start = url.IndexOf('?') + 1;
        var fragment = url.IndexOf('#', start);
        return fragment < 0 ? url[start..] : url[start..fragment];
    }
}
