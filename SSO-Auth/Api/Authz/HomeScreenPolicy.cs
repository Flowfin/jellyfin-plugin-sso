// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller;

namespace Jellyfin.Plugin.SSO_Auth.Api.Authz;

/// <summary>Seeds the web client's home-screen layout from a provisioning template onto a brand-new account (#1101), once, at creation.</summary>
/// <remarks>
/// The layout is written into the typed <see cref="DisplayPreferences.HomeSections"/> collection of the web
/// client's <c>usersettings</c> document, because the host lifts the <c>homesection</c> keys into that collection
/// on write and rebuilds them on read, so a row put into the custom bag would never be read. All
/// <see cref="SlotCount"/> slots are written with <see cref="HomeSectionType.None"/> in the rest, the way the
/// client's own settings page writes them. The caller writes it after the account row is persisted and isolates a
/// failure, so a layout can never fail a login; the user's later save adds rows beside the seeded ten and wins.
/// </remarks>
internal static class HomeScreenPolicy
{
    /// <summary>
    /// The client key the web client reads and writes its user settings under.
    /// </summary>
    internal const string WebClient = "emby";

    /// <summary>
    /// How many home-screen slots the web client renders and its settings page persists. A configured
    /// layout is padded to this length with <see cref="HomeSectionType.None"/> so it is the whole layout.
    /// </summary>
    internal const int SlotCount = 10;

    /// <summary>
    /// The item id of the web client's user-settings document. The server derives it from the literal
    /// <c>usersettings</c> with this same extension, so the two cannot come apart.
    /// </summary>
    internal static readonly Guid UserSettingsItemId = "usersettings".GetMD5();

    /// <summary>
    /// Whether the template names a home-screen layout at all. An absent or empty list names none, and a
    /// template naming none never reaches the store - not even for the read that would create the row.
    /// </summary>
    /// <param name="template">The template; <see langword="null"/> names nothing.</param>
    /// <returns>True when there is a layout to write.</returns>
    internal static bool NamesLayout(ProvisioningPolicyTemplate? template) => template?.HomeSections is { Count: > 0 };

    /// <summary>Parses a configured section list, refusing a name that is not a declared <see cref="HomeSectionType"/> member spelled exactly and a list longer than the web client has slots; one parse for the validator and the writer.</summary>
    /// <param name="names">The configured section names, top slot first.</param>
    /// <param name="sections">The parsed sections in order; empty when the list was refused.</param>
    /// <param name="refusedName">The first name that did not parse, or <see langword="null"/> when every name parsed, including when the list was refused for its length alone.</param>
    /// <returns>True when every name parsed and the list fits the slots.</returns>
    internal static bool TryParseHomeSections(IReadOnlyList<string?> names, out IReadOnlyList<HomeSectionType> sections, out string? refusedName)
    {
        ArgumentNullException.ThrowIfNull(names);

        var parsed = new List<HomeSectionType>(names.Count);
        sections = parsed;
        refusedName = null;
        if (names.Count > SlotCount)
        {
            return false;
        }

        foreach (var name in names)
        {
            // The same three checks the subtitle mode gets, for the same reasons: ignoreCase false so a
            // mis-cased spelling is reported rather than guessed at, IsDefined against a numeral that parses
            // to an undeclared value, and the name round-trip against a numeral that parses to a declared
            // one and would pin the layout to the ORDER upstream happens to declare the enum in.
            if (!Enum.TryParse(name, ignoreCase: false, out HomeSectionType section)
                || !Enum.IsDefined(section)
                || !string.Equals(section.ToString(), name, StringComparison.Ordinal))
            {
                parsed.Clear();
                refusedName = name ?? string.Empty;
                return false;
            }

            parsed.Add(section);
        }

        return true;
    }

    /// <summary>
    /// Writes the template's layout into the web client's user-settings document for a freshly created
    /// account. Writes nothing - and reads nothing, so no document comes into existence - when the
    /// template names no layout or names one the parse refuses (a configuration edited by hand around the
    /// validator); a partial layout is a layout nobody configured.
    /// </summary>
    /// <param name="store">The host's display-preferences store.</param>
    /// <param name="userId">The brand-new account.</param>
    /// <param name="template">The template resolved for the account; <see langword="null"/> writes nothing.</param>
    /// <returns>The number of configured sections written, so the caller can stay silent when there was nothing to do.</returns>
    internal static int ApplyAtProvisioning(IDisplayPreferencesManager store, Guid userId, ProvisioningPolicyTemplate? template)
    {
        ArgumentNullException.ThrowIfNull(store);

        if (template?.HomeSections is not { Count: > 0 } names || !TryParseHomeSections(names, out var sections, out _))
        {
            return 0;
        }

        // The store's read creates the document when the account has none yet, which a brand-new account
        // never has - the same read-modify-write the server's own controller performs for the client.
        var preferences = store.GetDisplayPreferences(userId, UserSettingsItemId, WebClient);
        preferences.HomeSections.Clear();
        for (var order = 0; order < SlotCount; order++)
        {
            preferences.HomeSections.Add(new HomeSection
            {
                Order = order,
                Type = order < sections.Count ? sections[order] : HomeSectionType.None,
            });
        }

        store.UpdateDisplayPreferences(preferences);
        return sections.Count;
    }
}
