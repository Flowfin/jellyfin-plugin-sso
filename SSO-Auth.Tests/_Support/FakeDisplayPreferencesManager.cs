// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// An in-memory <see cref="IDisplayPreferencesManager"/> for the home-screen seed (#1101). It keeps one
/// document per (user, item, client) the way the host does - the read creates the document when there is
/// none - and counts its calls, so a test can say the store was never touched, which is a claim a
/// substitute answering defaults cannot make. The members the seed never calls throw rather than answer,
/// so a caller that strays onto them is reported instead of being fed an empty answer.
/// </summary>
internal sealed class FakeDisplayPreferencesManager : IDisplayPreferencesManager
{
    private readonly Dictionary<(Guid UserId, Guid ItemId, string Client), DisplayPreferences> _documents = new();

    /// <summary>Gets every document the store holds, by the key the host keys them under.</summary>
    internal IReadOnlyDictionary<(Guid UserId, Guid ItemId, string Client), DisplayPreferences> Documents => _documents;

    /// <summary>Gets how many times a document was read (and created when absent).</summary>
    internal int Reads { get; private set; }

    /// <summary>Gets how many times a document was written back.</summary>
    internal int Updates { get; private set; }

    /// <summary>Gets or sets the exception every member throws, standing in for a store that is down.</summary>
    internal Exception? Failure { get; set; }

    public DisplayPreferences GetDisplayPreferences(Guid userId, Guid itemId, string client)
    {
        FailIfDown();
        Reads++;
        var key = (userId, itemId, client);
        if (!_documents.TryGetValue(key, out var document))
        {
            document = new DisplayPreferences(userId, itemId, client);
            _documents[key] = document;
        }

        return document;
    }

    public void UpdateDisplayPreferences(DisplayPreferences displayPreferences)
    {
        FailIfDown();
        Updates++;
        _documents[(displayPreferences.UserId, displayPreferences.ItemId, displayPreferences.Client)] = displayPreferences;
    }

    public ItemDisplayPreferences GetItemDisplayPreferences(Guid userId, Guid itemId, string client) => throw OffThePath();

    public IList<ItemDisplayPreferences> ListItemDisplayPreferences(Guid userId, string client) => throw OffThePath();

    public Dictionary<string, string?> ListCustomItemDisplayPreferences(Guid userId, Guid itemId, string client) => throw OffThePath();

    public void SetCustomItemDisplayPreferences(Guid userId, Guid itemId, string client, Dictionary<string, string?> customPreferences) => throw OffThePath();

    public void UpdateItemDisplayPreferences(ItemDisplayPreferences itemDisplayPreferences) => throw OffThePath();

    private static NotSupportedException OffThePath()
        => new("The home-screen seed reads and updates the user-settings document and nothing else; a call here is a caller off that path.");

    private void FailIfDown()
    {
        if (Failure is not null)
        {
            throw Failure;
        }
    }
}
