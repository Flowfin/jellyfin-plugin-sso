// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Text.Json;
using Jellyfin.Extensions.Json;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The account-link backup crosses a JSON boundary that no other test in this suite crosses. Every
/// <see cref="LinkImportTests"/> case hands <c>LinkImport.Apply</c> a document built in process, so the
/// importer's refusals are all proven against an object that never went over the wire - while the endpoint
/// an operator actually posts to receives one that did, bound by the host's serializer.
///
/// The two are not the same document. A get-only collection property is dropped by System.Text.Json, which
/// turns the restore into a success that restores nothing: HTTP 204, an audit line reading `0 link(s)
/// rebound`, and an empty link table on a server whose administrator has just been told the migration
/// worked. Silence is the whole danger here, so the property is pinned where the bytes are.
///
/// <para>
/// WHAT THIS BOUNDARY IS NOT is the endpoint's, and the difference is measured rather than assumed.
/// These cases deserialize with <c>JsonDefaults.Options</c>, which is where Jellyfin declares its
/// serializer defaults; the MVC input formatter the endpoint is actually bound by is configured FROM
/// those and is not identical to them. A member spelled <c>links</c> binds nothing here and binds fine at
/// the endpoint, read off a running 10.11.11 with this build installed - so the formatter is
/// case-insensitive where these options are not. The property below survives that difference, because a
/// property no serializer can assign is dropped by every one of them, and the endpoint behaviour itself
/// was verified against a real server rather than inferred from here.
/// </para>
/// </summary>
public class LinkExportDocumentJsonTests
{
    private static readonly Guid SourceBob = Guid.Parse("b0b00000-0000-0000-0000-000000000002");
    private static readonly Guid TargetBob = Guid.Parse("7a19e700-0000-0000-0000-00000000000b");

    /// <summary>
    /// The whole migration in one property: export on the source, send it as JSON exactly as the endpoint
    /// receives it, and restore on the target. Deleting the creation-handling attribute on
    /// <c>LinkExportDocument.Links</c> makes this fail with zero restored links.
    /// </summary>
    [Fact]
    public void ExportedDocument_SurvivesTheJsonBoundary_AndStillRestores()
    {
        var json = JsonSerializer.Serialize(LinkExport.Build(Source(), id => id == SourceBob ? "bob" : null), JsonDefaults.Options);

        var received = JsonSerializer.Deserialize<LinkExportDocument>(json, JsonDefaults.Options);

        Assert.NotNull(received);
        Assert.Single(received!.Links);

        var target = Target();
        LinkImport.Apply(target, received, username => username == "bob" ? TargetBob : null);

        Assert.Equal(TargetBob, target.OidConfigs["idp"].CanonicalLinks["sub-bob"]);
    }

    /// <summary>
    /// The refusals the operator documentation quotes are reachable only if the entries arrive. Before the
    /// fix this posted document produced HTTP 204 rather than the refusal, because the entry naming an
    /// account this instance does not hold was dropped before the importer ever saw it.
    /// </summary>
    [Fact]
    public void EntryNamingAnUnknownAccount_StillRefuses_AfterTheJsonBoundary()
    {
        const string Json = """
            {"FormatVersion":1,"Links":[{"Protocol":"OpenID","Provider":"idp","CanonicalName":"sub-bob","Username":"nobody"}]}
            """;

        var received = JsonSerializer.Deserialize<LinkExportDocument>(Json, JsonDefaults.Options);

        var refusal = Assert.Throws<ArgumentException>(() => LinkImport.Apply(Target(), received!, _ => null));
        Assert.Contains("no Jellyfin account is named 'nobody' on this instance", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A posted <c>"Links": null</c> means what an omitted member has always meant - nothing to restore -
    /// and never a null reference reaching the importer. The read-only shape with creation handling could
    /// not express this: System.Text.Json cannot assign null to a property it may only populate, and the
    /// throw escapes the input formatter as a 500, past the endpoint's own null check and rate limiter.
    /// </summary>
    [Fact]
    public void NullLinksMember_BindsToAnEmptyDocument_RatherThanThrowing()
    {
        var received = JsonSerializer.Deserialize<LinkExportDocument>("""{"FormatVersion":1,"Links":null}""", JsonDefaults.Options);

        Assert.NotNull(received);
        Assert.Empty(received!.Links);
    }

    /// <summary>
    /// A repeated member takes the LAST one, which is what `jq`, `JSON.parse` and every other reader an
    /// operator inspects a backup file with do. Populating a read-only collection appends instead, so what
    /// the operator reads and what the server applies would differ on a file carrying a hidden first array.
    /// </summary>
    [Fact]
    public void RepeatedLinksMember_TakesTheLastOne_AsEveryJsonReaderDoes()
    {
        const string Json = """
            {"FormatVersion":1,"Links":[{"Protocol":"OpenID","Provider":"idp","CanonicalName":"hidden","Username":"admin"}],"Links":[{"Protocol":"OpenID","Provider":"idp","CanonicalName":"sub-bob","Username":"bob"}]}
            """;

        var received = JsonSerializer.Deserialize<LinkExportDocument>(Json, JsonDefaults.Options);

        var only = Assert.Single(received!.Links);
        Assert.Equal("sub-bob", only.CanonicalName);
    }

    private static PluginConfiguration Source()
    {
        var configuration = new PluginConfiguration();
        var provider = new OidConfig { Enabled = true, OidEndpoint = "https://idp.example.test" };
        provider.CanonicalLinks["sub-bob"] = SourceBob;
        configuration.OidConfigs["idp"] = provider;
        return configuration;
    }

    private static PluginConfiguration Target()
    {
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["idp"] = new OidConfig { Enabled = true, OidEndpoint = "https://idp.example.test" };
        return configuration;
    }
}
