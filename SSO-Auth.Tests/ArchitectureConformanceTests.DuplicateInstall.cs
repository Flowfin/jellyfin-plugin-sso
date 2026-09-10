// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the refusal that stands while a second copy of this plugin is loaded (#1601).
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void TheDuplicateRefusalComesBeforeAnythingElseOnTheWritePath()
    {
        // The ordering IS the fix, and it is invisible from the two lines it separates. With two copies of
        // this plugin loaded, a configuration produced by the other copy is not this copy's
        // PluginConfiguration - the types have different identities - so PersistBase's type check does not
        // match it and hands it to the base class unchanged. That is the host write, and the host write is
        // what replaces the operator's providers with defaults. A refusal placed after the type check
        // therefore never runs on the one shape that does the damage.
        //
        // Measured on a live Jellyfin 12.0.0 with the published packages: SSO-Auth.xml went 3576 bytes with
        // a provider, to 601, to 38, over one downgrade and one upgrade.
        var source = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "SSOPlugin.cs"));

        var persist = source.IndexOf("private void PersistBase(BasePluginConfiguration configuration)", StringComparison.Ordinal);
        Assert.True(persist >= 0, "PersistBase is the single write path and this rule is written against it.");

        var refusal = source.IndexOf("if (LoadedMoreThanOnce)", persist, StringComparison.Ordinal);
        var typeCheck = source.IndexOf("if (configuration is not PluginConfiguration incoming)", persist, StringComparison.Ordinal);

        Assert.True(refusal >= 0, "PersistBase refuses to write while a second copy of this plugin is loaded (#1601).");
        Assert.True(typeCheck >= 0, "PersistBase still separates this plugin's configuration type from anything else.");
        Assert.True(
            refusal < typeCheck,
            "The duplicate-install refusal must come BEFORE the configuration type check in PersistBase "
            + "(#1601): a configuration from the other loaded copy fails that check and falls through to "
            + "the base class, which is the write that empties the file.");
    }

    [Fact]
    public void TheDuplicateCheckRunsBeforeTheConfigurationIsEverRead()
    {
        // The copy this check takes is only worth something while the file on disk is still the operator's.
        // The host overwrites it during its own lazy load of Configuration, so anything in this constructor
        // that reads Configuration before the check would hand back an already-emptied file to copy.
        // Asserted against the constructor text rather than by running it, because the failure is an
        // ordering a passing unit test would not notice.
        var source = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "SSOPlugin.cs"));

        var detect = source.IndexOf("DuplicateInstall.Detect(ConfigurationFilePath", StringComparison.Ordinal);
        var store = source.IndexOf("new ProviderConfigStore(() => Configuration", StringComparison.Ordinal);

        Assert.True(detect >= 0, "The constructor asks whether a second copy is loaded (#1601).");
        Assert.True(store >= 0, "The constructor still builds the provider config store over the live configuration.");
        Assert.True(
            detect < store,
            "The duplicate-install check runs before anything in the constructor reaches Configuration "
            + "(#1601), so the copy it takes is the file as the operator left it.");
    }
}
