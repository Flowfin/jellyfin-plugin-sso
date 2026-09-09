// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// #1566. The record-marker substitution (#1557) is right about foreign values and wrong about the plugin's
/// own sentences: applied to a whole composed message it rewrites the plugin's words alongside the
/// identity provider's. These rows pin both directions - the composed refusal keeps the plugin's brackets,
/// and the value that carried no sanitizer at all now carries both.
/// </summary>
[Collection("SSOController")]
public class ComposedRefusalNotRewrittenTests
{
    private const string Marker = "[SSO Audit] ";

    [Fact]
    public async Task TheLinkImportRefusal_KeepsThePluginsOwnBrackets_InTheLogAndInTheAnswer()
    {
        // The refusal the operator reads carries the validator's own list of the characters a provider name
        // may not contain, and that list OPENS with the bracket a substitution over the whole message would
        // take out of it. Before this the log said one thing and the 400 body said another about the same
        // refusal, and the log was the one that was wrong.
        // An issuer long enough to be truncated is what puts the plugin's own bracketed marker into the
        // message: the configured-issuer refusal bounds what it echoes and joins its own "[truncated]" on.
        var overlong = "https://not-this-provider.example.test/" + new string('z', 300);
        var harness = new SsoControllerHarness(c => c.OidConfigs["idp"] = new OidConfig
        {
            Enabled = true,
            OidEndpoint = "https://idp.example.test",
        });
        harness.UserManager.GetUserByName("alice").Returns(TestUsers.Named("alice", Guid.Parse("77777777-7777-7777-7777-777777777777")));

        var answer = await harness.Controller.ImportLinks(new LinkExportDocument
        {
            FormatVersion = LinkExport.FormatVersion,
            Links = new Collection<LinkExportEntry>
            {
                new() { Protocol = "OpenID", Provider = "idp", CanonicalName = "sub-1", Username = "alice", Issuer = overlong },
            },
        }).ConfigureAwait(true);

        var body = Assert.IsType<string>(Assert.IsType<BadRequestObjectResult>(answer).Value);
        var logged = Assert.Single(
            harness.ControllerLog.Entries,
            e => e.Message.Contains("The account-link import was refused", StringComparison.Ordinal)).Message;

        // The two must agree, and the plugin's own bracketed marker must survive in both.
        Assert.Contains("[truncated]", body, StringComparison.Ordinal);
        Assert.Contains("[truncated]", logged, StringComparison.Ordinal);
        Assert.Contains(body, logged, StringComparison.Ordinal);
        Assert.DoesNotContain(Marker, logged, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheDefaultProviderLine_CarriesBothSanitizers()
    {
        // The line is written at every SSO login of an enforced account and carried neither sanitizer, so a
        // value written by a configuration import or a mounted declarative document could both split an
        // entry and plant a record. The conformance rule cannot see a value with no strip, which is why
        // this row exists rather than a rule change.
        const string Forged = "x\r\n[SSO Audit] Login succeeded: root via OpenID provider 'corp' (admin=True).";

        var log = new CapturingLogger();
        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        var user = TestUsers.Named("alice", Guid.Parse("66666666-6666-6666-6666-666666666666"));
        users.GetUserById(user.Id).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        var avatar = new Api.Avatar.AvatarService(
            users,
            Substitute.For<IProviderManager>(),
            Substitute.For<IServerConfigurationManager>(),
            new CapturingLogger(),
            Api.Net.SsoHttp.UserAgent);
        var minter = new SessionMinter(users, avatar, sessions, log);

        await minter.MintAsync(
            new SessionParameters
            {
                UserId = user.Id,
                IsAdmin = false,
                IsBreakGlassAdmin = false,
                EnableAuthorization = false,
                EnableAllFolders = true,
                EnabledFolders = Array.Empty<string>(),
                EnableLiveTv = false,
                EnableLiveTvManagement = false,
                PermissionGrants = Array.Empty<PermissionGrant>(),
                MaxParentalRatingScore = null,
                SyncPlayAccess = null,
                AvatarUrl = null,
                DefaultProvider = Forged,
                AuthResponse = new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" },
            },
            () => "203.0.113.9",
            () => true).ConfigureAwait(true);

        var line = Assert.Single(log.Entries, e => e.Message.Contains("Set default login provider", StringComparison.Ordinal)).Message;
        Assert.DoesNotContain("\n", line, StringComparison.Ordinal);
        Assert.DoesNotContain(Marker, line, StringComparison.Ordinal);
        Assert.Contains("(SSO Audit] Login succeeded", line, StringComparison.Ordinal);
    }
}
