// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api;
using MediaBrowser.Common.Api;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Header value that selects the impersonated caller for a request against the fixture host.
/// </summary>
public static class TestRoles
{
    /// <summary>The header the test authentication scheme reads to decide who the caller is.</summary>
    public const string Header = "X-Test-Role";

    /// <summary>An authenticated, non-administrator caller (passes a plain <c>[Authorize]</c>, fails elevation).</summary>
    public const string User = "user";

    /// <summary>An authenticated administrator (passes both the default policy and the elevation policy).</summary>
    public const string Admin = "admin";
}

/// <summary>Hosts the real <see cref="SSOController"/> in an in-process Kestrel server, so the authorization attributes on the production endpoints are enforced by the genuine ASP.NET Core pipeline rather than asserted present by reflection.</summary>
/// <remarks>
/// Real here: the shipped controller assembly loaded through <c>AddApplicationPart</c>, its authorization attributes, and the routing, authentication and
/// authorization middleware that rejects a caller before the action body runs. Supplied here, because inside Jellyfin it is the responsibility of the host: a test
/// authentication scheme keyed off <see cref="TestRoles.Header"/>, and <see cref="Policies.RequiresElevation"/> registered to require the Administrator role.
/// </remarks>
public sealed class SsoAuthorizationServerFixture : IAsyncDisposable
{
    private readonly WebApplication _app;

    private long _entered;

    private long _completed;

    /// <summary>
    /// The substituted user manager the hosted controller resolves, so a row can decide what an account
    /// resolves to: the ticket arm reads the account behind a ticket again at the redeem (#1793).
    /// </summary>
    public IUserManager UserManager { get; }

    public SsoAuthorizationServerFixture()
    {
        // Set the process-wide SSOPlugin.Instance the controller reads at construction
        // (SSOPlugin.Instance.ConfigStore in the SSOController ctor). Mirrors SsoControllerHarness so an
        // authorized request reaches the action body cleanly instead of NRE-ing into a 500. The rejection
        // paths (401/403) never construct the controller, so they do not depend on this.
        var appPaths = Substitute.For<IApplicationPaths>();
        appPaths.PluginConfigurationsPath.Returns(Path.Combine(Path.GetTempPath(), "sso-authz-test-" + Guid.NewGuid()));
        appPaths.PluginsPath.Returns(Path.Combine(Path.GetTempPath(), "sso-authz-test-plugins-" + Guid.NewGuid()));
        var xml = Substitute.For<IXmlSerializer>();
        xml.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(new Jellyfin.Plugin.SSO_Auth.Config.PluginConfiguration());
        _ = new SSOPlugin(appPaths, xml, Substitute.For<ILogger<SSOPlugin>>());

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        // The ten constructor collaborators of SSOController, resolved from DI when the framework activates
        // the controller. They are substitutes: this fixture proves the AUTHORIZATION gate, not the action
        // bodies (those are covered by the in-process SsoControllerHarness tests).
        builder.Services.AddSingleton(Substitute.For<ISessionManager>());
        UserManager = Substitute.For<IUserManager>();
        builder.Services.AddSingleton(UserManager);
        builder.Services.AddSingleton(BuildAuthorizationContext());
        builder.Services.AddSingleton<ICryptoProvider>(new FakeCryptoProvider());
        builder.Services.AddSingleton(Substitute.For<IProviderManager>());
        builder.Services.AddSingleton(Substitute.For<IServerConfigurationManager>());
        builder.Services.AddSingleton<IDisplayPreferencesManager>(new FakeDisplayPreferencesManager());
        builder.Services.AddHttpClient();

        builder.Services.AddAuthentication(TestAuthHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, null);

        // The default policy (used by a bare [Authorize]) requires an authenticated caller; the elevation
        // policy additionally requires the Administrator role, mirroring Jellyfin's RequiresElevation.
        builder.Services.AddAuthorizationBuilder()
            .AddPolicy(Policies.RequiresElevation, policy => policy.RequireAuthenticatedUser().RequireRole(AdministratorRole));

        builder.Services.AddControllers().AddApplicationPart(typeof(SSOController).Assembly);

        _app = builder.Build();

        // First in the pipeline, so the pair answers the question a request producing no status otherwise
        // leaves open (#1444): a connection the operating system accepted and Kestrel never dispatched
        // increments neither counter, while a request that entered the pipeline and never came back out
        // increments only the first. Measured on this host, those two cost different amounts of wall clock -
        // a refused port answers in about two seconds, an accepted-but-unanswered connection costs the whole
        // client timeout - so the elapsed time already separates them from a refusal; what it cannot say is
        // which side of Kestrel the request died on.
        _app.Use(async (context, next) =>
        {
            Interlocked.Increment(ref _entered);
            try
            {
                await next(context).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Increment(ref _completed);
            }
        });

        _app.UseRouting();
        _app.UseAuthentication();
        _app.UseAuthorization();
        _app.MapControllers();
        _app.StartAsync().GetAwaiter().GetResult();

        var address = _app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.GetEnumerator();
        address.MoveNext();
        // The timeout is explicit rather than inherited (#1444). HttpClient defaults to 100 seconds, measured
        // on this type rather than read from documentation, and every request here is a loopback call to a
        // server in this same process that answers in milliseconds. A stall therefore holds the suite for a
        // minute and a half per request with nothing said about it. A red run of these tests once took four
        // times as long as a green one and left no usable evidence; whether a stall produced that is not
        // established, and bounding the wait is what would let the next occurrence say so itself.
        Client = new HttpClient { BaseAddress = new Uri(address.Current), Timeout = TimeSpan.FromSeconds(30) };

        Endpoints = new EndpointCatalog(_app.Services);
    }

    /// <summary>Gets an <see cref="HttpClient"/> bound to the running host's loopback base address.</summary>
    public HttpClient Client { get; }

    /// <summary>Gets the authorization metadata discovered from the live endpoint table.</summary>
    public EndpointCatalog Endpoints { get; }

    /// <summary>
    /// Gets the count of requests that have entered the host pipeline and the count that have left it again,
    /// read as one snapshot. The walk reads it either side of a request that produced no status, and the
    /// difference says whether the host ever saw that request (#1444).
    /// </summary>
    public (long Entered, long Completed) Traffic =>
        (Interlocked.Read(ref _entered), Interlocked.Read(ref _completed));

    /// <summary>The role name Jellyfin grants administrators; the elevation policy requires it.</summary>
    internal const string AdministratorRole = "Administrator";

    /// <summary>Resolves the caller to a real host user, so the bare-<c>[Authorize]</c> canonical-link endpoints reach their action bodies instead of failing an in-body owner check.</summary>
    /// <remarks>
    /// That check is the subject of <c>RequestHelpersTests</c>, and leaving the caller unresolved would make an in-body denial indistinguishable from a mistaken
    /// elevation gate. It answers per request rather than handing out one fixed administrator, because a route that refuses in its own body would otherwise be
    /// reported open and could not be reported otherwise. The credential here is the <see cref="TestRoles.Header"/> header, so no credential resolves no user.
    /// </remarks>
    private static IAuthorizationContext BuildAuthorizationContext()
    {
        var hostUser = new User("test-caller", "SSO-Auth", "Default") { EnableUserPreferenceAccess = true };
        hostUser.SetPermission(PermissionKind.IsAdministrator, true);

        var authContext = Substitute.For<IAuthorizationContext>();
        authContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(call => Task.FromResult(
                CarriesTestCredential(call.Arg<HttpRequest>())
                    ? new AuthorizationInfo { User = hostUser }
                    : new AuthorizationInfo()));
        return authContext;
    }

    // The same reading TestAuthHandler makes, so the substitute and the authentication scheme cannot
    // disagree about who is calling: an absent or empty header is a request that proved nothing.
    private static bool CarriesTestCredential(HttpRequest? request) =>
        request is not null && request.Headers.TryGetValue(TestRoles.Header, out var role) && role.Count != 0;

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// A trivial authentication scheme: the <see cref="TestRoles.Header"/> header selects the caller.
    /// Absent header -> unauthenticated (any [Authorize] yields 401). "user" -> authenticated, no role.
    /// "admin" -> authenticated with the Administrator role.
    /// </summary>
    private sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public const string SchemeName = "Test";

        public TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(TestRoles.Header, out var role) || role.Count == 0)
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var claims = new List<Claim> { new(ClaimTypes.Name, "test-caller") };
            if (string.Equals(role.ToString(), TestRoles.Admin, StringComparison.Ordinal))
            {
                claims.Add(new Claim(ClaimTypes.Role, AdministratorRole));
            }

            var identity = new ClaimsIdentity(claims, SchemeName);
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}
