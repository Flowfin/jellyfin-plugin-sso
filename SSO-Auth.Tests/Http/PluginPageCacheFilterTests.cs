// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The filter that gives the host-served plugin pages a lifetime (#1627). It runs on every action of the
/// server, so most of these rows are about what it must NOT touch: another plugin's page, another action,
/// a result that is not a file, and any request at all when something inside it throws. The rows that are
/// about what it does pin the tag, the header and the 304, and that a weak or older tag is served in full.
/// </summary>
public class PluginPageCacheFilterTests
{
    private const string OurPage = "SSO-Auth-core.js";
    private static readonly string CurrentTag = PluginAssetVersion.ETag.ToString();

    [Fact]
    public void OurPage_IsStampedWithTheVersionTagAndNoCache()
    {
        var (filter, _) = Build();
        var context = Context("Dashboard", "GetDashboardConfigurationPage", OurPage, File(out _));
        var served = context.Result;

        filter.OnResultExecuting(context);

        Assert.Same(served, context.Result);
        Assert.Equal(CurrentTag, context.HttpContext.Response.Headers.ETag.ToString());
        Assert.Equal("no-cache", context.HttpContext.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public void OurPage_HeldAtTheCurrentVersion_IsA304_AndTheStreamIsReleased()
    {
        var (filter, _) = Build();
        var context = Context("Dashboard", "GetDashboardConfigurationPage", OurPage, File(out var stream), ifNoneMatch: CurrentTag);

        filter.OnResultExecuting(context);

        var status = Assert.IsType<StatusCodeResult>(context.Result);
        Assert.Equal(StatusCodes.Status304NotModified, status.StatusCode);
        Assert.False(stream.CanRead);
        // A 304 carries the validators the 200 would have, so the client keeps the same tag.
        Assert.Equal(CurrentTag, context.HttpContext.Response.Headers.ETag.ToString());
        Assert.Equal("no-cache", context.HttpContext.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public void AnyVersion_CountsAsHeld()
    {
        var (filter, _) = Build();
        var context = Context("Dashboard", "GetDashboardConfigurationPage", OurPage, File(out _), ifNoneMatch: "*");

        filter.OnResultExecuting(context);

        Assert.Equal(StatusCodes.Status304NotModified, Assert.IsType<StatusCodeResult>(context.Result).StatusCode);
    }

    [Fact]
    public void OurPage_HeldAtAnOlderVersion_IsServedInFull()
    {
        var (filter, _) = Build();
        var context = Context("Dashboard", "GetDashboardConfigurationPage", OurPage, File(out var stream), ifNoneMatch: "\"4.9.9.9\"");
        var served = context.Result;

        filter.OnResultExecuting(context);

        Assert.Same(served, context.Result);
        Assert.True(stream.CanRead);
        Assert.Equal(CurrentTag, context.HttpContext.Response.Headers.ETag.ToString());
    }

    [Fact]
    public void AWeakTag_DoesNotValidate()
    {
        // The tag is the whole version; a weak match would validate an asset whose bytes differ.
        var (filter, _) = Build();
        var context = Context("Dashboard", "GetDashboardConfigurationPage", OurPage, File(out var stream), ifNoneMatch: "W/" + CurrentTag);
        var served = context.Result;

        filter.OnResultExecuting(context);

        Assert.Same(served, context.Result);
        Assert.True(stream.CanRead);
    }

    [Fact]
    public void TheHostsNameMatching_IsCaseInsensitive_AndSoIsThis()
    {
        var (filter, _) = Build();
        var context = Context("Dashboard", "GetDashboardConfigurationPage", OurPage.ToUpperInvariant(), File(out _));

        filter.OnResultExecuting(context);

        Assert.Equal(CurrentTag, context.HttpContext.Response.Headers.ETag.ToString());
    }

    [Fact]
    public void AnotherPluginsPage_PassesUntouched()
    {
        var (filter, _) = Build();
        var context = Context("Dashboard", "GetDashboardConfigurationPage", "Some-Other-Plugin", File(out var stream));
        var served = context.Result;

        filter.OnResultExecuting(context);

        AssertUntouched(context, served);
        Assert.True(stream.CanRead);
    }

    [Fact]
    public void AnotherAction_PassesUntouched_EvenWithOurName()
    {
        var (filter, _) = Build();
        var context = Context("Dashboard", "GetConfigurationPages", OurPage, File(out _));
        var served = context.Result;

        filter.OnResultExecuting(context);

        AssertUntouched(context, served);
    }

    [Fact]
    public void AnotherController_PassesUntouched_EvenWithTheHostsActionName()
    {
        var (filter, _) = Build();
        var context = Context("SSOViews", "GetDashboardConfigurationPage", OurPage, File(out _));
        var served = context.Result;

        filter.OnResultExecuting(context);

        AssertUntouched(context, served);
    }

    [Fact]
    public void AResultThatIsNotAFile_PassesUntouched()
    {
        // The host answers 404 for a name nothing registers; a validator on that would be a lie.
        var (filter, _) = Build();
        var context = Context("Dashboard", "GetDashboardConfigurationPage", OurPage, new NotFoundResult(), ifNoneMatch: CurrentTag);
        var served = context.Result;

        filter.OnResultExecuting(context);

        AssertUntouched(context, served);
    }

    [Fact]
    public void WhileThePluginRegistersNoPage_NothingIsStamped()
    {
        var log = new CapturingLogger();
        var filter = new PluginPageCacheFilter(() => Enumerable.Empty<string>(), log);
        var context = Context("Dashboard", "GetDashboardConfigurationPage", OurPage, File(out _), ifNoneMatch: CurrentTag);
        var served = context.Result;

        filter.OnResultExecuting(context);

        AssertUntouched(context, served);
        Assert.Empty(log.Entries);
    }

    [Fact]
    public void APageListThatThrows_LeavesTheHostsResponseAsBuilt_AndWarns()
    {
        // The one property that makes a global filter safe to register: whatever fails inside it, the
        // request it runs on is served exactly as the host built it.
        var log = new CapturingLogger();
        var filter = new PluginPageCacheFilter(() => throw new InvalidOperationException("boom"), log);
        var context = Context("Dashboard", "GetDashboardConfigurationPage", OurPage, File(out var stream), ifNoneMatch: CurrentTag);
        var served = context.Result;

        filter.OnResultExecuting(context);

        AssertUntouched(context, served);
        Assert.True(stream.CanRead);
        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("served as built", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheHostResolvesTheFilter_FromWhatTheRegistratorRegistered()
    {
        // The wiring is the one host-facing seam: the host builds its MVC options from every registration
        // in the container, and resolves a service filter from the container per request. Built the way
        // the outbound-client test builds it, this reads both back and drives one request through the
        // resolved instance - a request for another action, which the filter answers before it asks the
        // plugin instance for anything, so the outcome does not depend on whether one is up.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSingleton(Substitute.For<IUserManager>());
        services.AddSingleton(Substitute.For<ICryptoProvider>());
        new SsoOnlyServiceRegistrator().RegisterServices(services, Substitute.For<IServerApplicationHost>());
        using var provider = services.BuildServiceProvider();

        var filters = provider.GetRequiredService<IOptions<MvcOptions>>().Value.Filters;
        var registration = Assert.Single(filters, f => f is ServiceFilterAttribute service && service.ServiceType == typeof(PluginPageCacheFilter));
        Assert.IsType<ServiceFilterAttribute>(registration);
        var filter = provider.GetRequiredService<PluginPageCacheFilter>();

        var context = Context("Dashboard", "GetConfigurationPages", OurPage, File(out _));
        var served = context.Result;
        filter.OnResultExecuting(context);
        AssertUntouched(context, served);
    }

    private static void AssertUntouched(ResultExecutingContext context, IActionResult served)
    {
        Assert.Same(served, context.Result);
        Assert.Empty(context.HttpContext.Response.Headers.ETag.ToString());
        Assert.Empty(context.HttpContext.Response.Headers.CacheControl.ToString());
    }

    private static (PluginPageCacheFilter Filter, CapturingLogger Log) Build()
    {
        var log = new CapturingLogger();
        return (new PluginPageCacheFilter(() => new[] { "SSO-Auth", "SSO-Auth.js", OurPage, "SSO-Auth.css" }, log), log);
    }

    // The host's result for a page: a stream over the embedded resource, which is what the filter must
    // release when it answers 304 instead.
    private static FileStreamResult File(out MemoryStream stream)
    {
        stream = new MemoryStream(new byte[] { 1, 2, 3 });
        return new FileStreamResult(stream, "application/javascript");
    }

    private static ResultExecutingContext Context(string controller, string action, string name, IActionResult result, string? ifNoneMatch = null)
    {
        var http = new DefaultHttpContext();
        http.Request.QueryString = new QueryString("?name=" + Uri.EscapeDataString(name));
        if (ifNoneMatch is not null)
        {
            http.Request.Headers.IfNoneMatch = ifNoneMatch;
        }

        var descriptor = new ControllerActionDescriptor { ControllerName = controller, ActionName = action };
        var actionContext = new ActionContext(http, new RouteData(), descriptor);
        return new ResultExecutingContext(actionContext, new List<IFilterMetadata>(), result, controller: new object());
    }
}
