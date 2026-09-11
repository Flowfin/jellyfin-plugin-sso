// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
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
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The filter's one host-facing seam read back the way the host reads it (#1627): the instance the container
/// resolves, through the public constructor, stamps the pages the LIVE plugin instance registers. It runs
/// in the non-parallel collection because it stands a real plugin instance up, which makes the plugin being
/// up a fact of this test rather than of whatever ran before it in the process.
/// </summary>
[Collection("SSOController")]
public class PluginPageCacheFilterWiringTests
{
    [Fact]
    public void TheResolvedFilter_StampsAPageTheLivePluginRegisters_AndNotOneItDoesNot()
    {
        _ = new SsoControllerHarness();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSingleton(Substitute.For<IUserManager>());
        services.AddSingleton(Substitute.For<ICryptoProvider>());
        new SsoOnlyServiceRegistrator().RegisterServices(services, Substitute.For<IServerApplicationHost>());
        using var provider = services.BuildServiceProvider();
        var filter = provider.GetRequiredService<PluginPageCacheFilter>();

        // The core script is a registered PAGE and not a view: a source wired to the wrong list would
        // leave it unstamped, and the 304 proves the tag came through the same source.
        var page = Context("SSO-Auth-core.js", PluginAssetVersion.ETag.ToString());
        filter.OnResultExecuting(page);
        Assert.Equal(StatusCodes.Status304NotModified, Assert.IsType<StatusCodeResult>(page.Result).StatusCode);
        Assert.Equal(PluginAssetVersion.ETag.ToString(), page.HttpContext.Response.Headers.ETag.ToString());

        var other = Context("Some-Other-Plugin", PluginAssetVersion.ETag.ToString());
        var served = other.Result;
        filter.OnResultExecuting(other);
        Assert.Same(served, other.Result);
        Assert.Empty(other.HttpContext.Response.Headers.ETag.ToString());
    }

    private static ResultExecutingContext Context(string name, string ifNoneMatch)
    {
        var http = new DefaultHttpContext();
        http.Request.QueryString = new QueryString("?name=" + name);
        http.Request.Headers.IfNoneMatch = ifNoneMatch;
        var descriptor = new ControllerActionDescriptor { ControllerName = "Dashboard", ActionName = "GetDashboardConfigurationPage" };
        var result = new FileStreamResult(new System.IO.MemoryStream(new byte[] { 1 }), "application/javascript");
        return new ResultExecutingContext(new ActionContext(http, new RouteData(), descriptor), new List<IFilterMetadata>(), result, controller: new object());
    }
}
