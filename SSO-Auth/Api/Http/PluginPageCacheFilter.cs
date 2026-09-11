// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// Gives the plugin's pages and page scripts, which the host serves from its own <c>web/ConfigurationPage</c>
/// action, the lifetime answer the plugin's own asset route gives (#1627): the version tag and
/// <c>no-cache</c>, and a 304 for a browser that already holds the current version.
/// </summary>
/// <remarks>
/// <para>
/// The host serves a plugin's registered pages with no validator and no lifetime, and its web client loads
/// a page and its script under the registered name, so nothing on the plugin side can put a version into
/// those URLs. What a plugin can do is register a result filter with the host's MVC options and act on that
/// one action, for its own names only: every other action, and every other plugin's page, passes through
/// exactly as the host built it.
/// </para>
/// <para>
/// NOTHING HERE MAY FAIL A REQUEST. A filter registered with the options runs on every action of the
/// server, so a failure inside it would fail responses that are not this plugin's to fail. The predicate
/// and the stamping are wrapped: on any exception the response stands as it was at that moment, as the
/// host built it or, once the 304 has been chosen, that 304, and the failure is logged at Warning.
/// </para>
/// <para>
/// The action is reachable without authentication today, so the 304 grants nothing a 200 would not, and
/// the tag is the plugin's file version, which <see cref="SSOViewsController"/> has exposed the same way
/// since #253 (T-I, decided on #1627).
/// </para>
/// </remarks>
internal sealed class PluginPageCacheFilter : IResultFilter
{
    // The host's action, named the way MVC names it: the controller's class name without its suffix, and
    // the method name. A rename in the host turns this filter into a no-op, never into a wrong stamp.
    private const string HostController = "Dashboard";
    private const string HostAction = "GetDashboardConfigurationPage";

    private readonly Func<IEnumerable<string>> _pageNames;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginPageCacheFilter"/> class for the host's container:
    /// the names it stamps are the pages the live plugin instance registers, and none while the plugin
    /// instance is not up.
    /// </summary>
    /// <param name="logger">The logger.</param>
    public PluginPageCacheFilter(ILogger<PluginPageCacheFilter> logger)
        : this(() => SSOPlugin.Instance is { } plugin ? plugin.GetPages().Select(page => page.Name) : Enumerable.Empty<string>(), logger)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginPageCacheFilter"/> class over an explicit source
    /// of page names, which is what the tests hand it.
    /// </summary>
    /// <param name="pageNames">Yields the registered page names this filter stamps.</param>
    /// <param name="logger">The logger.</param>
    internal PluginPageCacheFilter(Func<IEnumerable<string>> pageNames, ILogger logger)
    {
        _pageNames = pageNames ?? throw new ArgumentNullException(nameof(pageNames));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public void OnResultExecuting(ResultExecutingContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            if (context.ActionDescriptor is not ControllerActionDescriptor { ControllerName: HostController, ActionName: HostAction }
                || context.Result is not FileStreamResult file)
            {
                return;
            }

            // The host matches the name without regard to case, so this does too: a name the host serves
            // under this plugin's registration is a name this plugin stamps.
            var name = context.HttpContext.Request.Query["name"].ToString();
            if (!_pageNames().Any(registered => string.Equals(registered, name, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            var headers = context.HttpContext.Response.Headers;
            headers.ETag = PluginAssetVersion.ETag.ToString();
            headers.CacheControl = PluginAssetVersion.CacheControl;

            if (HoldsCurrentVersion(context.HttpContext.Request))
            {
                // The 304 is in place before the stream the host opened over the embedded resource is
                // released, so a release that failed would leave the right answer behind, not a
                // half-released file result for the executor.
                context.Result = new StatusCodeResult(StatusCodes.Status304NotModified);
                file.FileStream.Dispose();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[SSO] Could not finish deciding the cache lifetime of a plugin page; the response stands as it was at that moment.");
        }
    }

    /// <inheritdoc />
    public void OnResultExecuted(ResultExecutedContext context)
    {
    }

    // The weak comparison, as RFC 9110 requires for If-None-Match and as the plugin's own route answers
    // through MVC: the tag is the version, so equal tags mean equal bytes, and a W/ prefix arrives from an
    // intermediary that recompressed the body, not from a different asset. `*` is a client asking for
    // anything the server holds, which for a stored asset is the current one.
    private static bool HoldsCurrentVersion(HttpRequest request)
    {
        return EntityTagHeaderValue.TryParseList(request.Headers.IfNoneMatch, out var tags)
            && tags.Any(tag => tag.Equals(EntityTagHeaderValue.Any) || tag.Compare(PluginAssetVersion.ETag, useStrongComparison: false));
    }
}
