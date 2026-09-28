// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;
using Jellyfin.Plugin.SSO_Auth.Api.Localization;
using MediaBrowser.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// The sso views controller.
/// </summary>
[ApiController]
[Route("[controller]")]
public class SSOViewsController : ControllerBase
{
    private readonly ILogger<SSOViewsController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOViewsController"/> class.
    /// </summary>
    /// <param name="logger">Instance of the <see cref="ILogger{SSOViewsController}"/> interface.</param>
    public SSOViewsController(ILogger<SSOViewsController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Gets an HTML view.
    /// </summary>
    /// <param name="viewName">The name of the view / asset to fetch.</param>
    /// <returns>The HTML view with the specified name.</returns>
    [HttpGet("{viewName}")]
    public ActionResult GetView([FromRoute] string viewName)
    {
        if (SSOPlugin.Instance == null)
        {
            return BadRequest("No plugin instance found");
        }

        var view = SSOPlugin.Instance.GetViews()
            .FirstOrDefault(pageInfo => string.Equals(pageInfo.Name, viewName, StringComparison.Ordinal));

        if (view == null)
        {
            return NotFound("No matching view found");
        }

        var stream = SSOPlugin.Instance.GetType().Assembly.GetManifestResourceStream(view.EmbeddedResourcePath);

        if (stream == null)
        {
            _logger.LogError("Failed to get resource {Resource}", view.EmbeddedResourcePath);
            return NotFound();
        }

        // The version tag lets a client 304-revalidate instead of re-downloading jellyfin-apiClient.esm.min.js
        // (~79 KB) and emby-restyle.css on every linking-page load (#253); no-cache is what makes it ask
        // (#1627). Both are PluginAssetVersion's, the one answer both asset routes give.
        Response.Headers.CacheControl = PluginAssetVersion.CacheControl;
        return File(stream, MimeTypes.GetMimeType(view.EmbeddedResourcePath), lastModified: null, entityTag: PluginAssetVersion.ETag);
    }

    /// <summary>Gets the plugin's user-interface strings (#913) resolved into the culture requested by the caller's Accept-Language header, so the server owns the culture fallback and the pages carry only keys; anonymous and non-sensitive.</summary>
    /// <remarks>It serves the whole catalog, including the admin page's own labels, because the labels are fixed strings shipped in a public repository and splitting the payload by audience would add an authorization branch to a presentational endpoint for nothing.</remarks>
    /// <returns>Every UI string key resolved to a concrete value in the request's culture.</returns>
    [HttpGet("i18n")]
    [AllowAnonymous]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult<IReadOnlyDictionary<string, string>> GetLocalizationCatalog()
    {
        var culture = AcceptLanguage.Resolve(Request.Headers.AcceptLanguage.ToString());

        // The resolved set differs per requested language, so caches must key on it.
        Response.Headers.Vary = HeaderNames.AcceptLanguage;

        return Ok(SsoLocalizer.ResolvedCatalog(culture));
    }
}
