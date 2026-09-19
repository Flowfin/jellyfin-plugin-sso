// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// One concrete, callable endpoint discovered from the running host's live routing table, together with the
/// authorization verdict the middleware will apply to it.
/// </summary>
/// <param name="Method">The HTTP method to use.</param>
/// <param name="Url">A concrete request path with the route parameters filled by placeholders.</param>
/// <param name="Policy">The named authorization policy; <c>null</c> both for a bare <c>[Authorize]</c> and for an endpoint with no authorization requirement at all.</param>
/// <param name="Requirement">What the endpoint requires when <paramref name="Policy"/> is null, so the two meanings of null are told apart in every rendering.</param>
/// <param name="Action">The controller action method name, for a readable completeness assertion.</param>
public sealed record GatedEndpoint(string Method, string Url, string? Policy, string Requirement, string Action)
{
    /// <summary>The requirement an endpoint guarded by a bare <c>[Authorize]</c> carries.</summary>
    public const string Authenticated = "authenticated";

    /// <summary>The requirement an endpoint carries when it has no authorization attribute, or an explicit <c>[AllowAnonymous]</c>.</summary>
    public const string Anonymous = "anonymous";

    // NULL MEANT ONE THING HERE UNTIL THE ANONYMOUS BUCKET ARRIVED, AND THE RENDERING RESOLVED THE SECOND
    // MEANING THE WRONG WAY. A policy-less entry printed as "authenticated" because a bare [Authorize] was
    // the only policy-less case; the bucket for endpoints requiring nothing carries a null policy too, so
    // every one of them printed as requiring authentication - in exactly the assertion messages a reader
    // consults to find out which route lost its guard. The requirement travels beside the policy instead of
    // being inferred from its absence.
    public override string ToString() => $"{Method} {Url} [{Policy ?? Requirement}] ({Action})";
}

/// <summary>
/// Enumerates the host's <see cref="EndpointDataSource"/> and classifies every attribute-routed endpoint by
/// its authorization requirement. Reading the LIVE endpoint table (not a hardcoded list) means a newly added
/// guarded endpoint is discovered automatically, so the completeness assertion cannot silently under-cover.
/// </summary>
public sealed class EndpointCatalog
{
    private readonly List<GatedEndpoint> _elevationGated = new();
    private readonly List<GatedEndpoint> _authenticatedOnly = new();
    private readonly List<GatedEndpoint> _anonymous = new();

    public EndpointCatalog(IServiceProvider services)
    {
        var source = services.GetRequiredService<EndpointDataSource>();
        foreach (var endpoint in source.Endpoints.OfType<RouteEndpoint>())
        {
            // An explicit [AllowAnonymous] beats any [Authorize]; such an endpoint is UNGATED rather than
            // absent, and it lands in the third bucket below with the endpoints that carry no attribute.
            var allowAnonymous = endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null;
            var authorizeAttributes = endpoint.Metadata.GetOrderedMetadata<AuthorizeAttribute>();

            // AN UNGATED ENDPOINT IS CLASSIFIED, NOT SKIPPED (#1768). It was skipped until the RP-initiated
            // OpenID logout had to become reachable by a top-level navigation: taking [Authorize] off an
            // action then did not move it between buckets, it removed the action from the only suite that
            // exercises authorization through real ASP.NET routing, silently and at the moment the decision
            // most deserved a reader. Naming the bucket is what lets a rule assert over it.
            var ungated = allowAnonymous || authorizeAttributes.Count == 0;

            var policy = authorizeAttributes.Select(a => a.Policy).FirstOrDefault(p => !string.IsNullOrEmpty(p));
            var methods = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? new[] { HttpMethods.Get };
            var url = BuildConcreteUrl(endpoint.RoutePattern.RawText ?? string.Empty);
            var action = endpoint.Metadata.GetMetadata<ControllerActionDescriptor>()?.ActionName ?? endpoint.DisplayName ?? url;

            foreach (var method in methods)
            {
                var gated = new GatedEndpoint(
                    method,
                    url,
                    ungated ? null : policy,
                    ungated ? GatedEndpoint.Anonymous : GatedEndpoint.Authenticated,
                    action);
                if (ungated)
                {
                    _anonymous.Add(gated);
                }
                else if (string.IsNullOrEmpty(policy))
                {
                    _authenticatedOnly.Add(gated);
                }
                else
                {
                    _elevationGated.Add(gated);
                }
            }
        }
    }

    /// <summary>Gets the endpoints guarded by a named policy (the elevation-gated admin surface).</summary>
    public IReadOnlyList<GatedEndpoint> ElevationGated => _elevationGated;

    /// <summary>Gets the endpoints guarded by a bare <c>[Authorize]</c> (any authenticated caller).</summary>
    public IReadOnlyList<GatedEndpoint> AuthenticatedOnly => _authenticatedOnly;

    /// <summary>
    /// Gets the endpoints carrying no authorization requirement at all - no attribute, or an explicit
    /// <c>[AllowAnonymous]</c>. Reachable by anybody, so it is the bucket a route must never enter by
    /// accident (#1768).
    /// </summary>
    public IReadOnlyList<GatedEndpoint> Anonymous => _anonymous;

    // Fills every route parameter with a placeholder segment. A GUID is used everywhere: it is a valid
    // non-empty value for a string parameter and also parses for a Guid-typed one, so routing always reaches
    // the endpoint (the authorization middleware runs before any model binding could reject the value).
    private static string BuildConcreteUrl(string rawTemplate)
    {
        var segments = rawTemplate.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var filled = segments.Select(segment => segment.StartsWith('{') ? Guid.NewGuid().ToString() : segment);
        return "/" + string.Join('/', filled);
    }
}
