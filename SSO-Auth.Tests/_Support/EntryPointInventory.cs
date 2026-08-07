// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Where one action parameter's value comes from.
/// </summary>
public enum EntryPointSource
{
    /// <summary>A route segment, whether declared with <c>[FromRoute]</c> or bound by name from the template.</summary>
    Route,

    /// <summary>The query string.</summary>
    Query,

    /// <summary>A form field.</summary>
    Form,

    /// <summary>The request body, deserialized by the host's input formatter.</summary>
    Body,

    /// <summary>A request header.</summary>
    Header,

    /// <summary>The DI container, not the request - never an attacker-influenced value.</summary>
    Services,

    /// <summary>Supplied by the framework rather than by the request (a cancellation token).</summary>
    Framework,
}

/// <summary>
/// One parameter of one HTTP entry point, with the source its value arrives from.
/// </summary>
/// <param name="Name">The parameter name as declared.</param>
/// <param name="ParameterType">The declared parameter type.</param>
/// <param name="Source">Where the value comes from.</param>
/// <param name="IsExplicit">Whether an attribute named the source, as opposed to it being ASP.NET's default for this parameter.</param>
public sealed record EntryPointParameter(string Name, Type ParameterType, EntryPointSource Source, bool IsExplicit)
{
    /// <inheritdoc />
    public override string ToString() => $"{Source}{(IsExplicit ? string.Empty : " (implicit)")} {ParameterType.Name} {Name}";
}

/// <summary>
/// One reachable HTTP entry point: a method, a route template, the action behind it, and its parameters.
/// An action carrying two route attributes is two entry points, because that is two URLs a caller can arrive on.
/// </summary>
/// <param name="Method">The HTTP method, upper-case.</param>
/// <param name="Template">The action-level route template as declared, empty when the attribute carries none.</param>
/// <param name="Controller">The declaring controller's simple type name.</param>
/// <param name="Action">The action method name.</param>
/// <param name="Parameters">The action's parameters, in declaration order.</param>
public sealed record HttpEntryPoint(
    string Method,
    string Template,
    string Controller,
    string Action,
    IReadOnlyList<EntryPointParameter> Parameters)
{
    /// <inheritdoc />
    public override string ToString() =>
        $"{Method} {Template} -> {Controller}.{Action}({string.Join(", ", Parameters)})";
}

/// <summary>
/// The plugin's HTTP entry-point surface, derived by reflection from the controller types rather than from a
/// hand-written list (#1159), so an endpoint added later is seen without editing any rule built on this.
/// <para>
/// Every rule that asks "does every route a given field arrives on run the same validator" needs the set of
/// routes first. Getting that set from a literal list is the failure mode those rules exist to prevent: the
/// route somebody forgot to add to the list is exactly the route that skipped the validator. So the set is
/// walked, and the walk is sentinel-guarded by <see cref="EntryPointInventoryTests"/> against passing empty.
/// </para>
/// <para>
/// Implicit binding is the part a naive inventory gets wrong. <c>string provider</c> on <c>OidChallenge</c>
/// and <c>SamlChallenge</c> carries no attribute at all and binds from the route, so an inventory that reads
/// only <c>[From*]</c> attributes would miss a large share of the provider-id surface - the single most
/// route-multiplied field in this plugin. <see cref="ImplicitSourceOf"/> reproduces ASP.NET's default rule
/// instead of ignoring it.
/// </para>
/// </summary>
public static class EntryPointInventory
{
    /// <summary>
    /// Gets every entry point on the shipped plugin assembly's controllers.
    /// </summary>
    /// <returns>The entry points, in no guaranteed order.</returns>
    public static IReadOnlyList<HttpEntryPoint> OfThePlugin() => Of(ControllerTypes());

    /// <summary>
    /// Gets the controller types the shipped plugin assembly declares, discovered by base type rather than by
    /// name so a controller that is renamed or split still counts.
    /// </summary>
    /// <returns>The controller types.</returns>
    public static IReadOnlyList<Type> ControllerTypes() =>
        typeof(SSOPlugin).Assembly.GetTypes()
            .Where(t => t.IsClass && !t.IsAbstract && typeof(ControllerBase).IsAssignableFrom(t))
            .ToList();

    /// <summary>
    /// Gets every entry point on the given types. Types that are not controllers contribute nothing, so a
    /// caller may hand in a mixed set.
    /// </summary>
    /// <param name="types">The candidate types.</param>
    /// <returns>The entry points, in no guaranteed order.</returns>
    public static IReadOnlyList<HttpEntryPoint> Of(IEnumerable<Type> types)
    {
        ArgumentNullException.ThrowIfNull(types);

        return types
            .Where(t => t.IsClass && !t.IsAbstract && typeof(ControllerBase).IsAssignableFrom(t))
            .SelectMany(EntryPointsOn)
            .ToList();
    }

    // A public instance method is an action only when it carries an HTTP-method attribute. This plugin routes
    // by attribute throughout, so a public method without one - a helper the class happens to expose - is not
    // reachable over HTTP and must not appear. [NonAction] is honoured as well, for a method that carries a
    // verb attribute and is still excluded from routing.
    private static IEnumerable<HttpEntryPoint> EntryPointsOn(Type controller) =>
        controller.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => !m.IsSpecialName && m.GetCustomAttribute<NonActionAttribute>() is null)
            .SelectMany(method => method.GetCustomAttributes<HttpMethodAttribute>(inherit: true)
                .SelectMany(attribute => attribute.HttpMethods.Select(verb => new
                {
                    Verb = verb,
                    Template = attribute.Template ?? string.Empty,
                    Method = method,
                }))
                .Select(e => new HttpEntryPoint(
                    e.Verb.ToUpperInvariant(),
                    e.Template,
                    controller.Name,
                    e.Method.Name,
                    ParametersOf(e.Method, e.Template))));

    private static IReadOnlyList<EntryPointParameter> ParametersOf(MethodInfo action, string template) =>
        action.GetParameters()
            .Select(p => ExplicitSourceOf(p) is { } source
                ? new EntryPointParameter(p.Name ?? string.Empty, p.ParameterType, source, IsExplicit: true)
                : new EntryPointParameter(p.Name ?? string.Empty, p.ParameterType, ImplicitSourceOf(p, template), IsExplicit: false))
            .ToList();

    private static EntryPointSource? ExplicitSourceOf(ParameterInfo parameter) => parameter switch
    {
        _ when parameter.GetCustomAttribute<FromRouteAttribute>() is not null => EntryPointSource.Route,
        _ when parameter.GetCustomAttribute<FromQueryAttribute>() is not null => EntryPointSource.Query,
        _ when parameter.GetCustomAttribute<FromFormAttribute>() is not null => EntryPointSource.Form,
        _ when parameter.GetCustomAttribute<FromBodyAttribute>() is not null => EntryPointSource.Body,
        _ when parameter.GetCustomAttribute<FromHeaderAttribute>() is not null => EntryPointSource.Header,
        _ when parameter.GetCustomAttribute<FromServicesAttribute>() is not null => EntryPointSource.Services,
        _ => null,
    };

    // ASP.NET's default when no attribute names a source: a name that appears in the route template binds
    // from the route; otherwise a simple type binds from the query string and a complex one from the body.
    // Route-parameter names are matched case-insensitively, as routing matches them.
    private static EntryPointSource ImplicitSourceOf(ParameterInfo parameter, string template)
    {
        if (parameter.ParameterType == typeof(CancellationToken))
        {
            return EntryPointSource.Framework;
        }

        if (TemplateNames(template).Contains(parameter.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            return EntryPointSource.Route;
        }

        return IsSimple(parameter.ParameterType) ? EntryPointSource.Query : EntryPointSource.Body;
    }

    // The names inside a template's {...} segments, with any inline constraint or default (":int", "?", "=x")
    // stripped, and catch-all "*"/"**" prefixes removed.
    private static IEnumerable<string> TemplateNames(string template)
    {
        var rest = template;
        while (rest.IndexOf('{', StringComparison.Ordinal) is var open && open >= 0)
        {
            var close = rest.IndexOf('}', open);
            if (close < 0)
            {
                yield break;
            }

            var name = rest[(open + 1)..close].TrimStart('*');
            var cut = name.IndexOfAny([':', '=', '?']);
            yield return cut >= 0 ? name[..cut] : name;

            rest = rest[(close + 1)..];
        }
    }

    // "Simple" in the model-binding sense: something a single string can be converted into. Anything else is
    // a complex type, which is what makes the difference between an implicit query bind and an implicit body
    // bind.
    private static bool IsSimple(Type type)
    {
        var underlying = Nullable.GetUnderlyingType(type) ?? type;
        return underlying.IsPrimitive
            || underlying.IsEnum
            || underlying == typeof(string)
            || underlying == typeof(decimal)
            || underlying == typeof(DateTime)
            || underlying == typeof(DateTimeOffset)
            || underlying == typeof(TimeSpan)
            || underlying == typeof(Guid)
            || underlying == typeof(Uri);
    }
}
