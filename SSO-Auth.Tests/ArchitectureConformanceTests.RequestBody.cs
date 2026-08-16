// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using Jellyfin.Plugin.SSO_Auth.Api.Routing;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the request body is read once by the host binder, with the scan that refuses a second read and its vacuous-pass guard.
/// </content>
public partial class ArchitectureConformanceTests
{
    // The spellings that hand a second reader the bytes the host's binder already consumed.
    // "Request.Body" also matches "Request.BodyReader" - both return the same stream - and
    // EnableBuffering is the call that makes a second read possible at all. The form half of the boundary
    // is here too: SamlLoginService avoids Request.Form by hand today, for a different failure (#206), and
    // this list is what stops that choice from resting on the comment that records it.
    private static readonly string[] SecondBodyReadSpellings =
    {
        "Request.Body", "EnableBuffering", "Request.Form", "ReadFormAsync",
    };

    /// <summary>
    /// The duplicate-key posture of the ASP.NET request-body boundary (#1033), and the artefact that holds
    /// it: a request body is read ONCE, by the host's binder, and nothing in the plugin reads those bytes
    /// again.
    /// <para>
    /// The plugin does not own the input formatter behind <c>[FromBody]</c>, so it does not get to decide
    /// how a body naming one property twice is bound - every parser in the dependency set keeps the LAST
    /// occurrence. What makes that safe is not the formatter. A repeated name becomes a vulnerability when
    /// a validator reads one occurrence and a consumer reads another, and that split needs two readers of
    /// one body. With one reader there is no second occurrence for anything to reach, whichever one the
    /// formatter kept, so the posture holds without the plugin knowing which that is.
    /// </para>
    /// <para>
    /// Rejecting a repeat at this boundary instead would ADD the second reader the defect needs, and it
    /// could not be proved here: no test in this project loads the <c>System.Text.Json</c> the plugin binds
    /// in production - the test process loads a 10.x on both target legs while the plugin binds the host's
    /// copy - so an assertion about the formatter's behaviour would be measuring an assembly that never
    /// runs. The property below needs no such assertion. It is a fact about this tree's source, and a
    /// source scan decides it.
    /// </para>
    /// <para>
    /// Stated at the boundary rather than per route, deliberately. The controller binds a body at ten
    /// actions and <c>AuthResponse</c> at three of them; a posture written per route has to be restated
    /// ten times and drifts, and deciding for three leaves the same crack open next door.
    /// </para>
    /// </summary>
    [Fact]
    public void RequestBodies_AreReadOnceByTheHostBinder()
    {
        var strays = PluginSourceFiles()
            .Select(path => (Path: Path.GetRelativePath(RepoTree.Root, path).Replace(Path.DirectorySeparatorChar, '/'), Source: File.ReadAllText(path)))
            .SelectMany(file => SecondBodyReadSpellings
                .Where(spelling => SourceCallsInCode(file.Source, spelling))
                .Select(spelling => $"{file.Path}: {spelling}"))
            .OrderBy(stray => stray, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            strays.Count == 0,
            "A request body is bound once by the host and never read again (#1033); reading it a second time is what lets a validator and a consumer disagree about a repeated property name. Found: " + string.Join(" | ", strays));
    }

    [Fact]
    public void TheRequestBodyScan_RefusesAVacuousPass()
    {
        // Two ways this rule could report success while covering nothing. The scan could walk a tree with
        // no .cs files in it; and the boundary it is about could stop existing, because an endpoint set
        // that binds no body has no posture to hold and the silence would read as compliance. Both are
        // pinned, and the second is counted on CODE lines so a [FromBody] left in prose cannot keep it
        // alive.
        Assert.NotEmpty(PluginSourceFiles());

        var boundBodies = ControllerSourceFiles()
            .SelectMany(CodeLines)
            .Count(line => line.Text.Contains("[FromBody]", StringComparison.Ordinal));

        Assert.True(
            boundBodies > 0,
            "No controller action binds [FromBody] any more, so the request-body posture this rule holds (#1033) covers nothing; re-decide the boundary rather than leaving the rule standing.");
    }

    [Fact]
    public void ASecondReadOfARequestBody_IsRejectedByTheScan()
    {
        // The must-catch half, over the predicate rather than over the tree, spelled the way somebody
        // adding a duplicate-key check at this boundary would spell it: rewind the body and read it again
        // beside the object the host already bound. That IS the validator/consumer split, written as
        // diligence.
        const string Source = @"
internal static class Whatever
{
    internal static void Screen(HttpRequest request)
    {
        request.EnableBuffering();
        request.Body.Position = 0;
    }
}";

        Assert.True(HoldsASecondBodyRead(Source));
    }

    [Fact]
    public void TheRequestItself_IsNotFlaggedByTheScan()
    {
        // The must-not-catch twin, and the near-miss is one member wide: handing HttpContext.Request to the
        // authorization reader is what every elevated endpoint here does and touches no body, while adding
        // ".Body" to that same expression is the thing refused. The comment naming the banned spelling is
        // in the fixture on purpose - three such lines stand in the tree today, all of them prose
        // explaining why the form is bound rather than read (#206).
        const string Source = @"
internal static class Whatever
{
    // Bound via [FromForm] rather than reading Request.Form directly (#206).
    internal static async Task<AuthorizationInfo> Read(HttpContext context)
        => await _authContext.GetAuthorizationInfo(context.Request);
}";

        Assert.False(HoldsASecondBodyRead(Source));
    }

    // Whether a source text reaches a request body outside the host's binder, on a code line.
    private static bool HoldsASecondBodyRead(string source) =>
        SecondBodyReadSpellings.Any(spelling => SourceCallsInCode(source, spelling));
}
