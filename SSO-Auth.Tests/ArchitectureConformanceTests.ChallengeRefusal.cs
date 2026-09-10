// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rule for what a refused authorization request tells the administrator (#1610).
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void TheChallengeRefusalNamesTheRedirectUriItSent()
    {
        // The provider's answer to a redirect URI it does not have registered is a bare code and a message
        // that names nothing: `invalid_request - Failed to push authorization parameters` is the whole of
        // it. With pushed authorization on, that exchange is server to server, so the administrator never
        // reaches the provider's own error page, which is the only place the URL would otherwise appear.
        //
        // Measured, on a live Pocket ID 2.14.0 reproducing #1608: the provider logged
        // `fosite.MatchRedirectURIWithClientRedirectURIs` on its side and returned nothing but the code on
        // ours, and the difference between the two URIs was one scheme. Registering the right callback
        // turned the same login into 201 from the push and 302 from the plugin.
        //
        // A source rule rather than a behaviour test on purpose. Reaching this branch needs a provider whose
        // discovery succeeds and whose authorize preparation then fails, which is a fake identity provider
        // stood up for one log line. What the rule protects is the property that costs when it is absent -
        // the string being in the message - and that is visible in the text.
        var source = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Flows", "OidcLoginService.cs"));

        var line = source
            .Split('\n')
            .Select(candidate => candidate.TrimEnd('\r'))
            .FirstOrDefault(candidate =>
                candidate.Contains("preparing the authorization request failed", StringComparison.Ordinal)
                && candidate.Contains("LogWarning", StringComparison.Ordinal));

        Assert.True(
            line is not null,
            "The challenge refusal is logged in OidcLoginService and this rule is written against it (#1610).");

        Assert.True(
            line!.Contains("{RedirectUri}", StringComparison.Ordinal),
            "The refused-challenge line names the redirect URI it sent (#1610), because the provider's own "
            + "answer names nothing and the administrator cannot reach the page that would. This line does "
            + "not: " + line.Trim());

        Assert.True(
            line.Contains("redirectUri?.ReplaceLineEndings(string.Empty).Replace('[', '(')", StringComparison.Ordinal),
            "The redirect URI is composed from the request's host header, so it carries both sanitizers "
            + "inline at the call like every other foreign value this tree logs (#1557). This line does "
            + "not: " + line.Trim());
    }
}
