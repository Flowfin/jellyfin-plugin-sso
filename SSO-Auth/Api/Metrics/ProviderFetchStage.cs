// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Metrics;

/// <summary>
/// Which server-to-provider fetch failed (#1139). The two fail for different reasons and are fixed in
/// different places, so a single "provider unreachable" counter would send an operator to the wrong one.
/// </summary>
internal enum ProviderFetchStage
{
    /// <summary>The discovery document or the JWKS behind it could not be read.</summary>
    Discovery,

    /// <summary>The authorization code could not be exchanged at the token endpoint.</summary>
    Token,
}
