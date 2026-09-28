// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Audit;

/// <summary>Writes the "[SSO Audit]" lines for the security events of this plugin: logins, adoptions, provisioning, configuration and logout.</summary>
/// <remarks>
/// A foreign value loses its line endings and its "[" becomes "(" at every call, spelled out inline so CodeQL's log-forging
/// tracking sees it (#1555, #1557); a path this server composed keeps only the line-ending strip. Every call is guarded by
/// <see cref="ILogger.IsEnabled(LogLevel)"/> (CA1873, #566). What a line may name and why the bracket is substituted:
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#audit-trail"/>.
/// </remarks>
internal static partial class SsoAudit
{
    /// <summary>The most characters of a route-chosen provider name a logout line prints (#1792); the rest is cut and marked.</summary>
    internal const int MaxLoggedProviderChars = 128;

    /// <summary>Marks a provider name a logout line cut, so a truncated name is not read as the whole one.</summary>
    internal const string ProviderCutMark = "[truncated]";
}
