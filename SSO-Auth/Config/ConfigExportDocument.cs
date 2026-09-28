// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>The portable document the config export produces and the import consumes: a version marker plus the redacted configuration (#161).</summary>
/// <remarks>A JSON-only transport shape; serializing it applies the configuration's own JSON-boundary redaction.</remarks>
public class ConfigExportDocument
{
    /// <summary>Gets or sets the document format version, which the import refuses when it does not recognise it.</summary>
    public int FormatVersion { get; set; }

    /// <summary>Gets or sets the redacted plugin configuration: a detached snapshot on export, the configuration to merge on import.</summary>
    public PluginConfiguration? Configuration { get; set; }
}
