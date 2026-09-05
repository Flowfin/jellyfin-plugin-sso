// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SSO-Auth.Tests")]

// The out-of-band fuzz harness (SSO-Auth.Fuzz, #402) drives the internal untrusted-input parse entry
// points - SamlResponseLoader, PkceDiscovery, OidcResponseIssuer - directly, the same way the test
// project does. It is a separate, non-shipping project kept out of the normal build/test path.
[assembly: InternalsVisibleTo("SSO-Auth.Fuzz")]

// The in-process benchmark harness (SSO-Auth.Bench, #1117) reads two internals directly, and both are
// there because the number it prints is about them. PluginConfiguration.ToPersistedForm is the whole cost
// of the undo behind a configuration write (#1521, measured by #1532), and LinkExport.FormatVersion names
// the document version its import fixture posts. Non-shipping and outside the normal build/test path, the
// same standing the fuzz harness has above.
[assembly: InternalsVisibleTo("SSO-Auth.Bench")]

// The VSTest twin of the test project (SSO-Auth.Tests.Stryker, #899) compiles the SAME test sources
// for the Stryker mutation run only - Stryker's runner speaks VSTest and cannot drive the MTP-v2
// test project. Non-shipping, outside the normal build/test path; delete with the twin when Stryker
// gains MTP v2 support.
[assembly: InternalsVisibleTo("SSO-Auth.Tests.Stryker")]
