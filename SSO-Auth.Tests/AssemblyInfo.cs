// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Runtime.CompilerServices;

// The in-process login-latency benchmark (SSO-Auth.Bench, #1117) drives the real SSOController through
// this project's SsoControllerHarness and OidcTokenFixture, both internal here. Referencing them rather
// than copying them is what keeps the instrument measuring the current login setup (see the comment in
// SSO-Auth.Bench.csproj). Non-shipping, outside the normal build/test path: the bench is not in
// SSO-Auth.sln and no CI job builds it.
[assembly: InternalsVisibleTo("SSO-Auth.Bench")]
