// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Provider;

/// <summary>
/// One non-secret fact line of a provider Test-connection probe (#1728): the catalogue key of the line and
/// the provider value that fills its <c>{value}</c> slot - an issuer, an endpoint, a certificate subject, a
/// key count - or null where the line carries no value: a fact stated by the key alone (PKCE advertised, the
/// certificate outside its validity), or one the document did not advertise, which the page renders as the
/// not-advertised row rather than an empty line. The value is provider data, never prose and never a secret.
/// </summary>
/// <param name="Key">The catalogue key of the fact line, one of <see cref="ProviderTestKeys"/>.</param>
/// <param name="Value">The provider value the line's <c>{value}</c> slot shows, or null.</param>
internal sealed record ProviderTestFact(string Key, string? Value);
