// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Globalization;
using System.Net.Http;

namespace Jellyfin.Plugin.SSO_Auth.Api.Net;

/// <summary>
/// The refusal <see cref="ProviderResponseSizeLimit"/> raises when a provider response exceeds the seam's
/// byte bound.
///
/// It derives from <see cref="HttpRequestException"/> on purpose. Every existing caller on the login path
/// already treats an <see cref="HttpRequestException"/> as a fail-closed transport failure - the discovery
/// read, the SAML metadata importer and the avatar fetch each catch it and refuse - so the bound inherits
/// their fail-closed handling without one of them needing to learn a new exception type.
///
/// The MESSAGE is load-bearing, and that is measured rather than assumed. On the discovery path the identity
/// library converts a transport failure into its own error result before the plugin sees an exception, so no
/// caller there can catch this type apart; what reaches the operator's warning is this message, passed
/// through as the library's error text. So the message names the bound, and
/// <c>ProviderResponseSizeLimitDiscoveryTests</c> pins that it still does.
/// </summary>
internal sealed class ProviderResponseTooLargeException : HttpRequestException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ProviderResponseTooLargeException"/> class.
    /// </summary>
    /// <param name="maxBytes">The bound that was exceeded, so a caller can name the limit without importing the constant.</param>
    internal ProviderResponseTooLargeException(long maxBytes)
        : base(string.Create(CultureInfo.InvariantCulture, $"The provider response exceeds the {maxBytes}-byte limit."))
    {
        MaxBytes = maxBytes;
    }

    /// <summary>Gets the bound that was exceeded, in bytes.</summary>
    internal long MaxBytes { get; }
}
