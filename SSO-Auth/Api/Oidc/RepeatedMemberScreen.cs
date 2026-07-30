// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Refuses a provider response whose body names a member twice, BEFORE the identity library parses it
/// (#1005). It wraps the plugin's SSRF-hardened outbound client as a transport handler, so both documents the
/// discovery read fetches — the well-known document and the JWKS it points at — pass through one screen on
/// their way to the library.
///
/// Position is the whole point. An equivalent check applied to the parsed result would report the problem
/// after the fact: the library resolves a repeated <c>jwks_uri</c> to its last occurrence and dereferences
/// it, so by the time a post-hoc check could speak, the fetch the repeat aimed at has already happened. Here
/// the discovery response never reaches the library, so the JWKS URL it named is never requested at all.
///
/// The refusal deliberately carries no provider-authored text. <see cref="HttpResponseMessage.ReasonPhrase"/>
/// rejects CR/LF/NUL with a <see cref="FormatException"/>, so a member name spelled with an escaped line feed
/// would make this handler throw while building its own refusal; and sanitising the name to fit would place a
/// sanitiser one helper boundary away from the log call, which is exactly what the log-forging invariant
/// forbids. So the reason phrase is a constant and the member name is logged here, stripped inline.
/// </summary>
internal sealed class RepeatedMemberScreen : DelegatingHandler
{
    /// <summary>
    /// The constant reason the refusal travels under. It reaches the caller as the library's error text, so
    /// an operator reading the fail-closed warning sees why the read failed; WHICH member repeated is in this
    /// handler's own log entry, never in the response.
    /// </summary>
    internal const string RefusalReason = "The provider response names a JSON member twice";

    /// <summary>The reason a response that could not be walked to the end travels under.</summary>
    internal const string UninspectableReason = "The provider response could not be inspected as JSON";

    private readonly string? _provider;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="RepeatedMemberScreen"/> class.
    /// </summary>
    /// <param name="inner">The handler the screened request is forwarded to.</param>
    /// <param name="provider">The provider name, for the refusal log entry only.</param>
    /// <param name="logger">The logger the refusal is recorded on.</param>
    internal RepeatedMemberScreen(HttpMessageHandler inner, string? provider, ILogger logger)
        : base(inner)
    {
        _provider = provider;
        _logger = logger;
    }

    /// <summary>
    /// Forwards the request and screens a successful response's body before it reaches the library.
    /// </summary>
    /// <param name="request">The outbound request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The provider's response, or a refusal carrying <see cref="RefusalReason"/> in its place.</returns>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        // Only a response the library would parse is screened. A 404 or an HTML error page keeps its own
        // status, because replacing it would tell the operator the document was uninspectable when the real
        // answer is that the provider did not serve one.
        if (!response.IsSuccessStatusCode)
        {
            return response;
        }

        // Charset-honouring, exactly like the library's own read, so the screen and the library can never
        // disagree about what the bytes say; it also buffers the content, so the library still reads the
        // untouched original from this same response instance.
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        var verdict = StrictJson.Inspect(body, out var repeatedMember);
        if (verdict == StrictJson.Verdict.Clean)
        {
            return response;
        }

        // The provider name and the repeated member are stripped of line endings INLINE at the log call, so
        // neither can forge or split an entry (the log-forging sanitizer never crosses a helper boundary).
        _logger.LogWarning(
            "Refused the OpenID response from {Uri} for provider {Provider}: {Reason}{Member}. The read fails closed rather than handing a document that means two things to the reader that parses it.",
            request.RequestUri?.AbsoluteUri.ReplaceLineEndings(string.Empty),
            _provider?.ReplaceLineEndings(string.Empty),
            verdict == StrictJson.Verdict.Repeated ? RefusalReason : UninspectableReason,
            repeatedMember is null ? string.Empty : $" ({repeatedMember.ReplaceLineEndings(string.Empty)})");

        response.Dispose();
        return new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            ReasonPhrase = verdict == StrictJson.Verdict.Repeated ? RefusalReason : UninspectableReason,
            RequestMessage = request,
            Content = new StringContent(string.Empty),
        };
    }
}
