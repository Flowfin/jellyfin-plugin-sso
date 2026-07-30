// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Refuses a provider response whose body names a member twice, BEFORE the identity library parses it
/// (#1005). It presents the plugin's SSRF-hardened outbound client as a transport handler, so both documents
/// the discovery read fetches — the well-known document and the JWKS it points at — pass through one screen
/// on their way to the library.
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
internal sealed class RepeatedMemberScreen : HttpMessageHandler
{
    /// <summary>
    /// The constant reason a repeated-member refusal travels under. It reaches the caller as the library's
    /// error text, so an operator reading the fail-closed warning sees why the read failed; WHICH member
    /// repeated is in this handler's own log entry, never in the response.
    /// </summary>
    internal const string RefusalReason = "The provider response names a JSON member twice";

    /// <summary>The constant reason a response that could not be inspected as JSON travels under.</summary>
    internal const string UninspectableReason = "The provider response could not be inspected as JSON";

    // The screen decodes the body a second time on a path an anonymous caller can drive, so it refuses a
    // document far larger than any real one instead of walking it. Two orders of magnitude above the largest
    // measured (Microsoft's JWKS, ~13 KB), so no working provider meets it.
    //
    // What this does NOT do, stated because the bound's name invites the stronger reading: it does not bound
    // the FETCH. HttpClient.SendAsync buffers the whole response body before any handler above it is given
    // the response, so by the time this screen runs the provider's bytes are already in memory — measured,
    // which is why an earlier revision's buffering limit here was removed as inert. Bounding the fetch means
    // reading headers first and streaming under a cap, which changes the library's own read path and belongs
    // to #1041.
    private const int MaxScreenedBytes = 1024 * 1024;

    private readonly HttpClient _client;
    private readonly string? _provider;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="RepeatedMemberScreen"/> class.
    /// </summary>
    /// <param name="client">The client every screened request is forwarded through, so its User-Agent, timeout and hardened transport still apply. Its lifetime belongs to the caller, which is why this handler never disposes it.</param>
    /// <param name="provider">The provider name, for the refusal log entry only.</param>
    /// <param name="logger">The logger the refusal is recorded on.</param>
    internal RepeatedMemberScreen(HttpClient client, string? provider, ILogger logger)
    {
        _client = client;
        _provider = provider;
        _logger = logger;
    }

    /// <summary>
    /// Forwards the request and screens a successful response's body before it reaches the library.
    /// </summary>
    /// <param name="request">The outbound request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The provider's response, or a refusal carrying a constant reason in its place.</returns>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);

        // Only a response the library would parse is screened. A 404 or an HTML error page keeps its own
        // status, because replacing it would tell the operator the document was uninspectable when the real
        // answer is that the provider did not serve one.
        if (!response.IsSuccessStatusCode)
        {
            return response;
        }

        // A declared length over the bound is refused before anything is decoded.
        if (response.Content.Headers.ContentLength is > MaxScreenedBytes)
        {
            return Refuse(request, response, UninspectableReason, repeatedMember: null, cause: null);
        }

        string body;
        try
        {
            // Charset-honouring, exactly like the library's own read, so the screen and the library cannot
            // disagree about what the bytes say; it also reads from the buffer the response already holds, so
            // the untouched original stays readable from this same instance for the library afterwards.
            body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            response.Dispose();
            throw;
        }
        catch (Exception e) when (e is HttpRequestException or InvalidOperationException or IOException)
        {
            // The body could not be obtained or decoded at all: over the bound, or carrying a Content-Type
            // whose charset the runtime does not know — both provider-chosen, so both are refusals rather
            // than throws. Letting the throw escape would lose the reason an operator needs and would leave
            // this handler as the only fail path that reports nothing.
            return Refuse(request, response, UninspectableReason, repeatedMember: null, cause: e);
        }

        // The provider need not declare a length, so this is the bound that always applies: it keeps the walk
        // off a document no real provider serves.
        if (body.Length > MaxScreenedBytes)
        {
            return Refuse(request, response, UninspectableReason, repeatedMember: null, cause: null);
        }

        var verdict = StrictJson.Inspect(body, out var repeatedMember);
        if (verdict == StrictJson.Verdict.Clean)
        {
            return response;
        }

        return Refuse(
            request,
            response,
            verdict == StrictJson.Verdict.Repeated ? RefusalReason : UninspectableReason,
            repeatedMember,
            cause: null);
    }

    // Records why the response is being withheld and returns the constant-reason refusal in its place. The
    // provider name, the URL and the repeated member are stripped of line endings INLINE at the log call, so
    // none of them can forge or split an entry (the log-forging sanitizer never crosses a helper boundary).
    private HttpResponseMessage Refuse(HttpRequestMessage request, HttpResponseMessage response, string reason, string? repeatedMember, Exception? cause)
    {
        _logger.LogWarning(
            cause,
            "Refused the OpenID response from {Uri} for provider {Provider}: {Reason}{Member}. The read fails closed rather than handing a document that means two things to the reader that parses it.",
            request.RequestUri?.AbsoluteUri.ReplaceLineEndings(string.Empty),
            _provider?.ReplaceLineEndings(string.Empty),
            reason,
            repeatedMember is null ? string.Empty : $" ({repeatedMember.ReplaceLineEndings(string.Empty)})");

        response.Dispose();
        return new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            ReasonPhrase = reason,
            RequestMessage = request,
            Content = new StringContent(string.Empty),
        };
    }
}
