// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.IO;
using System.Linq;
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
    // CHARACTERS, not bytes, and named that way after the byte-shaped name misdescribed it: this is compared
    // against a decoded string's length, so a UTF-16 response is twice this on the wire and the UTF-8 array
    // the walk allocates from it can be three times this. The gap is bounded and small; the wrong unit in the
    // name was the defect worth fixing.
    //
    // What this does NOT do: it does not bound the FETCH. That is a property of where this handler sits —
    // above HttpClient, which has already buffered the whole body by the time any handler is handed the
    // response — and not of HttpClient being unboundable. Bounding the fetch means reading headers first and
    // streaming under a cap, which is a different position in the stack and belongs to #1041.
    private const int MaxScreenedChars = 1024 * 1024;

    // The repeated member's name is provider-chosen and reaches the log, so what is logged is bounded. An
    // 800 KB name produced a single 400 KB entry — measured — on a path an anonymous caller drives once per
    // request, which is a log-amplification primitive rather than a diagnostic.
    private const int MaxLoggedMemberChars = 128;

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

        // A non-success response passes through unscreened so it keeps its own status: replacing a 404 with
        // "could not be inspected" would tell the operator the document was malformed when the real answer is
        // that the provider served none.
        //
        // Be clear about what that costs, because an earlier version of this comment claimed the library does
        // not parse such a body and the claim is false — measured: a 400/401/404/500 body still populates
        // `DiscoveryDocumentResponse`, and a repeated `issuer` in it resolves to the attacker's last
        // occurrence. What keeps that value from being acted on is the caller's `IsError` check in
        // OidcDiscoveryReader, which returns before touching any of them. That check is therefore
        // load-bearing rather than incidental, and a future read of `discovery.Issuer` or `discovery.Raw`
        // outside it would reintroduce exactly what this screen removes. The behaviour is pinned by
        // ANonSuccessBodyThatRepeatsAMember_IsNeverActedOn; the structural rule that would stop the read at
        // compile time belongs with the conformance work in #1062.
        if (!response.IsSuccessStatusCode)
        {
            return response;
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
            // Unreachable at this seam today and kept deliberately: HttpClient.SendAsync has already buffered
            // the body above, so a cancelled or timed-out read surfaces from that call rather than from here,
            // and no test can drive this arm. It exists so that a later move to ResponseHeadersRead — which is
            // what bounding the fetch (#1041) requires — cannot silently turn a cancellation into a refusal
            // that blames the provider. Folding it into the refusal below is the natural simplification and
            // is what this comment exists to stop.
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
        if (body.Length > MaxScreenedChars)
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
    // provider name, the URL and the repeated member are neutralised INLINE at the log call, so none of them
    // can forge or split an entry (the log-forging sanitizer never crosses a helper boundary).
    //
    // The member name gets more than ReplaceLineEndings, and deliberately: it is the only fully
    // provider-chosen, arbitrary-codepoint string this plugin logs, and ReplaceLineEndings passes a raw
    // vertical tab and a raw NUL through — measured. A console sink advances a line on VT, so the first
    // forges an entry; the second truncates the record for any C-string-based consumer. Format characters go
    // with them: a right-to-left override reorders the rest of the entry as it is displayed, forging by
    // rearranging rather than by inserting. It is also bounded,
    // because an 800 KB member name became a single 400 KB log line on a path an anonymous caller can drive
    // once per request. 128 characters is more than an operator needs to report the name to their provider.
    //
    // The cause is rendered here rather than passed as the logger's exception argument, and bounded on the
    // same terms: a decode failure's message quotes the provider's own Content-Type, so handing the whole
    // exception to the sink would route straight around the bound above.
    private HttpResponseMessage Refuse(HttpRequestMessage request, HttpResponseMessage response, string reason, string? repeatedMember, Exception? cause)
    {
        _logger.LogWarning(
            "Refused the OpenID response from {Uri} for provider {Provider}: {Reason}{Member}{Cause}. The read fails closed rather than handing a document that means two things to the reader that parses it.",
            request.RequestUri?.AbsoluteUri.ReplaceLineEndings(string.Empty),
            _provider?.ReplaceLineEndings(string.Empty),
            reason,
            repeatedMember is null ? string.Empty : $" ({new string(repeatedMember.Where(c => !char.IsControl(c) && char.GetUnicodeCategory(c) != UnicodeCategory.Format && c != '\u2028' && c != '\u2029').Take(MaxLoggedMemberChars).ToArray())})",
            cause is null ? string.Empty : $" [{cause.GetType().Name}: {new string(cause.Message.Where(c => !char.IsControl(c) && char.GetUnicodeCategory(c) != UnicodeCategory.Format && c != '\u2028' && c != '\u2029').Take(MaxLoggedMemberChars).ToArray())}]");

        response.Dispose();
        return new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            ReasonPhrase = reason,
            RequestMessage = request,
            Content = new StringContent(string.Empty),
        };
    }
}
