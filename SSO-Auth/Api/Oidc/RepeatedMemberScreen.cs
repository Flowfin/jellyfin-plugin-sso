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

    // Every provider-authored string this screen writes to the log is cut to this length. Measured: an 800 KB
    // member name produced a single 400 KB entry, on a path an anonymous caller drives once per request, which
    // is an amplification primitive rather than a diagnostic. 128 characters is more than an operator needs to
    // recognise a member name or a URL and report it onward.
    //
    // Bounding what the screen READS is a different question and deliberately not answered here: this handler
    // sits above an HttpClient that has already buffered the whole body, so a bound at this position limits
    // the walk and nothing else. #1041 owns the bound that would matter, at the position where it can.
    private const int MaxLoggedChars = 128;

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
        // that the provider served none. The library does parse such a body — measured — so what keeps its
        // values from being acted on is the caller's `IsError` return in OidcDiscoveryReader. That check is
        // load-bearing rather than incidental, which is why ANonSuccessBodyThatRepeatsAMember_IsNeverActedOn
        // pins the outcome; the structural rule that would stop the read at compile time is #1062's.
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
        catch (Exception e) when (e is HttpRequestException or InvalidOperationException or IOException)
        {
            // The body could not be obtained or decoded: a Content-Type naming a charset the runtime does not
            // know is the measured instance, and it is provider-chosen. Refusing rather than letting the throw
            // escape keeps the reason an operator needs, and keeps this handler from being the one fail path
            // that reports nothing.
            return Refuse(request, response, UninspectableReason, repeatedMember: null, cause: e);
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

    // Records why the response is being withheld and returns the constant-reason refusal in its place.
    //
    // Every provider-authored value is neutralised INLINE at the log call rather than through a helper,
    // because the log-forging sanitizer this repo relies on does not propagate across a method boundary.
    // That is what the one duplicated filter expression below buys, and it is the reason it is duplicated
    // rather than extracted.
    //
    // The member name needs more than ReplaceLineEndings: it is arbitrary provider-chosen text, and
    // ReplaceLineEndings passes a raw vertical tab and a raw NUL through — measured. A console sink
    // advances a line on the first, forging an entry; the second truncates the record for a C-string
    // consumer. Format characters go with them, since a right-to-left override forges by rearranging what
    // is displayed rather than by inserting. The request URI is provider-authored too on the JWKS leg, but
    // a Uri cannot carry a raw control character, so it needs the bound and not the filter.
    //
    // Only the exception TYPE is logged, never its message: the message quotes the provider's own
    // Content-Type, so it is one more untrusted string, while the type name is runtime-authored and
    // distinguishes the decode failures an operator actually needs to tell apart.
    private HttpResponseMessage Refuse(HttpRequestMessage request, HttpResponseMessage response, string reason, string? repeatedMember, Exception? cause)
    {
        _logger.LogWarning(
            "Refused the OpenID response from {Uri} for provider {Provider}: {Reason}{Member}{Cause}. The read fails closed rather than handing on a document whose meaning depends on which reader parses it.",
            Cut(request.RequestUri?.AbsoluteUri.ReplaceLineEndings(string.Empty)),
            _provider?.ReplaceLineEndings(string.Empty),
            reason,
            repeatedMember is null ? string.Empty : $" ({new string(repeatedMember.Where(c => !char.IsControl(c) && char.GetUnicodeCategory(c) != UnicodeCategory.Format && c != '\u2028' && c != '\u2029').Take(MaxLoggedChars).ToArray())})",
            cause is null ? string.Empty : $" [{cause.GetType().Name}]");
        response.Dispose();
        return new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            ReasonPhrase = reason,
            RequestMessage = request,
            Content = new StringContent(string.Empty),
        };
    }

    // Bounds a value for the log. Length only — the neutralisation that the log-forging rule governs stays
    // inline at the call above, and deliberately does not live here.
    private static string? Cut(string? value) =>
        value is not null && value.Length > MaxLoggedChars ? value.Substring(0, MaxLoggedChars) : value;
}
