// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>Refuses a provider response whose body names a member twice, before the identity library parses it (#1005).</summary>
/// <remarks>
/// It presents the SSRF-hardened outbound client as a transport handler, so the well-known document and the JWKS
/// it points at pass through one screen. Position is the point: the library resolves a repeated <c>jwks_uri</c> to
/// its last occurrence and dereferences it, so a post-hoc check would speak after the fetch the repeat aimed at.
/// The refusal carries a constant reason phrase, because the platform rejects CR, LF and NUL in it, and the member
/// name travels only on this handler's own log entry, bounded and neutralised at the call (#1195). Its units are
/// named for the property each pins and live beside the seams that exercise them (#1189).
/// </remarks>
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

    /// <summary>How much of a provider-authored member name may reach the refusal entry.</summary>
    /// <remarks>The name arrives with no natural bound short of the response cap. 128 sits above every member name these two documents carry, the longest registered discovery name being 46 characters, and far below the point where repeating the request fills a disk; both directions are pinned, because a ceiling-only proof passes against a stub.</remarks>
    private const int MaxLoggedMemberNameChars = 128;

    /// <summary>Marks a member name this screen cut, so a truncated name is not read as the whole name.</summary>
    private const string NameTruncationMarker = "[truncated]";

    private readonly HttpClient _client;
    private readonly string? _provider;
    private readonly ILogger _logger;
    private OidcDiscoveryRefusal _refusal;

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
    /// Gets the refusal this screen made, or <see cref="OidcDiscoveryRefusal.Unnamed"/> if it refused nothing
    /// (#1064). The reader hands this to its caller so the admin probe can say WHY a read failed instead of
    /// naming reachability at a document that arrived fine and was rejected. It is the screen's own record
    /// rather than a re-reading of the library's error text, so the two cannot drift apart.
    /// <para>
    /// A read fetches two documents through one screen, so a refusal on either leg is reported; the last one
    /// wins, and there is no second leg after a refusal because the first one ends the read.
    /// </para>
    /// </summary>
    internal OidcDiscoveryRefusal Refusal => _refusal;

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
        // that the provider served none. The library does parse such a body - measured - so what keeps its
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
            // The body could not be obtained or decoded, a charset the runtime does not know being the measured
            // instance; refusing keeps the reason an operator needs. Only InvalidOperationException can arrive today
            // because the client pre-buffers the body (#1196), and the other two arms are the net for the day it no longer does.
            return Refuse(request, response, OidcDiscoveryRefusal.Uninspectable, repeatedMember: null, cause: e);
        }

        var verdict = StrictJson.Inspect(body, out var repeatedMember);
        if (verdict == StrictJson.Verdict.Clean)
        {
            return response;
        }

        return Refuse(
            request,
            response,
            verdict == StrictJson.Verdict.Repeated ? OidcDiscoveryRefusal.RepeatedMember : OidcDiscoveryRefusal.Uninspectable,
            repeatedMember,
            cause: null);
    }

    // Records why the response is withheld and returns the constant-reason refusal. The repeated member name is the
    // one provider-authored value and is bounded and neutralised here, because the log-forging sanitizer does not
    // cross a method boundary: control and format characters, the line and paragraph separators and the record-marker
    // bracket (#1557) are replaced, and the cut steps back off a high surrogate rather than through it (#1195).
    private HttpResponseMessage Refuse(HttpRequestMessage request, HttpResponseMessage response, OidcDiscoveryRefusal refusal, string? repeatedMember, Exception? cause)
    {
        // One mapping from the refusal to the words an operator reads, so the log entry and the admin probe
        // that reports the same refusal (#1064) cannot be reworded apart.
        var reason = refusal == OidcDiscoveryRefusal.RepeatedMember ? RefusalReason : UninspectableReason;
        _refusal = refusal;

        // Bounded before it is filtered, so the walk over the characters is over what the entry can carry
        // rather than over everything the provider sent. The cut steps BACK off a high surrogate instead of
        // through it: the bound is the one thing here that can manufacture an unpaired surrogate, by
        // separating the halves of a legitimate astral pair, and a half pair corrupts the entry it lands in.
        var truncated = repeatedMember is { Length: > MaxLoggedMemberNameChars };
        var cut = repeatedMember is { Length: > MaxLoggedMemberNameChars } overlong
            ? overlong[..(char.IsHighSurrogate(overlong[MaxLoggedMemberNameChars - 1]) ? MaxLoggedMemberNameChars - 1 : MaxLoggedMemberNameChars)]
            : repeatedMember;

        // The filter, in the method that logs rather than behind a call from it. SA1118 forbids the
        // expression inside the argument list, so it is a local here; what the log-forging invariant rules
        // out is a HELPER, and TheNeutralisationLivesInTheMethodThatLogs is the scan that keeps it out.
        // The record-marker bracket is substituted on the FILTERED name and the truncation marker is joined
        // only afterwards (#1557): the marker is this screen's own text and opens with the very bracket the
        // substitution exists to remove, so joining it first would turn the screen's marker into a lie.
        var named = cut is null
            ? string.Empty
            : ", the repeated member is named \"" + new string(Array.FindAll(cut.ToCharArray(), c => !char.IsControl(c) && char.GetUnicodeCategory(c) is not (UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator))).Replace('[', '(') + (truncated ? NameTruncationMarker : string.Empty) + "\"";

        _logger.LogWarning(
            "Refused the OpenID {Document} for provider {Provider}: {Reason}{Member}{Cause}. The read fails closed rather than handing on a document whose meaning depends on which reader parses it.",
            DocumentKind(request),
            _provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            reason,
            named,
            cause is null ? string.Empty : $" [{cause.GetType().Name}]");

        response.Dispose();
        return new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            ReasonPhrase = reason,
            RequestMessage = request,
            Content = new StringContent(string.Empty),
        };
    }

    // Names which of the two documents this read fetches was refused, so an operator can tell them apart.
    // A constant chosen by the request, never a value taken from it: the JWKS URL is the provider's to
    // choose, and echoing it is what would put provider-authored text in the entry.
    private static string DocumentKind(HttpRequestMessage request) =>
        request.RequestUri is { } uri && uri.AbsolutePath.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal)
            ? "discovery document"
            : "JWKS document";
}
