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

/// <summary>
/// Refuses a provider response whose body names a member twice, BEFORE the identity library parses it
/// (#1005). It presents the plugin's SSRF-hardened outbound client as a transport handler, so both documents
/// the discovery read fetches - the well-known document and the JWKS it points at - pass through one screen
/// on their way to the library.
///
/// Position is the whole point. An equivalent check applied to the parsed result would report the problem
/// after the fact: the library resolves a repeated <c>jwks_uri</c> to its last occurrence and dereferences
/// it, so by the time a post-hoc check could speak, the fetch the repeat aimed at has already happened. Here
/// the discovery response never reaches the library, so the JWKS URL it named is never requested at all.
///
/// The RESPONSE carries no provider-authored text. <see cref="HttpResponseMessage.ReasonPhrase"/> rejects
/// CR/LF/NUL with a <see cref="FormatException"/>, so a member name spelled with an escaped line feed would
/// make this handler throw while building its own refusal. The reason phrase is therefore a constant, and the
/// member name travels only on this handler's own log entry, where it is bounded and neutralised inline at the
/// log call (#1195). An operator needs it: the name is what identifies the defect to report to the provider,
/// and no configuration relaxes the refusal, so an entry that withheld it would leave nothing to act on.
///
/// There is deliberately no <c>RepeatedMemberScreenTests</c>: a handler between the discovery read and the
/// library has no property that is not a property of a request travelling through it, so its units are named
/// for the property each pins and live beside the seams that exercise them. Which files those are is declared
/// in <c>ArchitectureConformanceTests.TypesWithNoMirroredTestFile</c>, where a rule refuses the declaration
/// once it stops describing the tree (#1189) - so this absence is a decision a reader can check rather than a
/// gap they have to guess at.
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

    /// <summary>
    /// How much of a provider-authored member name may reach the refusal entry. The name arrives with no
    /// natural bound: measured before this bound existed, one anonymous challenge put an 800 KB name in front
    /// of this call, and the only thing limiting it was the 1 MB response cap
    /// (<see cref="Net.ProviderResponseSizeLimit.MaxProviderResponseBytes"/>).
    /// <para>
    /// 128 sits well above every member name these two documents carry - the longest name in the OpenID
    /// discovery metadata registry is the 46-character <c>authorization_response_iss_parameter_supported</c>,
    /// and a JWKS entry's are shorter still - and far below the point where repeating the request fills a
    /// disk. Both directions are pinned by tests, because a ceiling-only proof passes against a bound
    /// tightened to a stub, and a stub throws away the one thing the entry exists to carry.
    /// </para>
    /// </summary>
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
            // The body could not be obtained or decoded: a Content-Type naming a charset the runtime does not
            // know is the measured instance, and it is provider-chosen. Refusing rather than letting the throw
            // escape keeps the reason an operator needs, and keeps this handler from being the one fail path
            // that reports nothing.
            //
            // Of the three types named above, only InvalidOperationException can arrive TODAY (#1196):
            // the client this forwards through completes under the default ResponseContentRead, so the body is
            // already buffered when SendAsync returns and a copy failure is raised one line above this try,
            // measured, and wrapped into an HttpRequestException on the way. The other two arms are the net for
            // the day the read is no longer pre-buffered, and
            // ABodyThatCannotBeCopied_ReachesNeitherTheHttpRequestExceptionNorTheIOExceptionArm goes red on
            // exactly that day, so keeping them stays a checkable claim rather than a decorative one.
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

    // Records why the response is being withheld and returns the constant-reason refusal in its place.
    //
    // ONE value here is provider-authored: the repeated member name. Everything beside it is not - the reason
    // is a compile-time constant, the provider name is the operator's own configuration value, the document
    // is named by a constant chosen from the request rather than echoed out of it, and only the exception
    // TYPE is logged because its message quotes the provider's own Content-Type back.
    //
    // The name is bounded and neutralised in THIS method, and that is not a style choice: the log-forging
    // sanitizer this repository relies on does not propagate across a method boundary, so a filter lifted
    // into a helper stops being one as far as the analyzer is concerned.
    //
    // Four classes come off it, each because ReplaceLineEndings - the strip applied to the operator's own
    // provider name beside it - does not remove them:
    //
    //   * CONTROL characters. A raw vertical tab advances a line on a console sink and a raw NUL truncates
    //     the record for a C-string consumer, and ReplaceLineEndings passes both through. The class also
    //     covers CR, LF, FF and NEL, so it subsumes that strip rather than sitting beside it, which is why
    //     the strip is not also applied here: it would make two of these four classes unkillable by their
    //     own mutation and prove nothing the class arms do not already prove.
    //   * FORMAT characters. A right-to-left override is neither a control nor a separator, and it reorders
    //     the rest of the entry as it is displayed - forging by rearranging rather than by inserting.
    //   * The LINE and PARAGRAPH separators, which a line-ending replacement treats as line endings but a
    //     control-character test does not reach.
    //
    // The fourth class named on #1195, the unpaired surrogate, has no arm, because a provider cannot put one
    // here: a raw one has no UTF-8 encoding and StrictJson refuses the document before the walk starts, and
    // an escaped one is a name GetString will not complete, so the walk reports Unreadable and never a name.
    // AnUnpairedSurrogate_NeverBecomesARepeatedMemberName is what keeps that a measurement rather than a
    // belief; a surrogate filter would instead mangle the legitimate astral names that arrive in pairs.
    //
    // What CAN manufacture one is the bound, by cutting between the halves of a pair, so the cut steps back
    // off a high surrogate rather than through it.
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
        var cut = repeatedMember is null || repeatedMember.Length <= MaxLoggedMemberNameChars
            ? repeatedMember
            : string.Concat(
                repeatedMember.AsSpan(0, char.IsHighSurrogate(repeatedMember[MaxLoggedMemberNameChars - 1]) ? MaxLoggedMemberNameChars - 1 : MaxLoggedMemberNameChars),
                NameTruncationMarker);

        // The filter, in the method that logs rather than behind a call from it. SA1118 forbids the
        // expression inside the argument list, so it is a local here; what the log-forging invariant rules
        // out is a HELPER, and TheNeutralisationLivesInTheMethodThatLogs is the scan that keeps it out.
        var named = cut is null
            ? string.Empty
            : ", the repeated member is named \"" + new string(Array.FindAll(cut.ToCharArray(), c => !char.IsControl(c) && char.GetUnicodeCategory(c) is not (UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator))) + "\"";

        _logger.LogWarning(
            "Refused the OpenID {Document} for provider {Provider}: {Reason}{Member}{Cause}. The read fails closed rather than handing on a document whose meaning depends on which reader parses it.",
            DocumentKind(request),
            _provider?.ReplaceLineEndings(string.Empty),
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
