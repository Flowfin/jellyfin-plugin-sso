// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Duende.IdentityModel.Jwk;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using SharpFuzz;

namespace Jellyfin.Plugin.SSO_Auth.Fuzz;

/// <summary>
/// Coverage-guided fuzz driver (#402) for the plugin's untrusted-input parse entry points - the
/// functions that turn attacker-controlled bytes from the unauthenticated callback endpoints into
/// objects, BEFORE any signature or claim is trusted. One target is selected per run via the
/// <c>SSO_FUZZ_TARGET</c> environment variable so libFuzzer's single-input contract is honoured while
/// the same executable covers every surface.
///
/// The property under test is uniform across targets: on ANY input the entry point must terminate with
/// a fail-closed result (false / null / a rejection) OR one of the exceptions it explicitly maps - it
/// must never leak an unmapped exception (which on the real callback path becomes an HTTP 500 / DoS)
/// and must never hang. A "crash" libFuzzer records here is therefore a real finding: an exception type
/// the fail-closed filters do not catch. Each finding is triaged as its own security issue, per #174 -
/// never patched silently in-harness.
/// </summary>
internal static class Program
{
    // A single, valid, self-signed IdP certificate reused across the SAML iterations: TryParse loads it
    // before it parses the body, so a stable good certificate keeps the fuzzer exercising the BODY parse
    // (the untrusted surface) rather than repeatedly failing on the certificate. Random bytes cannot forge
    // a signature that verifies against it, so IsValid stays fail-closed; the target is the parse/validate
    // code path's robustness, not a signature bypass (which coverage-guided fuzzing cannot reach).
    private static readonly string SamlCertificateBase64 = CreateSelfSignedCertificateBase64();

    // The role-claim path the `roles` target drives, pinned beside the corpus it belongs to: segment[0] is
    // the claim name the caller matched, the rest walk into the claim value. Changing it invalidates every
    // seed in corpus/roles, which is why it lives here as one constant rather than at the call.
    private static readonly string[] RoleClaimPath = { "resource_access", "jellyfin", "roles" };

    private static int Main(string[] args)
    {
        var target = Environment.GetEnvironmentVariable("SSO_FUZZ_TARGET") ?? "saml";

        ReadOnlySpanAction run = target switch
        {
            "saml" => FuzzSamlResponse,
            "discovery" => FuzzOidcDiscovery,
            "idtoken" => FuzzOidcIdToken,
            "jwks" => FuzzJwks,
            "roles" => FuzzOidcRoles,
            _ => throw new ArgumentException(
                $"Unknown SSO_FUZZ_TARGET '{target}'. Expected one of: saml, discovery, idtoken, jwks, roles."),
        };

        // Smoke mode replays the seed corpus through the selected target once and exits, WITHOUT libFuzzer.
        // It proves the dispatch + parse wiring runs and that every seed is handled fail-closed (no unmapped
        // throw), so the harness can be validated on any platform - including the maintainer's Windows box,
        // where the Linux-only libFuzzer runtime is unavailable - and as a cheap CI sanity check. The real
        // coverage-guided run is the default path below.
        if (Environment.GetEnvironmentVariable("SSO_FUZZ_SMOKE") == "1")
        {
            return RunSmoke(run, target, args);
        }

        Fuzzer.LibFuzzer.Run(run);
        return 0;
    }

    // Feeds every seed file in the target's corpus directory through the target once. Any unmapped
    // exception propagates and fails the process - the same signal libFuzzer would record as a crash.
    private static int RunSmoke(ReadOnlySpanAction run, string target, string[] args)
    {
        var corpus = args.Length > 0
            ? args[0]
            : Environment.GetEnvironmentVariable("SSO_FUZZ_CORPUS") ?? Path.Combine("corpus", target);

        if (!Directory.Exists(corpus))
        {
            Console.Error.WriteLine($"Corpus directory not found: {corpus}");
            return 2;
        }

        var count = 0;
        foreach (var file in Directory.EnumerateFiles(corpus))
        {
            run(File.ReadAllBytes(file));
            count++;
        }

        Console.WriteLine($"Smoke OK: {count} seed(s) for target '{target}' handled fail-closed with no unmapped exception.");
        return 0;
    }

    // SAML: the base64 SAMLResponse form field from the anonymous assertion-consumer endpoint. Exercises
    // SamlResponseLoader.TryParse (base64 decode + hardened XML DOM load + certificate load) and, on a
    // successful parse, the full validate/claim-reader surface of SamlResponse - every one of which must
    // stay fail-closed and never throw an unmapped exception.
    private static void FuzzSamlResponse(ReadOnlySpan<byte> data)
    {
        var response = Encoding.UTF8.GetString(data);

        if (!SamlResponseLoader.TryParse(SamlCertificateBase64, response, out var saml) || saml is null)
        {
            return;
        }

        // A parsed-but-untrusted response: drive validation and every getter the callback reads. None may
        // throw. IsValid must stay false for fuzzer-generated bytes (no forged signature), but its RESULT
        // is not asserted - a legitimately signed seed would return true; only an exception is a finding.
        // Dispose the parsed response (it owns the certificate's unmanaged handle) after the drive (#674).
        using (saml)
        {
            saml.IsValid();
            _ = saml.GetSignatureAlgorithm();
            _ = saml.GetNameID();
            _ = saml.GetAssertionId();
            _ = saml.GetNotOnOrAfter();
            _ = saml.GetRecipient();
            _ = saml.GetInResponseTo();
            _ = saml.GetDestination();
            _ = saml.GetCustomAttributes("Role");
        }
    }

    // OpenID discovery document: the raw JSON the challenge fetches from the provider. Both pure readers
    // that interpret it must fail closed/tolerant on any malformed or hostile document and never throw an
    // unmapped exception (they catch only JsonException today).
    private static void FuzzOidcDiscovery(ReadOnlySpan<byte> data)
    {
        var json = Encoding.UTF8.GetString(data);

        _ = PkceDiscovery.SupportsS256(json);
        _ = OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(json);
    }

    // OpenID id_token: the raw JWT string. IdTokenIssuer parses the token to read its issuer for the
    // RFC 9207 mix-up check and must never throw on a degenerate/hostile token (it catches only
    // ArgumentException / SecurityTokenException today).
    private static void FuzzOidcIdToken(ReadOnlySpan<byte> data)
    {
        var token = Encoding.UTF8.GetString(data);

        _ = OidcResponseIssuer.IdTokenIssuer(token);
    }

    // Provider JWKS: the raw key-set JSON the challenge fetches from the provider's jwks_uri, converted
    // into the signing keys every verified token is checked against (OidcIdTokenValidator and
    // OidcLogoutTokenValidator both build their IssuerSigningKeys through OidcSignatureKeys.Convert).
    // These are provider bytes read before anything is trusted, and unlike the JSON readers above the
    // conversion touches key MATERIAL - a truncated modulus, an invalid EC point - which throws beyond
    // the JsonException those readers filter. Convert's own contract is that it never throws: it skips
    // the unusable key so one bad entry cannot take down verification against a good one. Anything that
    // escapes it is the finding.
    private static void FuzzJwks(ReadOnlySpan<byte> data)
    {
        var json = Encoding.UTF8.GetString(data);

        JsonWebKeySet keySet;
        try
        {
            keySet = new JsonWebKeySet(json);
        }
        catch (Exception)
        {
            // The library's own key-set parse, not the plugin's. On the real path it runs inside the
            // identity library's discovery call, under OidcDiscoveryReader's catch-all, so a throw here
            // is already fail-closed in production and is not a finding this harness should report.
            // Measured over ten hostile bodies: System.Text.Json.JsonException for a body that is not a
            // key set (garbage, truncated, a bare array, "keys" holding a string, a type-confused entry)
            // and ArgumentNullException for an empty one. The catch is wider than those two because the
            // property under test starts at Convert; a filter listing them would turn any other library
            // throw into a crasher this harness would report as a plugin finding.
            return;
        }

        // Convert collects disposable ECDsa handles for the caller to release, as the SAML target
        // disposes its parsed response. Released whatever Convert does, so an iteration cannot leak a
        // key handle into the next one.
        var ephemeralKeys = new List<IDisposable>();
        try
        {
            _ = OidcSignatureKeys.Convert(keySet, ephemeralKeys);
        }
        finally
        {
            foreach (var ephemeralKey in ephemeralKeys)
            {
                ephemeralKey.Dispose();
            }
        }
    }

    // OpenID role claim: the value of the claim the role-claim path names, which reaches the plugin from
    // the id_token or the UserInfo response and is provider-authored. OidcRoleExtractor.ExtractRoles parses
    // it as JSON and walks it, so it is a byte-level parse surface like the readers above, and today no
    // target feeds it.
    //
    // The path is FIXED so a seed and the driver cannot drift apart: every seed in corpus/roles is the value
    // of a `resource_access` claim under the path resource_access.jellyfin.roles, which is Keycloak's shape.
    // Both terminal shapes are driven from the one input span, because the shape is a per-provider setting
    // (RoleClaimIsObjectMap, #934) rather than a property of the bytes: the same document is a valid input
    // to either, and the mutator should reach both arms without needing two corpora.
    //
    // Only the harness's uniform property is asserted, by not catching: the call must terminate with a
    // fail-closed result or an exception the extractor maps. WHICH roles come back from an unreadable or
    // repeated-key claim is #1053's decision to make, and nothing here encodes an answer to it.
    private static void FuzzOidcRoles(ReadOnlySpan<byte> data)
    {
        var claimValue = Encoding.UTF8.GetString(data);

        _ = OidcRoleExtractor.ExtractRoles(RoleClaimPath, claimValue, terminalIsObjectMap: false);
        _ = OidcRoleExtractor.ExtractRoles(RoleClaimPath, claimValue, terminalIsObjectMap: true);
    }

    private static string CreateSelfSignedCertificateBase64()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Fuzz SAML IdP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        return Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
    }
}
