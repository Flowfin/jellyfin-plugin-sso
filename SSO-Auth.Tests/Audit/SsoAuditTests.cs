// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SsoAudit"/> - the structured security audit-log entries (#928 U1). Every
/// method is pinned on three properties: the level it fires at, the "[SSO Audit]" prefix plus its
/// key fields, and the two inline sanitizers on EVERY foreign caller-supplied string so an identity-
/// provider- or admin-supplied value can neither SPLIT an entry (the line-ending strip) nor forge a
/// second one inside the line it lands in (the bracket substitution, #1555). A filesystem path this
/// server composed for itself is not a foreign value and deliberately carries only the first, because
/// the exact text is the actionable content of the line it appears in. The sensitive-data posture
/// is structural - the signatures accept no secret, token, NameID or SessionIndex - and the fixed-
/// code discipline (reason codes are enum names/constants, never request-derived text) is asserted
/// where a code parameter exists.
/// </summary>
public class SsoAuditTests
{
    [Fact]
    public void InsecureOptionsEnabled_LogsWarning_NamingProviderAndOptions()
    {
        var logger = new CapturingLogger();

        SsoAudit.InsecureOptionsEnabled(logger, "OpenID", "corp", new[] { "DisableHttps", "DoNotValidateEndpoints" });

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corp", entry.Message, StringComparison.Ordinal);
        Assert.Contains("DisableHttps", entry.Message, StringComparison.Ordinal);
        Assert.Contains("DoNotValidateEndpoints", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void InsecureOptionsEnabled_StripsLineEndingsFromProviderName()
    {
        var logger = new CapturingLogger();

        // A provider name carrying a newline must not split the entry - the sanitizer collapses it.
        SsoAudit.InsecureOptionsEnabled(logger, "OpenID", "corp\r\nInjected", new[] { "DisableHttps" });

        var message = Assert.Single(logger.Entries).Message;
        Assert.DoesNotContain("\n", message, StringComparison.Ordinal);
        Assert.Contains("corpInjected", message, StringComparison.Ordinal);
    }

    [Fact]
    public void LoginSucceeded_LogsInformation_NamingUserProtocolProviderAndAdminFlag()
    {
        var logger = new CapturingLogger();

        SsoAudit.LoginSucceeded(logger, "OpenID", "corp", "alice", isAdmin: true);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("alice", entry.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corp", entry.Message, StringComparison.Ordinal);
        Assert.Contains("admin=True", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LoginSucceeded_StripsLineEndings_FromUsernameAndProvider()
    {
        var logger = new CapturingLogger();

        // Both the username (IdP-derived) and the provider (route/admin input) are foreign values.
        SsoAudit.LoginSucceeded(logger, "SAML", "corp\nX", "ali\r\nce", isAdmin: false);

        var message = Assert.Single(logger.Entries).Message;
        Assert.DoesNotContain("\n", message, StringComparison.Ordinal);
        Assert.Contains("alice", message, StringComparison.Ordinal);
        Assert.Contains("corpX", message, StringComparison.Ordinal);
    }

    [Fact]
    public void LoginSucceeded_StripsLineEndings_FromTheProviderPresentedName()
    {
        // The presented name is a second identity-provider-supplied value in the same template (#1551), so
        // it is a second forging surface and carries the same inline sanitizer as the first.
        var logger = new CapturingLogger();

        SsoAudit.LoginSucceeded(logger, "OpenID", "corp", "alice.jellyfin", isAdmin: false, presentedUsername: "ali\r\n[SSO Audit] forged");

        var message = Assert.Single(logger.Entries).Message;
        Assert.DoesNotContain("\n", message, StringComparison.Ordinal);
        Assert.Contains("Login succeeded: alice.jellyfin", message, StringComparison.Ordinal);

        // THIS ROW ASSERTED THE FORGED MARKER SURVIVED UNTIL #1555, and that was the defect stated as an
        // expectation: the fixture's own name carries the audit prefix, the line-ending strip left it
        // whole, and an unanchored search over the trail then matched a record nothing emitted. The
        // line-ending property this row exists for is unchanged - the two halves of the name are joined
        // and no newline reaches the message - and the marker cannot open a second record beside it.
        Assert.Contains("presented the name 'ali(SSO Audit] forged'", message, StringComparison.Ordinal);
    }

    [Fact]
    public void LoginSucceeded_APresentedNameDifferingOnlyInStrippedCharacters_AddsNothingToTheLine()
    {
        // The decision is taken on what the line will PRINT, not on the raw values. Compared raw, these two
        // are different strings; printed, they are the same name - so a raw comparison emits a line asserting
        // a difference and then showing two identical names, which an identity provider can produce at will
        // just by appending a newline to the name it presents.
        var logger = new CapturingLogger();

        SsoAudit.LoginSucceeded(logger, "OpenID", "corp", "alice", isAdmin: false, presentedUsername: "alice\r\n");

        var message = Assert.Single(logger.Entries).Message;
        Assert.Equal("[SSO Audit] Login succeeded: alice via OpenID provider 'corp' (admin=False).", message);
    }

    [Fact]
    public void LoginSucceeded_APresentedNameEqualToTheAccountName_AddsNothingToTheLine()
    {
        // The clause exists for the drift arm only. Every other login writes what it always wrote, and this
        // is the row that fails if the comparison is dropped and the clause becomes unconditional.
        var logger = new CapturingLogger();

        SsoAudit.LoginSucceeded(logger, "OpenID", "corp", "alice", isAdmin: false, presentedUsername: "alice");

        var message = Assert.Single(logger.Entries).Message;
        Assert.Equal("[SSO Audit] Login succeeded: alice via OpenID provider 'corp' (admin=False).", message);
    }

    [Fact]
    public void ProvisionedPendingApproval_LogsWarning_SayingNoSessionWasIssued()
    {
        var logger = new CapturingLogger();

        SsoAudit.ProvisionedPendingApproval(logger, "OpenID", "corp", "newbie\r\nX");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("newbieX", entry.Message, StringComparison.Ordinal);
        Assert.Contains("no session issued", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AccountAdopted_LogsWarning_NamingTheAdoptedAccountAndStrippingLineEndings()
    {
        var logger = new CapturingLogger();

        SsoAudit.AccountAdopted(logger, "SAML", "corp\rX", "vic\ntim");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("victim", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corpX", entry.Message, StringComparison.Ordinal);
        Assert.Contains("AllowExistingAccountLink", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AccountDeprovisioned_LogsWarning_NamingProtocolAndProvider_ButNeverASubject()
    {
        var logger = new CapturingLogger();

        // The provider is the only foreign value the signature accepts (there IS no subject/username
        // parameter - the no-sensitive-data posture is structural, T-I1). A newline in it must not split
        // the entry, and the fixed toggle name gives the operator the exact setting to check.
        SsoAudit.AccountDeprovisioned(logger, "OpenID", "corp\r\nInjected");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corpInjected", entry.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID", entry.Message, StringComparison.Ordinal);
        Assert.Contains("DisableAccountOnRoleDenied", entry.Message, StringComparison.Ordinal);
        Assert.Contains("Administrators are never disabled", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ProviderConfiguredAndRemoved_LogInformation_AndStripTheProviderName(bool configured)
    {
        var logger = new CapturingLogger();

        if (configured)
        {
            SsoAudit.ProviderConfigured(logger, "OpenID", "corp\r\nX");
        }
        else
        {
            SsoAudit.ProviderRemoved(logger, "OpenID", "corp\r\nX");
        }

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains(configured ? "configured" : "removed", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corpX", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PkceNotAdvertised_LogsWarning_PointingAtRequirePkce_AndStripsTheProviderName()
    {
        var logger = new CapturingLogger();

        SsoAudit.PkceNotAdvertised(logger, "corp\nX");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corpX", entry.Message, StringComparison.Ordinal);
        Assert.Contains("RequirePkce", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ConfigImported_LogsWarning_WithTheMergedProviderCounts()
    {
        var logger = new CapturingLogger();

        SsoAudit.ConfigImported(logger, oidProviders: 2, samlProviders: 1);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("2 OpenID", entry.Message, StringComparison.Ordinal);
        Assert.Contains("1 SAML", entry.Message, StringComparison.Ordinal);
        Assert.Contains("re-entered", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LinkPreprovisioned_LogsWarning_WithTheActorProviderAndTarget_ButNoSubject()
    {
        // The audit line for a grant made on an administrator credential alone (#1133). The canonical
        // subject is withheld deliberately: it identifies a real person at the identity provider, and the
        // provider plus the target account are what an operator needs to find the grant.
        var logger = new CapturingLogger();
        var target = Guid.Parse("a11ce000-0000-0000-0000-000000000001");

        SsoAudit.LinkPreprovisioned(logger, "admin", "OpenID", "idp", target);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("admin", entry.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID", entry.Message, StringComparison.Ordinal);
        Assert.Contains("idp", entry.Message, StringComparison.Ordinal);
        Assert.Contains(target.ToString(), entry.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LinkPreprovisioned_StripsLineEndings_SoAnActorOrProviderCannotForgeALogLine()
    {
        // Log forging (cs/log-forging): the actor is a username and the provider is a stored name, and a
        // line ending in either would let a second, fabricated audit line be written by the first.
        var logger = new CapturingLogger();

        SsoAudit.LinkPreprovisioned(logger, "admin\r\n[SSO Audit] forged", "OpenID", "idp\nforged", Guid.Empty);

        var entry = Assert.Single(logger.Entries);
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LogoutRequested_LogsInformation_WithProviderAndCountOnly()
    {
        var logger = new CapturingLogger();

        SsoAudit.LogoutRequested(logger, "corp\r\nX", usersRevoked: 3);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corpX", entry.Message, StringComparison.Ordinal);
        Assert.Contains("3 user(s)", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LogoutRejected_LogsWarning_WithTheFixedReasonCode_AndNoSessionTerminated()
    {
        var logger = new CapturingLogger();

        // The reason is a FIXED code (an enum member name), never request-derived text - the caller
        // contract SSOControllerSamlLogoutTests pins from the validator side.
        SsoAudit.LogoutRejected(logger, "corp\nX", "Replay");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corpX", entry.Message, StringComparison.Ordinal);
        Assert.Contains("Replay", entry.Message, StringComparison.Ordinal);
        Assert.Contains("No session was terminated", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void BackChannelLogoutRejected_LogsWarning_AndDoesNotFileItselfUnderSaml()
    {
        var logger = new CapturingLogger();

        SsoAudit.BackChannelLogoutRejected(logger, "corp\nX", OidcLogoutTokenValidator.RejectReason.Replay);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID back-channel logout", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corpX", entry.Message, StringComparison.Ordinal);
        Assert.Contains(OidcLogoutTokenValidator.RejectReason.Replay, entry.Message, StringComparison.Ordinal);
        Assert.Contains("No session was terminated", entry.Message, StringComparison.Ordinal);

        // An operator filtering for OpenID logout failures used to find them all worded as SAML, because the
        // OpenID sites called the shared SAML helper (#1184).
        Assert.DoesNotContain("SAML", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void BackChannelLogoutNotPerformed_IsAnErrorAndSaysTheTerminationDidNotHappen()
    {
        var logger = new CapturingLogger();

        SsoAudit.BackChannelLogoutNotPerformed(logger, "corp\nX", OidcLogoutTokenValidator.RejectReason.ProviderUnreachable);

        var entry = Assert.Single(logger.Entries);

        // The severity is the filter an operator alerts on, so it is asserted rather than the wording alone:
        // a revocation the IdP ordered and the plugin did not perform must not sit at the same level as the
        // forged tokens it is supposed to stand out from.
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("could NOT be performed", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corpX", entry.Message, StringComparison.Ordinal);
        Assert.Contains(OidcLogoutTokenValidator.RejectReason.ProviderUnreachable, entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("SAML", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void BackChannelLogoutNotPerformed_StillEmitsWhereWarningsAreOff()
    {
        // The counterpart to the IsEnabled row below: the two events differ by severity, so the one an
        // operator pages on must survive a sink that has already filtered the rejection noise away.
        var warningsOff = new LevelFilteredLogger(minimum: LogLevel.Error);

        SsoAudit.BackChannelLogoutRejected(warningsOff, "corp", OidcLogoutTokenValidator.RejectReason.Replay);
        SsoAudit.BackChannelLogoutNotPerformed(warningsOff, "corp", OidcLogoutTokenValidator.RejectReason.ProviderUnreachable);

        var entry = Assert.Single(warningsOff.Entries);
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Contains("could NOT be performed", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryEntry_CarriesTheFilterablePrefix_AndInformationLevelEmissionsRespectIsEnabled()
    {
        // The IsEnabled guard exists so the inline sanitizer is not evaluated when the level is off
        // (CA1873); a disabled level must emit NOTHING rather than an unsanitized fallback.
        var off = new LevelFilteredLogger(minimum: LogLevel.Error);

        SsoAudit.LoginSucceeded(off, "OpenID", "corp", "alice", isAdmin: false);
        SsoAudit.ProviderConfigured(off, "OpenID", "corp");
        SsoAudit.LogoutRequested(off, "corp", 1);
        SsoAudit.ProvisionedPendingApproval(off, "OpenID", "corp", "u");
        SsoAudit.AccountAdopted(off, "OpenID", "corp", "u");
        SsoAudit.AccountDeprovisioned(off, "OpenID", "corp");
        SsoAudit.PkceNotAdvertised(off, "corp");
        SsoAudit.LogoutRejected(off, "corp", "Replay");
        SsoAudit.BackChannelLogoutRejected(off, "corp", OidcLogoutTokenValidator.RejectReason.Replay);

        Assert.Empty(off.Entries);
    }

    [Fact]
    public void TheRollbackAndPersistenceLines_RespectIsEnabled_AndTolerateNoLoggerAtAll()
    {
        // The same IsEnabled contract as the row above, for the lines #1521 and #1533 added, and at BOTH
        // severities: two of them are Error, which a sink filtered to Warning would still take, so the
        // level has to be off entirely to prove the guard rather than the sink. The null arm is not
        // decoration either - ProviderConfigStore is constructed with a null logger by callers that want
        // no audit at all, and an audit line that dereferenced it would fail the write it is reporting on.
        var off = new LevelFilteredLogger(minimum: LogLevel.None);

        SsoAudit.ConfigurationRollbackUnavailable(off, new InvalidOperationException("x"));
        SsoAudit.ConfigurationRollbackFailed(off, new InvalidOperationException("x"));
        SsoAudit.ConfigurationChangedSubscriberFailed(off, new InvalidOperationException("x"));
        SsoAudit.ProvisionedAccountRolledBack(off, "SAML", "corp", "alice");
        SsoAudit.ProvisionedAccountRollbackFailed(off, "alice", new InvalidOperationException("x"));

        Assert.Empty(off.Entries);

        SsoAudit.ConfigurationRollbackUnavailable(null!, new InvalidOperationException("x"));
        SsoAudit.ConfigurationRollbackFailed(null!, new InvalidOperationException("x"));
        SsoAudit.ConfigurationChangedSubscriberFailed(null!, new InvalidOperationException("x"));
        SsoAudit.ProvisionedAccountRolledBack(null!, "SAML", "corp", "alice");
        SsoAudit.ProvisionedAccountRollbackFailed(null!, "alice", new InvalidOperationException("x"));
    }

    [Fact]
    public void TheRollbackLines_CarryThePrefix_AndStripLineEndings()
    {
        // A rollback line is what an operator finds above the failure that caused it, so it has to be
        // filterable by the same prefix as every other audit line and carry no injected line break - the
        // exception message and the username both arrive from outside this plugin.
        var log = new CapturingLogger();

        SsoAudit.ProvisionedAccountRolledBack(log, "SAML", "corp\nEVIL", "ali\nce");
        SsoAudit.ProvisionedAccountRollbackFailed(log, "ali\nce", new InvalidOperationException("boom\nEVIL"));
        SsoAudit.ConfigurationRollbackUnavailable(log, new InvalidOperationException("boom\nEVIL"));
        SsoAudit.ConfigurationRollbackFailed(log, new InvalidOperationException("boom\nEVIL"));
        SsoAudit.ConfigurationChangedSubscriberFailed(log, new InvalidOperationException("boom\nEVIL"));

        Assert.Equal(5, log.Entries.Count);
        Assert.All(log.Entries, e => Assert.StartsWith("[SSO Audit]", e.Message, StringComparison.Ordinal));
        Assert.All(log.Entries, e => Assert.DoesNotContain("\n", e.Message, StringComparison.Ordinal));
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Error);
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public void TheRollbackLines_SurviveNullFields()
    {
        // Every field on these lines is null-conditional, and this is what proves those arms are reachable
        // rather than decoration. A rollback line reports a failure that has already happened; one that
        // threw on a null provider name would replace the diagnosis with a second fault, on the exact path
        // an operator is trying to read.
        var log = new CapturingLogger();

        SsoAudit.ProvisionedAccountRolledBack(log, null!, null!, null!);
        SsoAudit.ProvisionedAccountRollbackFailed(log, null!, null!);
        SsoAudit.ConfigurationRollbackUnavailable(log, null!);
        SsoAudit.ConfigurationRollbackFailed(log, null!);
        SsoAudit.ConfigurationChangedSubscriberFailed(log, null!);

        Assert.Equal(5, log.Entries.Count);
        Assert.All(log.Entries, e => Assert.StartsWith("[SSO Audit]", e.Message, StringComparison.Ordinal));
    }

    // The payload of #1555, verbatim: a presented name whose text closes the sentence it lands in and
    // then opens a whole second, plausible record on the SAME physical line. Stripping line endings does
    // not touch it - it forges no new line - so an unanchored search or a SIEM substring rule reports a
    // login by "root" that never happened. The bracket escape is what makes the marker unforgeable, and
    // these two rows redden the moment it is taken back off the emitter.
    private const string SecondRecordPayload =
        "x'. [SSO Audit] Login succeeded: root via OpenID provider 'corp' (admin=True). The provider presented the name 'root";

    [Fact]
    public void LoginSucceeded_APresentedNameForgingASecondRecord_LeavesOneAuditMarkerOnTheLine()
    {
        var logger = new CapturingLogger();

        // Both foreign values of this entry carry the payload, so the row reddens whichever of the two
        // loses its substitution. The account name cannot carry one in practice - Jellyfin's own
        // allowlist admits no bracket - which is exactly why the provider name is the second here.
        SsoAudit.LoginSucceeded(logger, "OpenID", SecondRecordPayload, "eve", isAdmin: false, presentedUsername: SecondRecordPayload);

        var message = Assert.Single(logger.Entries).Message;
        Assert.Equal(1, CountMarkers(message));
        Assert.StartsWith("[SSO Audit]", message, StringComparison.Ordinal);

        // The forged record is what a reader is meant not to be able to find, so the assertion is on the
        // text a search would look for rather than on the escape that prevents it.
        Assert.DoesNotContain("[SSO Audit] Login succeeded: root", message, StringComparison.Ordinal);
    }

    [Fact]
    public void AccountRenamed_AForeignNameForgingASecondRecord_LeavesOneAuditMarkerOnTheLine()
    {
        var logger = new CapturingLogger();

        // The shape reaches every entry carrying a foreign value, not the login line alone, which is why
        // the repair sits on the emitter rather than on one entry. EVERY foreign argument of this entry
        // carries the payload - the provider name as well as both account names - so the row reddens if
        // the substitution is dropped from any one of the three. What it does NOT hold down is the other
        // emitters, and that is what the conformance rule over this file is for.
        SsoAudit.AccountRenamed(logger, "OpenID", SecondRecordPayload, SecondRecordPayload, SecondRecordPayload);

        var message = Assert.Single(logger.Entries).Message;
        Assert.Equal(1, CountMarkers(message));
        Assert.DoesNotContain("[SSO Audit] Login succeeded: root", message, StringComparison.Ordinal);
    }

    private static int CountMarkers(string message)
    {
        var markers = 0;
        for (var at = message.IndexOf("[SSO Audit] ", StringComparison.Ordinal); at >= 0; at = message.IndexOf("[SSO Audit] ", at + 1, StringComparison.Ordinal))
        {
            markers++;
        }

        return markers;
    }

    private sealed class LevelFilteredLogger : ILogger
    {
        private readonly LogLevel _minimum;

        internal LevelFilteredLogger(LogLevel minimum) => _minimum = minimum;

        internal System.Collections.Generic.List<(LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable BeginScope<TState>(TState state)
            where TState : notnull => null!;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= _minimum;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                Entries.Add((logLevel, formatter(state, exception)));
            }
        }
    }
}
