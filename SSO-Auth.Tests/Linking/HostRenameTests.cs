// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Binding <c>RenameUser</c> against whichever shape the loaded server exposes (#1138).
/// </summary>
/// <remarks>
/// <para>
/// `IUserManager.RenameUser` changed arity inside the supported range. Measured against the tags:
/// v10.11.0 to v10.11.8 declare <c>RenameUser(User, string)</c>, and v10.11.9 onwards
/// <c>RenameUser(Guid, string, string)</c>. The repository declares <c>targetAbi: "10.11.0.0"</c>, so a
/// source reference to either shape breaks one of the two builds.
/// </para>
/// <para>
/// WHY THESE ROWS USE HAND-WRITTEN TYPES RATHER THAN A FAKE IUserManager. A substitute for the interface can
/// only ever carry the shape this assembly compiled against, which is the arm that was never in doubt. The
/// arm that matters is the one on a server this build cannot see, and the only way to hand the resolver that
/// shape is to declare it here.
/// </para>
/// </remarks>
public class HostRenameTests
{
    private static readonly Guid Account = Guid.Parse("66666666-6666-6666-6666-666666666666");

    /// <summary>A server on the current line: three arguments, keyed by id.</summary>
    private sealed class CurrentLine
    {
        public Task RenameUser(Guid userId, string oldName, string newName) => Task.CompletedTask;
    }

    /// <summary>A server on the floor: two arguments, taking the account itself.</summary>
    private sealed class AtTheFloor
    {
        public Task RenameUser(User user, string newName) => Task.CompletedTask;
    }

    /// <summary>A server exposing both, which no released Jellyfin does.</summary>
    private sealed class BothShapes
    {
        public Task RenameUser(Guid userId, string oldName, string newName) => Task.CompletedTask;

        public Task RenameUser(User user, string newName) => Task.CompletedTask;
    }

    /// <summary>A server exposing neither.</summary>
    private sealed class NoShape
    {
    }

    [Fact]
    public void OnTheCurrentLine_TheThreeArgumentShapeIsBoundWithIdAndBothNames()
    {
        var call = HostRename.Resolve(typeof(CurrentLine), null, Account, "alice.old", "alice.new");

        Assert.NotNull(call);
        Assert.Equal(3, call.Value.Method.GetParameters().Length);
        Assert.Equal(new object?[] { Account, "alice.old", "alice.new" }, call.Value.Arguments);
    }

    /// <summary>
    /// The arm that a fake <c>IUserManager</c> cannot reach, and the reason this file exists.
    /// </summary>
    [Fact]
    public void AtTheAbiFloor_TheTwoArgumentShapeIsBoundWithTheAccountAndTheNewName()
    {
        var account = new User("alice.old", "prov", "reset");

        var call = HostRename.Resolve(typeof(AtTheFloor), account, Account, "alice.old", "alice.new");

        Assert.NotNull(call);
        Assert.Equal(2, call.Value.Method.GetParameters().Length);
        Assert.Equal(new object?[] { account, "alice.new" }, call.Value.Arguments);
    }

    /// <summary>
    /// The current line wins where both are present, so the common case never falls through to a lookup it
    /// does not need and no server ever gets the older call while offering the newer one.
    /// </summary>
    [Fact]
    public void WhereBothArePresent_TheCurrentLineIsPreferred()
    {
        var call = HostRename.Resolve(typeof(BothShapes), new User("alice.old", "prov", "reset"), Account, "alice.old", "alice.new");

        Assert.NotNull(call);
        Assert.Equal(3, call.Value.Method.GetParameters().Length);
    }

    /// <summary>
    /// Neither shape resolves to nothing rather than to something wrong. The caller turns this into the
    /// refusal sentence, which its own broad catch logs and swallows: on such a server the account keeps its
    /// name and the login proceeds, which is what the feature being off would also do.
    /// </summary>
    [Fact]
    public void WhereNeitherIsPresent_NothingIsBound()
    {
        Assert.Null(HostRename.Resolve(typeof(NoShape), new User("alice.old", "prov", "reset"), Account, "alice.old", "alice.new"));
    }

    /// <summary>
    /// The sentence names both signatures, because an admin reading it in a log needs to know what their
    /// server was asked for rather than that something reflective did not work.
    /// </summary>
    [Theory]
    [InlineData("RenameUser(Guid, string, string)")]
    [InlineData("RenameUser(User, string)")]
    public void TheRefusalNamesBothSignatures(string signature)
    {
        Assert.Contains(signature, HostRename.NeitherShape, StringComparison.Ordinal);
    }
}
