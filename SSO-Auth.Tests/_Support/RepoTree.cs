// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The repository root, for the source-scanning rules that need the tree rather than the assembly (#1189).
/// <para>
/// Every such rule used to carry its own walk-up, and the count only ever went up: six copies across the
/// test project on the day this landed. Each one counted the levels between its own file and the root by
/// hand - one for a file at the test-project root, two for a file in a subfolder - so the copies were not
/// interchangeable, and a rule file moved between folders would resolve a root one level off and scan a
/// tree that is not the repository. Nothing catches that, in either direction: a scan over the wrong root
/// reports the same all-clear as a scan that found nothing wrong.
/// </para>
/// <para>
/// So the root is not counted here, it is SEARCHED for, by walking up until the solution file appears. The
/// search starts from this file rather than from the caller's, which is why moving a rule file cannot move
/// the answer: no rule contributes a path any more. A checkout with no solution file at any level throws
/// rather than returning a directory that is not the root, because the wrong root is the failure this type
/// exists to remove and returning one silently would reintroduce it in a new place.
/// </para>
/// </summary>
internal static class RepoTree
{
    // Searched for rather than counted, so the answer does not depend on how deep this file sits. The call
    // is written out rather than passed as a method group because the compiler fills the caller path in at
    // the CALL site, and a method group would give the lambda nothing to fill in.
    private static readonly Lazy<string> RootDirectory = new(() => Find());

    /// <summary>
    /// Gets the absolute path of the repository root - the directory holding <c>SSO-Auth.sln</c>.
    /// </summary>
    internal static string Root => RootDirectory.Value;

    // The marker is the solution file: it is at the root, it is tracked, and it is the one thing a checkout
    // of this repository cannot be missing. A directory name would not do - a checkout can be cloned into a
    // directory called anything - and .git would not either, since a worktree carries a FILE by that name.
    private static string Find([CallerFilePath] string thisFilePath = "")
    {
        var directory = new DirectoryInfo(Path.GetDirectoryName(thisFilePath)!);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "SSO-Auth.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            $"No SSO-Auth.sln above {thisFilePath}, so the repository root cannot be resolved. The source-scanning rules read the tree, and a wrong root would let them scan a tree that is not the repository and report an all-clear.");
    }
}
