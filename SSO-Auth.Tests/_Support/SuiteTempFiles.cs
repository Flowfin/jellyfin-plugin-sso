// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>One directory per test run, owned by the suite, for the tests that write real files (#1218).</summary>
/// <remarks>
/// Key blobs written straight into the shared <c>Path.GetTempPath()</c> were swept between a write and the read after it. A suite-owned subdirectory does not make
/// the files un-deletable; it removes the exposure to a sweep aimed at the shared directory and makes the lifetime that of the suite.
/// </remarks>
internal static class SuiteTempFiles
{
    // Created on first use rather than in a static constructor, so a run that touches none of these tests
    // creates no directory at all. Lazy is thread-safe by default, which matters because the suite runs
    // its collections in parallel.
    private static readonly Lazy<string> RootDirectory = new(CreateRoot);

    /// <summary>
    /// A path inside this run's own directory, with a name unique per call. The file is NOT created; the
    /// caller writes it, exactly as it did when the path pointed at the shared temp directory.
    /// </summary>
    /// <param name="prefix">A short prefix naming the test family, kept so a leftover file still says where it came from.</param>
    /// <param name="extension">The file extension, including the dot.</param>
    /// <returns>The full path.</returns>
    internal static string Path(string prefix, string extension = ".key") =>
        System.IO.Path.Combine(RootDirectory.Value, prefix + "-" + Guid.NewGuid().ToString("N") + extension);

    private static string CreateRoot()
    {
        var root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sso-suite-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        // Best-effort removal at the end of the run. It is deliberately swallowed: a directory that could
        // not be deleted (a file still held open by a crashed run, a scanner holding a handle) must not
        // turn a green suite red on the way out, and the next run is unaffected because it creates its own.
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        };

        return root;
    }
}
