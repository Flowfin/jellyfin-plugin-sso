// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Captures every log entry as (level, formatted message) so a test can assert on what was emitted.
/// Shared by the audit-log tests and the config-store tests.
/// </summary>
internal sealed class CapturingLogger : ILogger
{
    // The exception is kept beside the message because a real sink renders the two SEPARATELY: an entry that
    // must carry a type name and nothing more looks identical, in its formatted message, to one that also
    // handed the exception object over. A test that only reads the message cannot tell those apart, so a
    // value the entry exists to withhold could reach the sink with every assertion still green (#1196).
    internal List<(LogLevel Level, string Message, Exception? Exception)> Records { get; } = new();

    internal List<(LogLevel Level, string Message)> Entries => Records.ConvertAll(r => (r.Level, r.Message));

    public IDisposable BeginScope<TState>(TState state)
        where TState : notnull => null!;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => Records.Add((logLevel, formatter(state, exception), exception));
}
