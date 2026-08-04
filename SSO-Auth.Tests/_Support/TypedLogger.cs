// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Presents a <see cref="CapturingLogger"/> as the generic <see cref="ILogger{TCategoryName}"/> a component
/// asks its constructor for, so a test can read back what that component logged. Nothing is reinterpreted:
/// every call is forwarded unchanged to the capturing logger.
/// </summary>
/// <typeparam name="T">The category the component was written against.</typeparam>
internal sealed class TypedLogger<T> : ILogger<T>
{
    private readonly CapturingLogger _inner;

    internal TypedLogger(CapturingLogger inner) => _inner = inner;

    public IDisposable BeginScope<TState>(TState state)
        where TState : notnull => _inner.BeginScope(state);

    public bool IsEnabled(LogLevel logLevel) => _inner.IsEnabled(logLevel);

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        _inner.Log(logLevel, eventId, state, exception, formatter);
}
