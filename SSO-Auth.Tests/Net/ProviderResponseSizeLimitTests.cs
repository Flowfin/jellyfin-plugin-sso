// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The outbound response-size bound (#1169, part of #1041). One named limit, enforced once at the seam every
/// server-to-provider call passes through, so an anonymous challenge cannot be made to allocate without bound
/// by a hostile or compromised authorization server.
/// <para>
/// Timeouts already bound how LONG a slow server can hold the endpoint. Nothing bounded how MUCH a fast one
/// could make it allocate, and the discovery body is parsed several times over, so a large body cost a
/// multiple of its own size on a route that needs no credential to reach.
/// </para>
/// </summary>
public sealed class ProviderResponseSizeLimitTests
{
    private const long Max = ProviderResponseSizeLimit.MaxProviderResponseBytes;

    [Fact]
    public async Task AnAdvertisedLengthOverTheBound_IsRefusedWithoutReadingTheBody()
    {
        // The cheap path: Content-Length alone is enough to refuse, and the body is never touched. The
        // counter below proves "never touched" rather than assuming it - a bound that still reads the
        // megabytes it is refusing would not be a bound on allocation at all.
        var bodyReads = 0;
        using var client = Client(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new CountingContent(new string('a', 32), () => bodyReads++, declaredLength: Max + 1),
        });

        var ex = await Assert.ThrowsAsync<ProviderResponseTooLargeException>(
            () => client.GetStringAsync("https://idp.example.test/.well-known/openid-configuration", TestContext.Current.CancellationToken));

        Assert.Equal(Max, ex.MaxBytes);
        Assert.Equal(0, bodyReads);
    }

    [Fact]
    public async Task ABodyOverTheBound_WithNoAdvertisedLength_IsStillRefused()
    {
        // A server that sends no Content-Length (chunked) or lies about it walks straight past the header
        // check. The bound has to be on bytes actually delivered, so this is the row that makes it a bound
        // rather than a courtesy - and it is the shape a hostile server would pick precisely because the
        // cheap check cannot see it.
        using var client = Client(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new UndeclaredLengthContent((int)Max + 4096),
        });

        var ex = await Record.ExceptionAsync(
            () => client.GetStringAsync("https://idp.example.test/.well-known/openid-configuration", TestContext.Current.CancellationToken));

        // Asserted on the whole exception chain rather than on the outermost type: HttpClient buffers the
        // body itself and may re-wrap what the stream threw, so pinning only the top type would pin a
        // runtime detail. What must hold is that the refusal reaches the caller as a fail-closed transport
        // failure and that this bound is identifiably the reason.
        Assert.NotNull(ex);
        Assert.IsAssignableFrom<HttpRequestException>(ex);
        Assert.Contains(Unwrap(ex), e => e is ProviderResponseTooLargeException);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1024)]
    [InlineData(64 * 1024)]
    public async Task ADocumentUnderTheBound_IsDeliveredByteForByte(int size)
    {
        // The positive control, and the one that matters most. A bound nobody surveyed against real documents
        // buys a hypothetical attack for a real provider lockout, so the sizes here bracket what a discovery
        // document, a JWKS and a UserInfo response actually are: single- to low-double-digit KB.
        var body = new string('x', size);
        using var client = Client(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });

        var received = await client.GetStringAsync("https://idp.example.test/jwks", TestContext.Current.CancellationToken);

        Assert.Equal(body, received);
    }

    [Fact]
    public async Task ABodyExactlyAtTheBound_IsDelivered()
    {
        // The boundary is pinned from the permitted side too, so a future off-by-one that starts refusing at
        // exactly the limit is a red test rather than a provider that mysteriously stops working.
        using var client = Client(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new UndeclaredLengthContent((int)Max) });

        var received = await client.GetByteArrayAsync("https://idp.example.test/jwks", TestContext.Current.CancellationToken);

        Assert.Equal(Max, received.LongLength);
    }

    [Fact]
    public async Task TheContentTypeSurvivesTheSubstitution()
    {
        // The limiter replaces the response content in order to count what comes out of it. The charset the
        // identity library and the repeated-member screen both decode by travels on Content-Type, so losing
        // it here would silently change how every provider body is read.
        using var client = Client(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        });

        using var response = await client.GetAsync("https://idp.example.test/jwks", TestContext.Current.CancellationToken);

        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("utf-8", response.Content.Headers.ContentType?.CharSet);
    }

    private static System.Collections.Generic.IEnumerable<Exception> Unwrap(Exception? ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
        {
            yield return e;
        }
    }

    private static HttpClient Client(Func<HttpRequestMessage, HttpResponseMessage> respond) =>
        new(new ProviderResponseSizeLimit { InnerHandler = new StubHttpMessageHandler(respond) });

    // Content that reports a length of the caller's choosing while holding a short body, so a test can prove
    // the header check refuses before the body is read.
    private sealed class CountingContent : HttpContent
    {
        private readonly byte[] _body;
        private readonly Action _onRead;

        internal CountingContent(string body, Action onRead, long declaredLength)
        {
            _body = Encoding.UTF8.GetBytes(body);
            _onRead = onRead;
            Headers.ContentLength = declaredLength;
        }

        protected override Task SerializeToStreamAsync(System.IO.Stream stream, System.Net.TransportContext? context)
        {
            _onRead();
            return stream.WriteAsync(_body, 0, _body.Length);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = Headers.ContentLength ?? 0;
            return true;
        }
    }

    // Content that refuses to state its length, which is what a chunked response looks like to the handler.
    private sealed class UndeclaredLengthContent : HttpContent
    {
        private readonly int _size;

        internal UndeclaredLengthContent(int size) => _size = size;

        protected override async Task SerializeToStreamAsync(System.IO.Stream stream, System.Net.TransportContext? context)
        {
            var chunk = new byte[8192];
            Array.Fill(chunk, (byte)'y');
            for (var written = 0; written < _size;)
            {
                var next = Math.Min(chunk.Length, _size - written);
                await stream.WriteAsync(chunk.AsMemory(0, next), CancellationToken.None).ConfigureAwait(false);
                written += next;
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }
}
