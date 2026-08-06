// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Jellyfin.Plugin.SSO_Auth.Api.Net;

/// <summary>
/// Refuses an over-large provider response at the plugin's outbound seam, before any parser sees the body
/// (#1169, part of #1041). Registered on both named outbound clients, so every server-to-provider call on the
/// login path is bounded from ONE place rather than per call site.
///
/// Position is the point. Three of the four fetches this bounds - JWKS, token and UserInfo - happen INSIDE
/// <c>Duende.IdentityModel.OidcClient</c>, over the client the plugin hands it, so there is no plugin call
/// site to guard for them. The fourth, the discovery read, is buffered whole by
/// <see cref="Oidc.RepeatedMemberScreen"/> before it is inspected, so a bound applied any later than here
/// would arrive after the allocation it exists to prevent.
///
/// What it bounds is allocation, not time. <c>OidcDiscoveryReader.FetchTimeout</c> already bounds how LONG a
/// slow server can hold the anonymous challenge endpoint open; nothing bounded how MUCH a fast one could make
/// it allocate, and the discovery body is parsed several times over, so a large body cost a multiple of its
/// own size on a route that needs no credential to reach.
/// </summary>
internal sealed class ProviderResponseSizeLimit : DelegatingHandler
{
    /// <summary>
    /// The most a provider response may carry before it is refused unread.
    ///
    /// Chosen against the largest document any consumer of this seam legitimately parses, which is SAML
    /// federation metadata: <see cref="Saml.SamlMetadataParser.MaxCharactersInDocument"/> caps that reader at
    /// 256 KiB, and <c>SamlMetadataImporter</c> enforces the same 256 KiB on its own read. An OpenID
    /// discovery document, a JWKS, a token response and a UserInfo document are single- to low-double-digit
    /// KB. So this bound sits four times above the largest legitimate document and roughly two orders of
    /// magnitude above the routine ones.
    ///
    /// Deliberately loose rather than tight, for the same reason the <c>kid</c> length cap is: the value
    /// being bounded at all is what closes the unbounded-allocation hole, while a tight bound would trade a
    /// hypothetical attack for a real lockout of a provider nobody surveyed. It is also deliberately ABOVE
    /// the SAML importer's own 256 KiB, so that importer keeps reporting its own clearer message and this
    /// seam never pre-empts it.
    ///
    /// The avatar fetch does not pass here - it builds its client directly on
    /// <see cref="SsoHttp.CreateHardenedHandler"/> and carries its own, much larger
    /// <c>AvatarService.MaxAvatarBytes</c>, because an image is legitimately megabytes where a metadata
    /// document is not. That separation is intended, not an oversight.
    /// </summary>
    internal const long MaxProviderResponseBytes = 1024 * 1024;

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        // The advertised length, when there is one: refusing here costs nothing and never reads the body at
        // all. A server that lies about it, or sends none (chunked), is caught by the counting stream below,
        // so this check is the cheap path rather than the guarantee.
        if (response.Content.Headers.ContentLength > MaxProviderResponseBytes)
        {
            response.Dispose();
            throw new ProviderResponseTooLargeException(MaxProviderResponseBytes);
        }

        var body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var bounded = new StreamContent(new BoundedStream(body, MaxProviderResponseBytes));

        // Carry the original headers across, so Content-Type (and the charset the library and the
        // repeated-member screen both decode by) survives the substitution unchanged.
        foreach (var header in response.Content.Headers)
        {
            bounded.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        response.Content = bounded;
        return response;
    }

    /// <summary>
    /// A read-only pass-through that refuses once more than <c>maxBytes</c> have come out of it. This is what
    /// makes the bound hold for a chunked response and for one whose Content-Length understates the body: the
    /// count is of bytes actually delivered, never of what the server claimed.
    /// </summary>
    private sealed class BoundedStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _maxBytes;
        private long _read;

        internal BoundedStream(Stream inner, long maxBytes)
        {
            _inner = inner;
            _maxBytes = maxBytes;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            return Count(read);
        }

        public override int Read(byte[] buffer, int offset, int count) => Count(_inner.Read(buffer, offset, count));

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Flush() => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }

        private int Count(int read)
        {
            _read += read;
            return _read > _maxBytes
                ? throw new ProviderResponseTooLargeException(_maxBytes)
                : read;
        }
    }
}
