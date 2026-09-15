// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Xml;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The minted-password record has to survive a restart (#1733), and that is not a formality: Jellyfin
/// persists a plugin configuration as XML through <c>XmlSerializer</c>, and this is the first map in this
/// configuration keyed on something other than a string.
/// </summary>
/// <remarks>
/// WHY THIS IS ITS OWN SUITE. A record that does not round-trip reverts the whole rule silently on the next
/// restart: every account sealed before the restart reads as holding a password of its own again, the guard
/// stops firing for exactly the population it was written for, and nothing anywhere goes red. No unit test
/// of the write path or the read path can see that, because both sides hold the same live object.
/// </remarks>
public class ProvisionedPasswordPersistenceTests
{
    private static readonly Guid Account = Guid.Parse("88888888-8888-8888-8888-888888888888");

    [Fact]
    public void TheMintedPasswordRecord_SurvivesTheXmlRoundTripJellyfinPersistsThrough()
    {
        var written = new PluginConfiguration();
        written.ProvisionedPasswords[Account] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        var read = RoundTrip(written);

        Assert.True(read.ProvisionedPasswords.ContainsKey(Account));
        Assert.Equal(written.ProvisionedPasswords[Account], read.ProvisionedPasswords[Account]);
    }

    [Fact]
    public void AConfigurationWrittenBeforeTheRecordExisted_ReadsAsAnEmptyMapRatherThanFailing()
    {
        // The upgrade path, and the direction that matters: every server upgrading into this build has a
        // config.xml with no ProvisionedPasswords element at all. That must read as "nothing recorded",
        // which is the answer that leaves those accounts exactly as they were, rather than throwing on the
        // way in and taking the whole configuration with it.
        var legacy = "<?xml version=\"1.0\" encoding=\"utf-16\"?>"
            + "<PluginConfiguration xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" />";

        var read = Deserialize(legacy);

        Assert.NotNull(read.ProvisionedPasswords);
        Assert.Empty(read.ProvisionedPasswords);
    }

    [Fact]
    public void AnEmptyRecord_RoundTripsAsAnEmptyRecord()
    {
        // The everyday case - no account sealed yet - through the same serializer, because an empty
        // IXmlSerializable map is the shape that reads back as null or throws when ReadXml mishandles the
        // empty element.
        var read = RoundTrip(new PluginConfiguration());

        Assert.NotNull(read.ProvisionedPasswords);
        Assert.Empty(read.ProvisionedPasswords);
    }

    private static PluginConfiguration RoundTrip(PluginConfiguration configuration)
    {
        var serializer = new XmlSerializer(typeof(PluginConfiguration));
        using var buffer = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
        serializer.Serialize(buffer, configuration);

        return Deserialize(buffer.ToString());
    }

    // DTD processing off and no resolver, which is what CA5369 asks for and what the host's own reader
    // does: this suite is about a map surviving a round trip, not about admitting an external document.
    private static PluginConfiguration Deserialize(string document)
    {
        using var text = new StringReader(document);
        using var reader = XmlReader.Create(text, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        return (PluginConfiguration)new XmlSerializer(typeof(PluginConfiguration)).Deserialize(reader)!;
    }
}
