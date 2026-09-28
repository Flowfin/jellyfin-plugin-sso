// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>Makes a string property write-only across the JSON boundary: read from a save, serialized back as null (#189).</summary>
/// <remarks>Not <c>[JsonIgnore]</c>, which is bidirectional and would drop the value on the incoming save too.</remarks>
internal sealed class WriteOnlySecretConverter : JsonConverter<string?>
{
    /// <inheritdoc />
    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.GetString();

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, string? value, JsonSerializerOptions options)
        => writer.WriteNullValue();
}
