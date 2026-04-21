using System.Text.Json;
using Sarif.Cli;
using Xunit;

namespace Sarif.Tests;

public class PropertyParserTests
{
    [Fact]
    public void Empty_inputs_return_null()
    {
        var bag = PropertyParser.Build(null, null, null, null, out var error);
        Assert.Null(error);
        Assert.Null(bag);
    }

    [Fact]
    public void Tags_become_a_string_array()
    {
        var bag = PropertyParser.Build(null, new[] { "security", "owasp" }, null, null, out var error);
        Assert.Null(error);
        Assert.NotNull(bag);
        var tags = bag!["tags"];
        Assert.Equal(JsonValueKind.Array, tags.ValueKind);
        Assert.Equal(new[] { "security", "owasp" }, tags.EnumerateArray().Select(e => e.GetString()).ToArray());
    }

    [Fact]
    public void Security_severity_and_cvss_are_emitted_as_strings()
    {
        // GitHub code-scanning convention: security-severity is a STRING containing a number.
        var bag = PropertyParser.Build(null, null, "9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", out _);
        Assert.NotNull(bag);
        Assert.Equal(JsonValueKind.String, bag!["security-severity"].ValueKind);
        Assert.Equal("9.8", bag["security-severity"].GetString());
        Assert.Equal(JsonValueKind.String, bag["cvssV3_1"].ValueKind);
    }

    [Theory]
    [InlineData("foo=bar", "foo", JsonValueKind.String, "bar")]
    [InlineData("foo=", "foo", JsonValueKind.String, "")]
    [InlineData("foo=true", "foo", JsonValueKind.True, null)]
    [InlineData("foo=false", "foo", JsonValueKind.False, null)]
    [InlineData("foo=42", "foo", JsonValueKind.Number, "42")]
    [InlineData("foo=-7", "foo", JsonValueKind.Number, "-7")]
    [InlineData("foo=3.14", "foo", JsonValueKind.Number, "3.14")]
    [InlineData("confidence=high", "confidence", JsonValueKind.String, "high")]
    public void Auto_typing_detects_primitives(string entry, string expectedKey, JsonValueKind expectedKind, string? expectedRaw)
    {
        var ok = PropertyParser.TryParseEntry(entry, out var key, out var value, out var error);
        Assert.True(ok, error);
        Assert.Equal(expectedKey, key);
        Assert.Equal(expectedKind, value.ValueKind);
        if (expectedRaw is not null)
        {
            if (expectedKind == JsonValueKind.String)
                Assert.Equal(expectedRaw, value.GetString());
            else
                Assert.Equal(expectedRaw, value.GetRawText());
        }
    }

    [Fact]
    public void Json_mode_parses_arbitrary_structures()
    {
        var ok = PropertyParser.TryParseEntry("evidence:json={\"score\":0.92,\"signals\":[\"a\",\"b\"]}",
            out var key, out var value, out var error);
        Assert.True(ok, error);
        Assert.Equal("evidence", key);
        Assert.Equal(JsonValueKind.Object, value.ValueKind);
        Assert.Equal(0.92, value.GetProperty("score").GetDouble());
        Assert.Equal(2, value.GetProperty("signals").GetArrayLength());
    }

    [Fact]
    public void Json_mode_with_invalid_json_reports_error()
    {
        var ok = PropertyParser.TryParseEntry("foo:json={not valid", out _, out _, out var error);
        Assert.False(ok);
        Assert.Contains("foo:json", error);
    }

    [Theory]
    [InlineData("=value")]
    [InlineData("nokeysep")]
    [InlineData(":json=v")]
    public void Malformed_entries_report_errors(string bad)
    {
        var ok = PropertyParser.TryParseEntry(bad, out _, out _, out var error);
        Assert.False(ok);
        Assert.NotNull(error);
    }

    [Fact]
    public void Property_with_equals_in_value_keeps_value_intact()
    {
        // Only the FIRST '=' is the separator.
        var ok = PropertyParser.TryParseEntry("query=name=foo", out var key, out var value, out _);
        Assert.True(ok);
        Assert.Equal("query", key);
        Assert.Equal("name=foo", value.GetString());
    }
}
