using System.Globalization;
using System.Text.Json;

namespace Sarif.Cli;

/// <summary>
/// Parses CLI property options into SARIF <c>properties</c> bag entries
/// (<see cref="Dictionary{TKey,TValue}"/> of <see cref="string"/> →
/// <see cref="JsonElement"/>).
///
/// Supported input forms (per <c>--property</c> occurrence):
///   <list type="bullet">
///     <item><c>key=value</c> — value is auto-typed as bool / int / double / string.</item>
///     <item><c>key:json=&lt;raw json&gt;</c> — value is parsed as JSON verbatim
///       (use this for arrays, objects, or to force a string that looks numeric).</item>
///     <item><c>key=</c> — empty string value.</item>
///   </list>
/// </summary>
public static class PropertyParser
{
    /// <summary>
    /// Builds a properties bag from the supplied CLI inputs.
    /// </summary>
    /// <param name="properties"><c>--property</c> occurrences in <c>key=value</c> or <c>key:json=value</c> form.</param>
    /// <param name="tags"><c>--tag</c> occurrences. Combined into a JSON string array under the <c>tags</c> key.</param>
    /// <param name="securitySeverity">If non-null, written as a string under <c>security-severity</c> (GitHub code-scanning convention).</param>
    /// <param name="cvss">If non-null, written as a string under <c>cvssV3_1</c>.</param>
    /// <param name="error">Human-readable error message if parsing fails; otherwise null.</param>
    /// <returns>The bag, or null if nothing was supplied or parsing failed.</returns>
    public static Dictionary<string, JsonElement>? Build(
        IReadOnlyList<string>? properties,
        IReadOnlyList<string>? tags,
        string? securitySeverity,
        string? cvss,
        out string? error)
    {
        error = null;
        var bag = new Dictionary<string, JsonElement>(StringComparer.Ordinal);

        if (properties is not null)
        {
            foreach (var p in properties)
            {
                if (!TryParseEntry(p, out var key, out var value, out var entryError))
                {
                    error = entryError;
                    return null;
                }
                bag[key!] = value;
            }
        }

        if (tags is not null && tags.Count > 0)
        {
            bag["tags"] = WriteValue(w =>
            {
                w.WriteStartArray();
                foreach (var t in tags) w.WriteStringValue(t);
                w.WriteEndArray();
            });
        }

        if (!string.IsNullOrEmpty(securitySeverity))
        {
            bag["security-severity"] = WriteValue(w => w.WriteStringValue(securitySeverity));
        }

        if (!string.IsNullOrEmpty(cvss))
        {
            bag["cvssV3_1"] = WriteValue(w => w.WriteStringValue(cvss));
        }

        return bag.Count == 0 ? null : bag;
    }

    /// <summary>
    /// Parses one <c>key=value</c> or <c>key:json=value</c> entry.
    /// </summary>
    public static bool TryParseEntry(string input, out string? key, out JsonElement value, out string? error)
    {
        key = null;
        value = default;
        error = null;

        if (string.IsNullOrEmpty(input))
        {
            error = "Empty --property entry.";
            return false;
        }

        int eq = input.IndexOf('=');
        if (eq <= 0)
        {
            error = $"--property '{input}' must be of the form key=value (or key:json=<raw json>).";
            return false;
        }

        var rawKey = input[..eq];
        var rawValue = input[(eq + 1)..];

        bool jsonMode = false;
        if (rawKey.EndsWith(":json", StringComparison.Ordinal))
        {
            jsonMode = true;
            rawKey = rawKey[..^":json".Length];
        }

        if (string.IsNullOrEmpty(rawKey))
        {
            error = $"--property '{input}' has an empty key.";
            return false;
        }

        if (jsonMode)
        {
            try
            {
                using var doc = JsonDocument.Parse(rawValue);
                value = doc.RootElement.Clone();
            }
            catch (JsonException ex)
            {
                error = $"--property '{rawKey}:json=...': {ex.Message}";
                return false;
            }
        }
        else
        {
            value = AutoType(rawValue);
        }

        key = rawKey;
        return true;
    }

    static JsonElement AutoType(string raw)
    {
        // Empty string stays a string.
        if (raw.Length == 0)
            return WriteValue(w => w.WriteStringValue(""));

        // Booleans (lowercase only — JSON convention).
        if (raw == "true") return WriteValue(w => w.WriteBooleanValue(true));
        if (raw == "false") return WriteValue(w => w.WriteBooleanValue(false));

        // Integers (long range) take precedence over doubles.
        if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i))
            return WriteValue(w => w.WriteNumberValue(i));

        // Doubles (invariant culture so '.' is the decimal separator).
        if (double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d)
            && !double.IsNaN(d) && !double.IsInfinity(d))
            return WriteValue(w => w.WriteNumberValue(d));

        return WriteValue(w => w.WriteStringValue(raw));
    }

    /// <summary>
    /// Builds a <see cref="JsonElement"/> by writing JSON via <see cref="Utf8JsonWriter"/>
    /// (AOT-safe — no reflection-based serialization).
    /// </summary>
    static JsonElement WriteValue(Action<Utf8JsonWriter> writeBody)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            writeBody(w);
        }
        using var doc = JsonDocument.Parse(ms.ToArray());
        return doc.RootElement.Clone();
    }
}
