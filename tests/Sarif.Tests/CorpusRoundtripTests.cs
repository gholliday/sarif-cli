using System.Text.Json;
using Sarif.Cli;
using Sarif.Cli.Model;
using Xunit;

namespace Sarif.Tests;

/// <summary>
/// The "no-data-loss" guarantee: every SARIF file in the corpus we care about
/// must round-trip through <see cref="SarifFile.Load"/> + <see cref="SarifFile.Save"/>
/// with no JSON value lost. Unknown sibling fields land in <c>AdditionalProperties</c>
/// (via <see cref="System.Text.Json.Serialization.JsonExtensionDataAttribute"/>) and
/// are re-emitted on save.
/// </summary>
public class CorpusRoundtripTests
{
    public static IEnumerable<TheoryDataRow<string>> CorpusFiles()
    {
        // Always-available bundled fixtures live next to the test assembly.
        var bundled = Path.Combine(AppContext.BaseDirectory, "fixtures");
        if (Directory.Exists(bundled))
        {
            foreach (var f in Directory.EnumerateFiles(bundled, "*.sarif", SearchOption.AllDirectories))
            {
                yield return new TheoryDataRow<string>(f) { TestDisplayName = Path.GetFileName(f) };
            }
        }

        // Opt-in extended corpus: point SARIF_CLI_CORPUS_DIRS at one or more
        // local directories (separated by Path.PathSeparator) of .sarif files
        // to extend coverage beyond the bundled fixtures.
        var extra = Environment.GetEnvironmentVariable("SARIF_CLI_CORPUS_DIRS");
        if (!string.IsNullOrEmpty(extra))
        {
            foreach (var root in extra.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                if (!Directory.Exists(root)) continue;
                foreach (var f in Directory.EnumerateFiles(root, "*.sarif", SearchOption.AllDirectories))
                {
                    yield return new TheoryDataRow<string>(f) { TestDisplayName = Path.GetFileName(f) };
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(CorpusFiles))]
    public void RoundTrip_LosesNothing(string path)
    {
        // Original JSON tree (parsed with stock STJ — independent of our model).
        using var originalDoc = JsonDocument.Parse(File.ReadAllBytes(path));

        // Round-trip through the model.
        var log = SarifFile.Load(path);
        var tmp = Path.Combine(Path.GetTempPath(), $"roundtrip-{Guid.NewGuid():N}.sarif");
        try
        {
            SarifFile.Save(log, tmp);
            using var roundTrippedDoc = JsonDocument.Parse(File.ReadAllBytes(tmp));

            // Walk both trees in lock-step and require structural equivalence.
            var diffs = new List<string>();
            CompareJson(originalDoc.RootElement, roundTrippedDoc.RootElement, "$", diffs);
            Assert.True(diffs.Count == 0,
                $"Round-trip diffs for {Path.GetFileName(path)}:\n  " + string.Join("\n  ", diffs.Take(25)));
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    static void CompareJson(JsonElement a, JsonElement b, string path, List<string> diffs)
    {
        if (a.ValueKind != b.ValueKind)
        {
            // Tolerate "absent" vs "null" — STJ can drop nulls under WhenWritingNull.
            if (a.ValueKind == JsonValueKind.Null && b.ValueKind == JsonValueKind.Undefined) return;
            if (b.ValueKind == JsonValueKind.Null && a.ValueKind == JsonValueKind.Undefined) return;
            diffs.Add($"{path}: kind {a.ValueKind} != {b.ValueKind}");
            return;
        }

        switch (a.ValueKind)
        {
            case JsonValueKind.Object:
                var aProps = a.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
                var bProps = b.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
                foreach (var (k, av) in aProps)
                {
                    if (!bProps.TryGetValue(k, out var bv))
                    {
                        // STJ drops nulls; that is acceptable.
                        if (av.ValueKind == JsonValueKind.Null) continue;
                        diffs.Add($"{path}.{k}: missing after round-trip ({av.ValueKind})");
                        continue;
                    }
                    CompareJson(av, bv, $"{path}.{k}", diffs);
                }
                foreach (var k in bProps.Keys)
                {
                    if (!aProps.ContainsKey(k))
                        diffs.Add($"{path}.{k}: appeared after round-trip");
                }
                break;

            case JsonValueKind.Array:
                int aLen = a.GetArrayLength();
                int bLen = b.GetArrayLength();
                if (aLen != bLen)
                {
                    diffs.Add($"{path}: array length {aLen} != {bLen}");
                    return;
                }
                for (int i = 0; i < aLen; i++)
                    CompareJson(a[i], b[i], $"{path}[{i}]", diffs);
                break;

            case JsonValueKind.String:
                var sa = a.GetString();
                var sb = b.GetString();
                if (sa != sb)
                {
                    // Tolerate URI normalisation: System.Uri may collapse trailing-slash
                    // and case on scheme/host. Fall back to Uri equality for those cases.
                    if (sa is not null && sb is not null &&
                        Uri.TryCreate(sa, UriKind.RelativeOrAbsolute, out var ua) &&
                        Uri.TryCreate(sb, UriKind.RelativeOrAbsolute, out var ub) &&
                        ua.Equals(ub))
                    {
                        return;
                    }
                    diffs.Add($"{path}: string \"{Trim(sa)}\" != \"{Trim(sb)}\"");
                }
                break;

            case JsonValueKind.Number:
                // Compare via raw text first (preserves int vs float distinction).
                var ra = a.GetRawText();
                var rb = b.GetRawText();
                if (ra != rb)
                {
                    if (a.TryGetDouble(out var da) && b.TryGetDouble(out var db) && da == db) return;
                    diffs.Add($"{path}: number {ra} != {rb}");
                }
                break;

            case JsonValueKind.True:
            case JsonValueKind.False:
            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
                break;
        }
    }

    static string Trim(string? s) =>
        s is null ? "<null>" : (s.Length <= 60 ? s : s[..60] + "…");
}
