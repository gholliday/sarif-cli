using System.CommandLine;
using System.Text.Json;
using Sarif.Cli.Model;
using Spectre.Console;

namespace Sarif.Cli.Commands;

/// <summary>
/// Bulk-import rules and results from a JSON Lines (JSONL) file.
///
/// Each non-blank, non-comment line is a JSON object with a <c>"kind"</c> field of
/// <c>"rule"</c> or <c>"result"</c>. Comment lines start with <c>//</c> and are ignored.
///
/// Rule schema (all fields optional except <c>id</c>):
/// <code>
/// {"kind":"rule","id":"R1","name":"X","shortDescription":"…","fullDescription":"…",
///  "helpUri":"https://…","helpText":"…","defaultLevel":"error|warning|note|none",
///  "tags":["t1","t2"],"securitySeverity":"7.5","cvss":"…","properties":{"k":"v"}}
/// </code>
///
/// Result schema (one of <c>ruleId</c>/<c>ruleIndex</c> required, plus <c>message</c>):
/// <code>
/// {"kind":"result","ruleId":"R1","ruleIndex":0,"message":"…",
///  "level":"error|warning|note|none","file":"src/x.cs","uriBaseId":"SRCROOT",
///  "startLine":42,"startColumn":9,"endLine":44,"endColumn":10,"snippet":"…",
///  "tags":[…],"securitySeverity":"…","cvss":"…","properties":{…}}
/// </code>
/// </summary>
internal static class BulkCommand
{
    internal static Command Create()
    {
        var jsonlArg = new Argument<FileInfo>("jsonl") { Description = "Path to a .jsonl file containing rule/result entries." };
        var fileArg = new Argument<FileInfo>("file") { Description = "Path to the .sarif file to add to." };
        var runOpt = new Option<int>("--run") { Description = "Run index (default 0).", DefaultValueFactory = _ => 0 };
        var continueOpt = new Option<bool>("--continue-on-error") { Description = "Skip malformed lines and continue. By default, the first error aborts the import." };

        var cmd = new Command("bulk", "Bulk-import rules and results from a JSONL file.")
        {
            jsonlArg, fileArg, runOpt, continueOpt
        };

        cmd.SetAction(parseResult =>
        {
            var jsonl = parseResult.GetValue(jsonlArg)!;
            var file = parseResult.GetValue(fileArg)!;
            var runIdx = parseResult.GetValue(runOpt);
            var continueOnError = parseResult.GetValue(continueOpt);

            if (!jsonl.Exists)
            {
                AnsiConsole.MarkupLine($"[red]JSONL file not found:[/] {Markup.Escape(jsonl.FullName)}");
                return 1;
            }

            var log = SarifFile.Load(file.FullName);
            if (runIdx < 0 || runIdx >= log.Runs.Count)
            {
                AnsiConsole.MarkupLine("[red]Invalid run index.[/]");
                return 1;
            }

            var run = log.Runs[runIdx];
            var driver = run.Tool.Driver;
            driver.Rules ??= new List<ReportingDescriptor>();
            run.Results ??= new List<Result>();

            int rulesAdded = 0, resultsAdded = 0, errors = 0;
            int lineNumber = 0;

            foreach (var rawLine in File.ReadLines(jsonl.FullName))
            {
                lineNumber++;
                var line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal))
                    continue;

                JsonDocument doc;
                try
                {
                    doc = JsonDocument.Parse(line);
                }
                catch (JsonException ex)
                {
                    if (!Report(continueOnError, lineNumber, $"Invalid JSON: {ex.Message}", ref errors)) return 1;
                    continue;
                }

                using (doc)
                {
                    var root = doc.RootElement;
                    if (root.ValueKind != JsonValueKind.Object)
                    {
                        if (!Report(continueOnError, lineNumber, "Top-level JSON value must be an object.", ref errors)) return 1;
                        continue;
                    }

                    if (!root.TryGetProperty("kind", out var kindEl) || kindEl.ValueKind != JsonValueKind.String)
                    {
                        if (!Report(continueOnError, lineNumber, "Missing string field 'kind' (expected \"rule\" or \"result\").", ref errors)) return 1;
                        continue;
                    }

                    var kind = kindEl.GetString();
                    switch (kind)
                    {
                        case "rule":
                            if (BuildRule(root, driver.Rules, out var ruleErr) && ruleErr is null)
                                rulesAdded++;
                            else
                            {
                                if (!Report(continueOnError, lineNumber, ruleErr ?? "Unknown rule error.", ref errors)) return 1;
                            }
                            break;

                        case "result":
                            if (BuildResult(root, driver.Rules, run.Results, run.OriginalUriBaseIds, out var resultErr) && resultErr is null)
                                resultsAdded++;
                            else
                            {
                                if (!Report(continueOnError, lineNumber, resultErr ?? "Unknown result error.", ref errors)) return 1;
                            }
                            break;

                        default:
                            if (!Report(continueOnError, lineNumber, $"Unknown 'kind' value '{kind}' (expected \"rule\" or \"result\").", ref errors)) return 1;
                            break;
                    }
                }
            }

            SarifFile.Save(log, file.FullName);

            var summary = $"[green]Bulk import:[/] +{rulesAdded} rule(s), +{resultsAdded} result(s)";
            if (errors > 0) summary += $" [yellow]({errors} error(s) skipped)[/]";
            summary += $" -> {Markup.Escape(file.FullName)}";
            AnsiConsole.MarkupLine(summary);
            return errors > 0 && !continueOnError ? 1 : 0;
        });
        return cmd;
    }

    static bool Report(bool continueOnError, int lineNumber, string message, ref int errors)
    {
        errors++;
        AnsiConsole.MarkupLine($"[red]Line {lineNumber}:[/] {Markup.Escape(message)}");
        return continueOnError;
    }

    /// <summary>Builds a rule entry from a JSONL object and appends it to <paramref name="rules"/>.</summary>
    internal static bool BuildRule(JsonElement root, List<ReportingDescriptor> rules, out string? error)
    {
        error = null;

        if (!TryGetString(root, "id", out var id) || string.IsNullOrEmpty(id))
        {
            error = "Rule entry requires a non-empty string 'id'.";
            return false;
        }

        if (rules.Any(r => r.Id == id))
        {
            error = $"Rule '{id}' already exists.";
            return false;
        }

        TryGetString(root, "name", out var name);
        TryGetString(root, "shortDescription", out var shortDesc);
        TryGetString(root, "fullDescription", out var fullDesc);
        TryGetString(root, "helpText", out var helpText);

        Uri? helpUri = null;
        if (TryGetString(root, "helpUri", out var helpUriStr) && !string.IsNullOrEmpty(helpUriStr))
        {
            if (!Uri.TryCreate(helpUriStr, UriKind.Absolute, out helpUri))
            {
                error = $"Invalid 'helpUri' '{helpUriStr}'.";
                return false;
            }
        }

        var defaultLevel = FailureLevel.Warning;
        if (TryGetString(root, "defaultLevel", out var levelStr) && !string.IsNullOrEmpty(levelStr))
        {
            if (!TryParseLevel(levelStr!, out defaultLevel))
            {
                error = $"Invalid 'defaultLevel' '{levelStr}'.";
                return false;
            }
        }

        if (!TryBuildProperties(root, out var bag, out var propError))
        {
            error = propError;
            return false;
        }

        rules.Add(new ReportingDescriptor
        {
            Id = id,
            Name = string.IsNullOrEmpty(name) ? null : name,
            ShortDescription = string.IsNullOrEmpty(shortDesc) ? null : new MultiformatMessageString { Text = shortDesc },
            FullDescription = string.IsNullOrEmpty(fullDesc) ? null : new MultiformatMessageString { Text = fullDesc },
            HelpUri = helpUri,
            Help = string.IsNullOrEmpty(helpText) ? null : new MultiformatMessageString { Text = helpText },
            DefaultConfiguration = new ReportingConfiguration { Level = defaultLevel },
            Properties = bag
        });
        return true;
    }

    /// <summary>Builds a result entry from a JSONL object and appends it to <paramref name="results"/>.</summary>
    internal static bool BuildResult(
        JsonElement root,
        List<ReportingDescriptor> rules,
        List<Result> results,
        Dictionary<string, ArtifactLocation>? originalUriBaseIds,
        out string? error)
    {
        error = null;

        TryGetString(root, "ruleId", out var ruleId);
        int? ruleIndex = TryGetInt(root, "ruleIndex");

        if (string.IsNullOrEmpty(ruleId) && ruleIndex is null)
        {
            error = "Result entry requires 'ruleId' or 'ruleIndex'.";
            return false;
        }

        if (ruleIndex is int idx)
        {
            if (idx < 0 || idx >= rules.Count)
            {
                error = $"'ruleIndex' {idx} is out of range (driver has {rules.Count} rule(s)).";
                return false;
            }
            var ruleAtIndex = rules[idx];
            if (string.IsNullOrEmpty(ruleId))
                ruleId = ruleAtIndex.Id;
            else if (!string.Equals(ruleId, ruleAtIndex.Id, StringComparison.Ordinal))
            {
                error = $"'ruleId' '{ruleId}' does not match the rule at index {idx} ('{ruleAtIndex.Id}').";
                return false;
            }
        }
        else
        {
            for (int i = 0; i < rules.Count; i++)
            {
                if (rules[i].Id == ruleId) { ruleIndex = i; break; }
            }
        }

        if (!TryGetString(root, "message", out var message) || string.IsNullOrEmpty(message))
        {
            error = "Result entry requires a non-empty string 'message'.";
            return false;
        }

        FailureLevel? level = null;
        if (TryGetString(root, "level", out var levelStr) && !string.IsNullOrEmpty(levelStr))
        {
            if (!TryParseLevel(levelStr!, out var parsed))
            {
                error = $"Invalid 'level' '{levelStr}'.";
                return false;
            }
            level = parsed;
        }

        if (!TryBuildProperties(root, out var bag, out var propError))
        {
            error = propError;
            return false;
        }

        var result = new Result
        {
            RuleId = ruleId,
            RuleIndex = ruleIndex,
            Level = level,
            Message = new Message { Text = message },
            Properties = bag
        };

        TryGetString(root, "file", out var fileUri);
        TryGetString(root, "uriBaseId", out var uriBaseId);
        if (!string.IsNullOrEmpty(fileUri))
        {
            if (!Uri.TryCreate(fileUri, UriKind.RelativeOrAbsolute, out var fileUriValue))
            {
                error = $"Invalid 'file' URI '{fileUri}'.";
                return false;
            }

            if (!string.IsNullOrEmpty(uriBaseId)
                && (originalUriBaseIds is null || !originalUriBaseIds.ContainsKey(uriBaseId)))
            {
                // Warn but don't fail — same behavior as `add result`.
                AnsiConsole.MarkupLine($"[yellow]Warning:[/] uriBaseId '{Markup.Escape(uriBaseId)}' is not declared in run.originalUriBaseIds.");
            }

            int? startLine = TryGetInt(root, "startLine");
            int? startColumn = TryGetInt(root, "startColumn");
            int? endLine = TryGetInt(root, "endLine");
            int? endColumn = TryGetInt(root, "endColumn");
            TryGetString(root, "snippet", out var snippet);

            Model.Region? region = null;
            if (startLine.HasValue || endLine.HasValue || !string.IsNullOrEmpty(snippet))
            {
                region = new Model.Region
                {
                    StartLine = startLine,
                    StartColumn = startColumn,
                    EndLine = endLine,
                    EndColumn = endColumn,
                    Snippet = string.IsNullOrEmpty(snippet) ? null : new ArtifactContent { Text = snippet }
                };
            }

            result.Locations = new List<Location>
            {
                new Location
                {
                    PhysicalLocation = new PhysicalLocation
                    {
                        ArtifactLocation = new ArtifactLocation
                        {
                            Uri = fileUriValue,
                            UriBaseId = string.IsNullOrEmpty(uriBaseId) ? null : uriBaseId
                        },
                        Region = region
                    }
                }
            };
        }

        results.Add(result);
        return true;
    }

    /// <summary>
    /// Combines top-level <c>tags</c>/<c>securitySeverity</c>/<c>cvss</c>/<c>properties</c>
    /// fields into a single SARIF properties bag.
    /// </summary>
    static bool TryBuildProperties(JsonElement root, out Dictionary<string, JsonElement>? bag, out string? error)
    {
        error = null;
        var b = new Dictionary<string, JsonElement>(StringComparer.Ordinal);

        if (root.TryGetProperty("properties", out var propsEl))
        {
            if (propsEl.ValueKind != JsonValueKind.Object)
            {
                bag = null;
                error = "'properties' must be a JSON object.";
                return false;
            }
            foreach (var p in propsEl.EnumerateObject())
                b[p.Name] = p.Value.Clone();
        }

        if (root.TryGetProperty("tags", out var tagsEl) && tagsEl.ValueKind == JsonValueKind.Array)
        {
            // Clone the array verbatim — assumes string elements.
            b["tags"] = tagsEl.Clone();
        }

        if (TryGetString(root, "securitySeverity", out var sev) && !string.IsNullOrEmpty(sev))
            b["security-severity"] = WriteString(sev);

        if (TryGetString(root, "cvss", out var cvss) && !string.IsNullOrEmpty(cvss))
            b["cvssV3_1"] = WriteString(cvss);

        bag = b.Count == 0 ? null : b;
        return true;
    }

    static bool TryGetString(JsonElement root, string name, out string? value)
    {
        if (root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String)
        {
            value = el.GetString();
            return true;
        }
        value = null;
        return false;
    }

    static int? TryGetInt(JsonElement root, string name)
    {
        if (root.TryGetProperty(name, out var el)
            && el.ValueKind == JsonValueKind.Number
            && el.TryGetInt32(out var i))
            return i;
        return null;
    }

    static bool TryParseLevel(string s, out FailureLevel level)
    {
        switch (s.Trim().ToLowerInvariant())
        {
            case "none": level = FailureLevel.None; return true;
            case "note": level = FailureLevel.Note; return true;
            case "warning": level = FailureLevel.Warning; return true;
            case "error": level = FailureLevel.Error; return true;
            default: level = default; return false;
        }
    }

    static JsonElement WriteString(string s)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStringValue(s);
        }
        using var doc = JsonDocument.Parse(ms.ToArray());
        return doc.RootElement.Clone();
    }
}
