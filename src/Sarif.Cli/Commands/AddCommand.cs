using System.CommandLine;
using System.Text.Json;
using Sarif.Cli.Model;
using Spectre.Console;

namespace Sarif.Cli.Commands;

internal static class AddCommand
{
    internal static Command Create()
    {
        var addCmd = new Command("add", "Add elements (rules, results) to a SARIF log.");
        addCmd.Add(CreateAddRuleCommand());
        addCmd.Add(CreateAddResultCommand());
        return addCmd;
    }

    static Command CreateAddRuleCommand()
    {
        var fileArg = new Argument<FileInfo>("file") { Description = "Path to a .sarif file." };
        var idOpt = new Option<string>("--id") { Description = "Rule id (e.g. 'CA1234').", Required = true };
        var nameOpt = new Option<string?>("--name") { Description = "Rule name (camel-cased, no spaces — e.g. 'AvoidNullReference')." };
        var shortDescOpt = new Option<string?>("--short-description") { Description = "Short description (one line)." };
        var fullDescOpt = new Option<string?>("--full-description") { Description = "Full description (multiple sentences)." };
        var helpUriOpt = new Option<string?>("--help-uri") { Description = "URL to rule documentation." };
        var helpTextOpt = new Option<string?>("--help-text") { Description = "Inline help text." };
        var levelOpt = new Option<string>("--default-level") { Description = "Default level: none|note|warning|error.", DefaultValueFactory = _ => "warning" };
        var tagOpt = new Option<string[]>("--tag") { Description = "Tag (repeatable). Adds to properties.tags[].", AllowMultipleArgumentsPerToken = false };
        var secSevOpt = new Option<string?>("--security-severity") { Description = "GitHub-style numeric severity (0.0-10.0); written to properties.security-severity." };
        var cvssOpt = new Option<string?>("--cvss") { Description = "CVSS v3.1 vector string; written to properties.cvssV3_1." };
        var propertyOpt = new Option<string[]>("--property") { Description = "Property entry (repeatable): key=value, or key:json=<raw json> for objects/arrays.", AllowMultipleArgumentsPerToken = false };
        var runOpt = new Option<int>("--run") { Description = "Run index (default 0).", DefaultValueFactory = _ => 0 };

        var cmd = new Command("rule", "Add a rule to the tool driver.")
        {
            fileArg, idOpt, nameOpt, shortDescOpt, fullDescOpt, helpUriOpt, helpTextOpt, levelOpt,
            tagOpt, secSevOpt, cvssOpt, propertyOpt, runOpt
        };

        cmd.SetAction(parseResult =>
        {
            var file = parseResult.GetValue(fileArg)!;
            var id = parseResult.GetValue(idOpt)!;
            var name = parseResult.GetValue(nameOpt);
            var shortDesc = parseResult.GetValue(shortDescOpt);
            var fullDesc = parseResult.GetValue(fullDescOpt);
            var helpUri = parseResult.GetValue(helpUriOpt);
            var helpText = parseResult.GetValue(helpTextOpt);
            var levelStr = parseResult.GetValue(levelOpt)!;
            var tags = parseResult.GetValue(tagOpt);
            var secSev = parseResult.GetValue(secSevOpt);
            var cvss = parseResult.GetValue(cvssOpt);
            var props = parseResult.GetValue(propertyOpt);
            var runIdx = parseResult.GetValue(runOpt);

            if (!TryParseLevel(levelStr, out var level))
            {
                AnsiConsole.MarkupLine($"[red]Invalid level '{Markup.Escape(levelStr)}'.[/] Use one of: none, note, warning, error.");
                return 1;
            }

            Uri? helpUriValue = null;
            if (!string.IsNullOrEmpty(helpUri))
            {
                if (!Uri.TryCreate(helpUri, UriKind.Absolute, out helpUriValue))
                {
                    AnsiConsole.MarkupLine($"[red]Invalid --help-uri '{Markup.Escape(helpUri)}'.[/] Must be an absolute URI.");
                    return 1;
                }
            }

            var bag = PropertyParser.Build(props, tags, secSev, cvss, out var propError);
            if (propError is not null)
            {
                AnsiConsole.MarkupLine($"[red]{Markup.Escape(propError)}[/]");
                return 1;
            }

            var log = SarifFile.Load(file.FullName);
            if (runIdx < 0 || runIdx >= log.Runs.Count)
            {
                AnsiConsole.MarkupLine("[red]Invalid run index.[/]");
                return 1;
            }

            var driver = log.Runs[runIdx].Tool.Driver;
            driver.Rules ??= new List<ReportingDescriptor>();

            if (driver.Rules.Any(r => r.Id == id))
            {
                AnsiConsole.MarkupLine($"[red]Rule '{Markup.Escape(id)}' already exists in run {runIdx}.[/]");
                return 1;
            }

            var rule = new ReportingDescriptor
            {
                Id = id,
                Name = name,
                ShortDescription = string.IsNullOrEmpty(shortDesc) ? null : new MultiformatMessageString { Text = shortDesc },
                FullDescription = string.IsNullOrEmpty(fullDesc) ? null : new MultiformatMessageString { Text = fullDesc },
                HelpUri = helpUriValue,
                Help = string.IsNullOrEmpty(helpText) ? null : new MultiformatMessageString { Text = helpText },
                DefaultConfiguration = new ReportingConfiguration { Level = level },
                Properties = bag
            };

            driver.Rules.Add(rule);
            SarifFile.Save(log, file.FullName);

            AnsiConsole.MarkupLine($"[green]Added rule[/] {Markup.Escape(id)} [dim](index {driver.Rules.Count - 1}, level {level})[/]");
            return 0;
        });
        return cmd;
    }

    static Command CreateAddResultCommand()
    {
        var fileArg = new Argument<FileInfo>("file") { Description = "Path to a .sarif file." };
        var ruleIdOpt = new Option<string?>("--rule-id") { Description = "Rule id this result is an instance of. One of --rule-id or --rule-index is required." };
        var ruleIndexOpt = new Option<int?>("--rule-index") { Description = "Rule index this result is an instance of. Useful when scripting from an iteration counter." };
        var messageOpt = new Option<string>("--message") { Description = "Result message text.", Required = true };
        var levelOpt = new Option<string?>("--level") { Description = "Override level: none|note|warning|error. Default uses the rule's defaultConfiguration." };
        var fileUriOpt = new Option<string?>("--file") { Description = "Source file URI (relative path or absolute URI)." };
        var uriBaseIdOpt = new Option<string?>("--uri-base-id") { Description = "uriBaseId for the artifact location (e.g. 'SRCROOT'). Should be a key in run.originalUriBaseIds." };
        var startLineOpt = new Option<int?>("--start-line") { Description = "1-based start line." };
        var startColOpt = new Option<int?>("--start-column") { Description = "1-based start column." };
        var endLineOpt = new Option<int?>("--end-line") { Description = "1-based end line." };
        var endColOpt = new Option<int?>("--end-column") { Description = "1-based end column." };
        var snippetOpt = new Option<string?>("--snippet") { Description = "Source snippet text for the region." };
        var tagOpt = new Option<string[]>("--tag") { Description = "Tag (repeatable). Adds to properties.tags[].", AllowMultipleArgumentsPerToken = false };
        var secSevOpt = new Option<string?>("--security-severity") { Description = "GitHub-style numeric severity (0.0-10.0); written to properties.security-severity." };
        var cvssOpt = new Option<string?>("--cvss") { Description = "CVSS v3.1 vector string; written to properties.cvssV3_1." };
        var propertyOpt = new Option<string[]>("--property") { Description = "Property entry (repeatable): key=value, or key:json=<raw json> for objects/arrays.", AllowMultipleArgumentsPerToken = false };
        var runOpt = new Option<int>("--run") { Description = "Run index (default 0).", DefaultValueFactory = _ => 0 };

        var cmd = new Command("result", "Add a result to a run.")
        {
            fileArg, ruleIdOpt, ruleIndexOpt, messageOpt, levelOpt,
            fileUriOpt, uriBaseIdOpt, startLineOpt, startColOpt, endLineOpt, endColOpt, snippetOpt,
            tagOpt, secSevOpt, cvssOpt, propertyOpt, runOpt
        };

        cmd.SetAction(parseResult =>
        {
            var file = parseResult.GetValue(fileArg)!;
            var ruleId = parseResult.GetValue(ruleIdOpt);
            var ruleIndexArg = parseResult.GetValue(ruleIndexOpt);
            var message = parseResult.GetValue(messageOpt)!;
            var levelStr = parseResult.GetValue(levelOpt);
            var fileUri = parseResult.GetValue(fileUriOpt);
            var uriBaseId = parseResult.GetValue(uriBaseIdOpt);
            var startLine = parseResult.GetValue(startLineOpt);
            var startCol = parseResult.GetValue(startColOpt);
            var endLine = parseResult.GetValue(endLineOpt);
            var endCol = parseResult.GetValue(endColOpt);
            var snippet = parseResult.GetValue(snippetOpt);
            var tags = parseResult.GetValue(tagOpt);
            var secSev = parseResult.GetValue(secSevOpt);
            var cvss = parseResult.GetValue(cvssOpt);
            var props = parseResult.GetValue(propertyOpt);
            var runIdx = parseResult.GetValue(runOpt);

            if (string.IsNullOrEmpty(ruleId) && ruleIndexArg is null)
            {
                AnsiConsole.MarkupLine("[red]One of --rule-id or --rule-index must be supplied.[/]");
                return 1;
            }

            FailureLevel? level = null;
            if (levelStr is not null)
            {
                if (!TryParseLevel(levelStr, out var parsed))
                {
                    AnsiConsole.MarkupLine($"[red]Invalid level '{Markup.Escape(levelStr)}'.[/]");
                    return 1;
                }
                level = parsed;
            }

            var bag = PropertyParser.Build(props, tags, secSev, cvss, out var propError);
            if (propError is not null)
            {
                AnsiConsole.MarkupLine($"[red]{Markup.Escape(propError)}[/]");
                return 1;
            }

            var log = SarifFile.Load(file.FullName);
            if (runIdx < 0 || runIdx >= log.Runs.Count)
            {
                AnsiConsole.MarkupLine("[red]Invalid run index.[/]");
                return 1;
            }

            var run = log.Runs[runIdx];
            run.Results ??= new List<Result>();

            // Resolve rule id ↔ rule index, preferring whichever the user supplied explicitly.
            var rules = run.Tool.Driver.Rules;
            int? ruleIndex = ruleIndexArg;
            string? resolvedRuleId = ruleId;

            if (ruleIndex is int idx)
            {
                if (rules is null || idx < 0 || idx >= rules.Count)
                {
                    AnsiConsole.MarkupLine($"[red]--rule-index {idx} is out of range[/] (driver has {rules?.Count ?? 0} rule(s)).");
                    return 1;
                }
                var ruleAtIndex = rules[idx];
                if (string.IsNullOrEmpty(resolvedRuleId))
                    resolvedRuleId = ruleAtIndex.Id;
                else if (!string.Equals(resolvedRuleId, ruleAtIndex.Id, StringComparison.Ordinal))
                {
                    AnsiConsole.MarkupLine($"[red]--rule-id '{Markup.Escape(resolvedRuleId)}' does not match the rule at index {idx} ('{Markup.Escape(ruleAtIndex.Id)}').[/]");
                    return 1;
                }
            }
            else if (rules is not null)
            {
                for (int i = 0; i < rules.Count; i++)
                {
                    if (rules[i].Id == resolvedRuleId) { ruleIndex = i; break; }
                }
            }

            if (ruleIndex is null)
            {
                AnsiConsole.MarkupLine($"[yellow]Warning:[/] no rule with id '{Markup.Escape(resolvedRuleId ?? "")}' is defined on the tool driver. Result will reference it by id only.");
            }

            var result = new Result
            {
                RuleId = resolvedRuleId,
                RuleIndex = ruleIndex,
                Level = level,
                Message = new Message { Text = message },
                Properties = bag
            };

            if (!string.IsNullOrEmpty(fileUri))
            {
                if (!Uri.TryCreate(fileUri, UriKind.RelativeOrAbsolute, out var fileUriValue))
                {
                    AnsiConsole.MarkupLine($"[red]Invalid --file URI '{Markup.Escape(fileUri)}'.[/]");
                    return 1;
                }

                if (!string.IsNullOrEmpty(uriBaseId)
                    && (run.OriginalUriBaseIds is null || !run.OriginalUriBaseIds.ContainsKey(uriBaseId)))
                {
                    AnsiConsole.MarkupLine($"[yellow]Warning:[/] --uri-base-id '{Markup.Escape(uriBaseId)}' is not declared in run.originalUriBaseIds. Use 'sarif-cli new ... --uri-base {Markup.Escape(uriBaseId)}=<path>'.");
                }

                Model.Region? region = null;
                if (startLine.HasValue || endLine.HasValue || !string.IsNullOrEmpty(snippet))
                {
                    region = new Model.Region
                    {
                        StartLine = startLine,
                        StartColumn = startCol,
                        EndLine = endLine,
                        EndColumn = endCol,
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

            run.Results.Add(result);
            SarifFile.Save(log, file.FullName);

            AnsiConsole.MarkupLine($"[green]Added result[/] [dim](rule {Markup.Escape(resolvedRuleId ?? "<none>")}, index {run.Results.Count - 1})[/]");
            return 0;
        });
        return cmd;
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
}
