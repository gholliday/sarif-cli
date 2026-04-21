using System.CommandLine;
using System.Text.Json;
using Sarif.Cli.Model;
using Spectre.Console;

namespace Sarif.Cli.Commands;

internal static class ListCommand
{
    internal static Command Create()
    {
        var listCmd = new Command("list", "List elements within a SARIF log.");
        listCmd.Add(CreateListRulesCommand());
        listCmd.Add(CreateListResultsCommand());
        return listCmd;
    }

    static Command CreateListRulesCommand()
    {
        var fileArg = new Argument<FileInfo>("file") { Description = "Path to a .sarif file." };
        var runOpt = new Option<int>("--run") { Description = "Run index (default 0).", DefaultValueFactory = _ => 0 };
        var noWrapOpt = new Option<bool>("--no-wrap") { Description = "Don't wrap long descriptions to terminal width." };
        var formatOpt = new Option<string>("--format") { Description = "Output format: text|json|tsv.", DefaultValueFactory = _ => "text" };
        var cmd = new Command("rules", "List the rules defined by the tool driver.") { fileArg, runOpt, noWrapOpt, formatOpt };

        cmd.SetAction(parseResult =>
        {
            var file = parseResult.GetValue(fileArg)!;
            var runIdx = parseResult.GetValue(runOpt);
            var noWrap = parseResult.GetValue(noWrapOpt);
            var format = parseResult.GetValue(formatOpt)!.ToLowerInvariant();
            var log = SarifFile.Load(file.FullName);

            if (runIdx < 0 || runIdx >= log.Runs.Count)
            {
                AnsiConsole.MarkupLine("[red]Invalid run index.[/]");
                return 1;
            }

            var rules = log.Runs[runIdx].Tool.Driver.Rules;
            if (rules is null || rules.Count == 0)
            {
                if (format == "text") AnsiConsole.MarkupLine("[dim](no rules defined)[/]");
                return 0;
            }

            switch (format)
            {
                case "json":
                    using (var stdout = Console.OpenStandardOutput())
                    using (var jw = new Utf8JsonWriter(stdout, new JsonWriterOptions { Indented = true }))
                    {
                        jw.WriteStartArray();
                        for (int i = 0; i < rules.Count; i++)
                        {
                            var r = rules[i];
                            jw.WriteStartObject();
                            jw.WriteNumber("index", i);
                            jw.WriteString("id", r.Id);
                            if (r.Name is not null) jw.WriteString("name", r.Name);
                            jw.WriteString("defaultLevel", (r.DefaultConfiguration?.Level ?? FailureLevel.Warning).ToString().ToLowerInvariant());
                            if (r.ShortDescription?.Text is { } sd) jw.WriteString("shortDescription", sd);
                            if (r.HelpUri is not null) jw.WriteString("helpUri", r.HelpUri.ToString());
                            jw.WriteEndObject();
                        }
                        jw.WriteEndArray();
                    }
                    Console.WriteLine();
                    return 0;

                case "tsv":
                    Console.WriteLine("index\tid\tname\tdefaultLevel\tshortDescription");
                    for (int i = 0; i < rules.Count; i++)
                    {
                        var r = rules[i];
                        Console.WriteLine($"{i}\t{r.Id}\t{r.Name}\t{(r.DefaultConfiguration?.Level ?? FailureLevel.Warning).ToString().ToLowerInvariant()}\t{TsvEscape(r.ShortDescription?.Text)}");
                    }
                    return 0;

                case "text":
                    var table = new Table()
                        .AddColumn("Index")
                        .AddColumn("Id")
                        .AddColumn("Name")
                        .AddColumn("Default level")
                        .AddColumn(new TableColumn("Short description") { NoWrap = noWrap });

                    for (int i = 0; i < rules.Count; i++)
                    {
                        var r = rules[i];
                        table.AddRow(
                            i.ToString(),
                            Markup.Escape(r.Id),
                            Markup.Escape(r.Name ?? ""),
                            Markup.Escape((r.DefaultConfiguration?.Level ?? FailureLevel.Warning).ToString()),
                            Markup.Escape(r.ShortDescription?.Text ?? ""));
                    }

                    AnsiConsole.Write(table);
                    return 0;

                default:
                    AnsiConsole.MarkupLine($"[red]Unknown --format '{Markup.Escape(format)}'.[/] Use one of: text, json, tsv.");
                    return 1;
            }
        });
        return cmd;
    }

    static Command CreateListResultsCommand()
    {
        var fileArg = new Argument<FileInfo>("file") { Description = "Path to a .sarif file." };
        var runOpt = new Option<int>("--run") { Description = "Run index (default 0).", DefaultValueFactory = _ => 0 };
        var ruleIdOpt = new Option<string?>("--rule-id") { Description = "Filter to results matching this rule id." };
        var formatOpt = new Option<string>("--format") { Description = "Output format: text|json|tsv.", DefaultValueFactory = _ => "text" };
        var cmd = new Command("results", "List the results in a run.") { fileArg, runOpt, ruleIdOpt, formatOpt };

        cmd.SetAction(parseResult =>
        {
            var file = parseResult.GetValue(fileArg)!;
            var runIdx = parseResult.GetValue(runOpt);
            var filter = parseResult.GetValue(ruleIdOpt);
            var format = parseResult.GetValue(formatOpt)!.ToLowerInvariant();
            var log = SarifFile.Load(file.FullName);

            if (runIdx < 0 || runIdx >= log.Runs.Count)
            {
                AnsiConsole.MarkupLine("[red]Invalid run index.[/]");
                return 1;
            }

            var run = log.Runs[runIdx];
            var allResults = run.Results ?? new List<Result>();
            var results = string.IsNullOrEmpty(filter)
                ? allResults
                : allResults.Where(r => string.Equals(r.RuleId ?? r.Rule?.Id, filter, StringComparison.Ordinal)).ToList();

            if (results.Count == 0)
            {
                if (format == "text") AnsiConsole.MarkupLine("[dim](no results)[/]");
                return 0;
            }

            switch (format)
            {
                case "json":
                    using (var stdout = Console.OpenStandardOutput())
                    using (var jw = new Utf8JsonWriter(stdout, new JsonWriterOptions { Indented = true }))
                    {
                        jw.WriteStartArray();
                        for (int i = 0; i < results.Count; i++)
                        {
                            var r = results[i];
                            jw.WriteStartObject();
                            jw.WriteNumber("index", i);
                            var rid = r.RuleId ?? r.Rule?.Id;
                            if (rid is not null) jw.WriteString("ruleId", rid);
                            jw.WriteString("level", (r.Level ?? FailureLevel.Warning).ToString().ToLowerInvariant());
                            jw.WriteString("location", FormatLocation(r));
                            if (r.Message.Text is { } mt) jw.WriteString("message", mt);
                            jw.WriteEndObject();
                        }
                        jw.WriteEndArray();
                    }
                    Console.WriteLine();
                    return 0;

                case "tsv":
                    Console.WriteLine("index\truleId\tlevel\tlocation\tmessage");
                    for (int i = 0; i < results.Count; i++)
                    {
                        var r = results[i];
                        Console.WriteLine($"{i}\t{r.RuleId ?? r.Rule?.Id ?? ""}\t{(r.Level ?? FailureLevel.Warning).ToString().ToLowerInvariant()}\t{TsvEscape(FormatLocation(r))}\t{TsvEscape(r.Message.Text)}");
                    }
                    return 0;

                case "text":
                    var table = new Table()
                        .AddColumn("#")
                        .AddColumn("Rule id")
                        .AddColumn("Level")
                        .AddColumn("Location")
                        .AddColumn("Message");

                    for (int i = 0; i < results.Count; i++)
                    {
                        var r = results[i];
                        table.AddRow(
                            i.ToString(),
                            Markup.Escape(r.RuleId ?? r.Rule?.Id ?? ""),
                            Markup.Escape((r.Level ?? FailureLevel.Warning).ToString()),
                            Markup.Escape(FormatLocation(r)),
                            Markup.Escape(Truncate(r.Message.Text ?? "", 80)));
                    }

                    AnsiConsole.Write(table);
                    return 0;

                default:
                    AnsiConsole.MarkupLine($"[red]Unknown --format '{Markup.Escape(format)}'.[/] Use one of: text, json, tsv.");
                    return 1;
            }
        });
        return cmd;
    }

    static string FormatLocation(Result result)
    {
        var phys = result.Locations?.FirstOrDefault()?.PhysicalLocation;
        if (phys is null) return "";
        var uri = phys.ArtifactLocation?.Uri?.ToString() ?? "";
        var region = phys.Region;
        if (region is null || region.StartLine is not int line) return uri;
        return region.StartColumn is int col
            ? $"{uri}:{line}:{col}"
            : $"{uri}:{line}";
    }

    static string Truncate(string s, int max) =>
        s.Length <= max ? s : string.Concat(s.AsSpan(0, max - 1), "…");

    static string TsvEscape(string? s) =>
        s is null ? "" : s.Replace('\t', ' ').Replace('\n', ' ').Replace('\r', ' ');
}
