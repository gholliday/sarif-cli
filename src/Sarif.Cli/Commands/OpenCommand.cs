using System.CommandLine;
using Sarif.Cli.Model;
using Spectre.Console;

namespace Sarif.Cli.Commands;

internal static class OpenCommand
{
    internal static Command Create()
    {
        var fileArg = new Argument<FileInfo>("file") { Description = "Path to a .sarif file." };
        var cmd = new Command("open", "Show a summary of a SARIF log.") { fileArg };

        cmd.SetAction(parseResult =>
        {
            var file = parseResult.GetValue(fileArg)!;
            var log = SarifFile.Load(file.FullName);

            AnsiConsole.MarkupLine($"[bold]File:[/] {Markup.Escape(file.FullName)}");
            AnsiConsole.MarkupLine($"[bold]Schema:[/] {Markup.Escape(log.Schema ?? "(none)")}");
            AnsiConsole.MarkupLine($"[bold]Version:[/] {Markup.Escape(log.Version)}");
            AnsiConsole.MarkupLine($"[bold]Runs:[/] {log.Runs.Count}");

            if (log.Runs.Count == 0) return 0;

            var table = new Table()
                .AddColumn("#")
                .AddColumn("Tool")
                .AddColumn("Version")
                .AddColumn("Rules")
                .AddColumn("Results");

            for (int i = 0; i < log.Runs.Count; i++)
            {
                var run = log.Runs[i];
                var driver = run.Tool.Driver;
                table.AddRow(
                    i.ToString(),
                    Markup.Escape(driver.Name),
                    Markup.Escape(driver.SemanticVersion ?? driver.Version ?? ""),
                    (driver.Rules?.Count ?? 0).ToString(),
                    (run.Results?.Count ?? 0).ToString());
            }

            AnsiConsole.Write(table);

            var counts = new Dictionary<FailureLevel, int>();
            foreach (var run in log.Runs)
            {
                if (run.Results is null) continue;
                foreach (var result in run.Results)
                {
                    var level = result.Level ?? LookupDefaultLevel(run, result.RuleId ?? result.Rule?.Id, result.RuleIndex);
                    counts[level] = counts.GetValueOrDefault(level) + 1;
                }
            }
            if (counts.Count > 0)
            {
                AnsiConsole.MarkupLine("[bold]Result levels:[/]");
                foreach (var kvp in counts.OrderByDescending(k => k.Value))
                {
                    AnsiConsole.MarkupLine($"  {Markup.Escape(kvp.Key.ToString())}: {kvp.Value}");
                }
            }

            return 0;
        });
        return cmd;
    }

    static FailureLevel LookupDefaultLevel(Run run, string? ruleId, int? ruleIndex)
    {
        var rules = run.Tool.Driver.Rules;
        if (rules is null) return FailureLevel.Warning;
        ReportingDescriptor? rule = null;
        if (ruleIndex is int idx && idx >= 0 && idx < rules.Count) rule = rules[idx];
        rule ??= rules.FirstOrDefault(r => r.Id == ruleId);
        return rule?.DefaultConfiguration?.Level ?? FailureLevel.Warning;
    }
}
