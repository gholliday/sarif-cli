using System.CommandLine;
using Sarif.Cli.Model;
using Spectre.Console;

namespace Sarif.Cli.Commands;

/// <summary>
/// Lightweight schema-shape smoke test: deserialises the file through our model,
/// reports basic counts, and surfaces common authoring slips. For full validation
/// (schema + 30+ correctness rules) use the Sarif.Multitool's <c>sarif validate</c>
/// command — see the README.
/// </summary>
internal static class ValidateCommand
{
    internal static Command Create()
    {
        var fileArg = new Argument<FileInfo>("file") { Description = "Path to a .sarif file." };
        var strictOpt = new Option<bool>("--strict") { Description = "Treat the surfaced authoring warnings as errors (exit code 2)." };
        var cmd = new Command("validate", "Smoke-test a SARIF file by deserialising it through the authoring model.") { fileArg, strictOpt };

        cmd.SetAction(parseResult =>
        {
            var file = parseResult.GetValue(fileArg)!;
            var strict = parseResult.GetValue(strictOpt);
            try
            {
                var log = SarifFile.Load(file.FullName);
                int runs = log.Runs.Count;
                int totalResults = log.Runs.Sum(r => r.Results?.Count ?? 0);
                int totalRules = log.Runs.Sum(r => r.Tool.Driver.Rules?.Count ?? 0);

                AnsiConsole.MarkupLine($"[green]OK[/] {Markup.Escape(file.FullName)}");
                AnsiConsole.MarkupLine($"  runs: {runs}, rules: {totalRules}, results: {totalResults}");

                var warnings = CheckAuthoringSlips(log);
                foreach (var w in warnings)
                    AnsiConsole.MarkupLine($"  [yellow]warn:[/] {Markup.Escape(w)}");

                if (warnings.Count == 0)
                    AnsiConsole.MarkupLine("[dim]Tip: for full schema + correctness validation install Sarif.Multitool ('dotnet tool install -g Sarif.Multitool') and run 'sarif validate'.[/]");

                return strict && warnings.Count > 0 ? 2 : 0;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]FAIL[/] {Markup.Escape(file.FullName)}");
                AnsiConsole.MarkupLine($"  {Markup.Escape(ex.Message)}");
                return 1;
            }
        });
        return cmd;
    }

    static List<string> CheckAuthoringSlips(SarifLog log)
    {
        var warnings = new List<string>();
        for (int ri = 0; ri < log.Runs.Count; ri++)
        {
            var run = log.Runs[ri];
            var ruleIds = new HashSet<string>(StringComparer.Ordinal);
            if (run.Tool.Driver.Rules is { } rules)
                foreach (var r in rules) ruleIds.Add(r.Id);

            if (run.Results is null) continue;
            for (int i = 0; i < run.Results.Count; i++)
            {
                var result = run.Results[i];

                var refId = result.RuleId ?? result.Rule?.Id;
                if (string.IsNullOrEmpty(refId))
                {
                    warnings.Add($"runs[{ri}].results[{i}]: result has no ruleId or rule.id.");
                }
                else if (ruleIds.Count > 0 && !ruleIds.Contains(refId))
                {
                    warnings.Add($"runs[{ri}].results[{i}]: ruleId '{refId}' is not defined on the tool driver.");
                }

                if (result.Locations is { } locs)
                {
                    for (int li = 0; li < locs.Count; li++)
                    {
                        var phys = locs[li].PhysicalLocation;
                        if (phys is null) continue;
                        var artifactUri = phys.ArtifactLocation?.Uri?.ToString();
                        if (string.IsNullOrEmpty(artifactUri))
                        {
                            warnings.Add($"runs[{ri}].results[{i}].locations[{li}].physicalLocation.artifactLocation.uri is empty.");
                        }
                    }
                }
            }
        }
        return warnings;
    }
}
