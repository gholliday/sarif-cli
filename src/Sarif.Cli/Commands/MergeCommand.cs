using System.CommandLine;
using Sarif.Cli.Model;
using Spectre.Console;

namespace Sarif.Cli.Commands;

/// <summary>
/// Concatenates the runs (and their rules + results) from N input SARIF files into
/// a single output file. This covers the 80% "I just want one log" use-case; for
/// rules-deduplication, schema-aware merging, or run-level merging across the same
/// tool, use Sarif.Multitool's <c>sarif merge</c>.
/// </summary>
internal static class MergeCommand
{
    internal static Command Create()
    {
        var inputsArg = new Argument<FileInfo[]>("inputs") { Description = "Input .sarif files to merge.", Arity = ArgumentArity.OneOrMore };
        var outputOpt = new Option<FileInfo>("--output", "-o") { Description = "Output .sarif file.", Required = true };
        var forceOpt = new Option<bool>("--force") { Description = "Overwrite the output file if it exists." };

        var cmd = new Command("merge", "Concatenate the runs from multiple SARIF files into one.")
        {
            inputsArg, outputOpt, forceOpt
        };

        cmd.SetAction(parseResult =>
        {
            var inputs = parseResult.GetValue(inputsArg)!;
            var output = parseResult.GetValue(outputOpt)!;
            var force = parseResult.GetValue(forceOpt);

            if (inputs.Length < 1)
            {
                AnsiConsole.MarkupLine("[red]At least one input file is required.[/]");
                return 1;
            }

            if (output.Exists && !force)
            {
                AnsiConsole.MarkupLine($"[red]Refusing to overwrite[/] {Markup.Escape(output.FullName)} (use --force).");
                return 1;
            }

            var merged = new SarifLog();

            foreach (var input in inputs)
            {
                if (!input.Exists)
                {
                    AnsiConsole.MarkupLine($"[red]Input file not found:[/] {Markup.Escape(input.FullName)}");
                    return 1;
                }

                SarifLog log;
                try
                {
                    log = SarifFile.Load(input.FullName);
                }
                catch (Exception ex)
                {
                    AnsiConsole.MarkupLine($"[red]Failed to parse[/] {Markup.Escape(input.FullName)}: {Markup.Escape(ex.Message)}");
                    return 1;
                }

                foreach (var run in log.Runs)
                    merged.Runs.Add(run);
            }

            SarifFile.Save(merged, output.FullName);
            int totalResults = merged.Runs.Sum(r => r.Results?.Count ?? 0);
            AnsiConsole.MarkupLine($"[green]Merged[/] {inputs.Length} file(s) → {merged.Runs.Count} run(s), {totalResults} result(s) → {Markup.Escape(output.FullName)}");
            return 0;
        });
        return cmd;
    }
}
