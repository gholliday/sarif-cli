using System.CommandLine;
using Spectre.Console;

namespace Sarif.Cli.Commands;

internal static class ExamplesCommand
{
    internal static Command Create()
    {
        var cmd = new Command("examples", "Show worked examples of building a SARIF log.");
        cmd.SetAction(_ =>
        {
            AnsiConsole.MarkupLine("[bold underline]Build a SARIF log from scratch[/]");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[dim]# 1. Scaffold a new log with tool driver metadata[/]");
            AnsiConsole.WriteLine("sarif-cli new results.sarif \\");
            AnsiConsole.WriteLine("  --tool MyAnalyzer --tool-version 1.0.0 \\");
            AnsiConsole.WriteLine("  --info-uri https://example.com/myanalyzer \\");
            AnsiConsole.WriteLine("  --organization Contoso \\");
            AnsiConsole.WriteLine("  --uri-base SRCROOT=file:///c:/repo/");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[dim]# 2. Define rules. --tag/--security-severity/--cvss/--property add to properties.[/]");
            AnsiConsole.WriteLine("sarif-cli add rule results.sarif \\");
            AnsiConsole.WriteLine("  --id MA0001 --name AvoidEmptyCatch \\");
            AnsiConsole.WriteLine("  --short-description \"Empty catch blocks hide errors.\" \\");
            AnsiConsole.WriteLine("  --default-level warning \\");
            AnsiConsole.WriteLine("  --help-uri https://example.com/rules/MA0001 \\");
            AnsiConsole.WriteLine("  --tag security --tag injection \\");
            AnsiConsole.WriteLine("  --security-severity 8.5 \\");
            AnsiConsole.WriteLine("  --property \"confidence=high\"");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[dim]# 3. Record results. Use --rule-index from a counter; --uri-base-id for SRCROOT.[/]");
            AnsiConsole.WriteLine("sarif-cli add result results.sarif \\");
            AnsiConsole.WriteLine("  --rule-index 0 \\");
            AnsiConsole.WriteLine("  --message \"Catch block on line 42 swallows all exceptions.\" \\");
            AnsiConsole.WriteLine("  --uri-base-id SRCROOT \\");
            AnsiConsole.WriteLine("  --file src/Foo.cs --start-line 42 --start-column 9 --end-line 44 --end-column 10 \\");
            AnsiConsole.WriteLine("  --snippet \"catch { }\" \\");
            AnsiConsole.WriteLine("  --property \"fingerprint=abc123\"");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[dim]# 4. Inspect (--format json|tsv pipe-friendly; validate --strict for CI).[/]");
            AnsiConsole.WriteLine("sarif-cli open results.sarif");
            AnsiConsole.WriteLine("sarif-cli list rules results.sarif --no-wrap");
            AnsiConsole.WriteLine("sarif-cli list results results.sarif --rule-id MA0001 --format tsv");
            AnsiConsole.WriteLine("sarif-cli validate results.sarif --strict");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[dim]# 5. Combine logs (concat semantics).[/]");
            AnsiConsole.WriteLine("sarif-cli merge a.sarif b.sarif --output combined.sarif");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[dim]# 6. Bulk-import from a JSONL file (one rule/result per line).[/]");
            AnsiConsole.MarkupLine("[dim]#    Great for regenerating a log from a source-of-truth (SQL, .csv, etc).[/]");
            AnsiConsole.WriteLine("cat <<'JSONL' > findings.jsonl");
            AnsiConsole.WriteLine("{\"kind\":\"rule\",\"id\":\"MA0001\",\"name\":\"AvoidEmptyCatch\",\"defaultLevel\":\"warning\",\"tags\":[\"security\"],\"securitySeverity\":\"8.5\"}");
            AnsiConsole.WriteLine("{\"kind\":\"result\",\"ruleId\":\"MA0001\",\"message\":\"Catch swallows exceptions.\",\"file\":\"src/Foo.cs\",\"uriBaseId\":\"SRCROOT\",\"startLine\":42}");
            AnsiConsole.WriteLine("JSONL");
            AnsiConsole.WriteLine("sarif-cli add bulk findings.jsonl results.sarif");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold underline]Validation, merging, conversion[/]");
            AnsiConsole.MarkupLine("This CLI focuses on [italic]authoring[/]. For schema validation, merging, conversion from");
            AnsiConsole.MarkupLine("other tools' output, querying, and rebasing URIs, install the official Microsoft tool:");
            AnsiConsole.WriteLine();
            AnsiConsole.WriteLine("  dotnet tool install --global Sarif.Multitool");
            AnsiConsole.WriteLine("  sarif validate results.sarif");
            AnsiConsole.WriteLine("  sarif merge run1.sarif run2.sarif --output merged.sarif");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold underline]Failure levels[/]");
            AnsiConsole.MarkupLine("  [grey]none[/]    — informational, not an issue");
            AnsiConsole.MarkupLine("  [blue]note[/]    — minor suggestion");
            AnsiConsole.MarkupLine("  [yellow]warning[/] — should be addressed");
            AnsiConsole.MarkupLine("  [red]error[/]   — must be addressed; blocks the build by convention");
            return 0;
        });
        return cmd;
    }
}
