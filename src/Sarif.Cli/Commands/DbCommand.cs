using System.CommandLine;
using Spectre.Console;

namespace Sarif.Cli.Commands;

/// <summary>
/// Commands for the optional Dolt-backed working store.
/// </summary>
internal static class DbCommand
{
    internal static Command Create()
    {
        var db = new Command("db", "Use an optional Dolt-backed SARIF working store through the sarif-dolt helper.");
        db.Add(CreateInitCommand());
        db.Add(CreateAddResultCommand());
        db.Add(CreateAddResultsCommand());
        db.Add(CreateCommitCommand());
        db.Add(CreateDiffCommand());
        db.Add(CreateExportCommand());
        return db;
    }

    static Command CreateInitCommand()
    {
        var storeOpt = StoreOption();
        var helperOpt = HelperOption();
        var toolOpt = new Option<string>("--tool") { Description = "Tool driver name.", Required = true };
        var toolVersionOpt = new Option<string?>("--tool-version") { Description = "Tool driver version." };
        var semanticVersionOpt = new Option<string?>("--semantic-version") { Description = "Tool semantic version." };
        var organizationOpt = new Option<string?>("--organization") { Description = "Tool organization." };
        var infoUriOpt = new Option<string?>("--info-uri") { Description = "Tool information URI." };
        var uriBaseOpt = new Option<string[]>("--uri-base") { Description = "Original URI base mapping (repeatable): NAME=URI.", AllowMultipleArgumentsPerToken = false };

        var cmd = new Command("init", "Initialize a Dolt-backed SARIF working store.")
        {
            storeOpt, helperOpt, toolOpt, toolVersionOpt, semanticVersionOpt, organizationOpt, infoUriOpt, uriBaseOpt
        };

        cmd.SetAction(parseResult =>
        {
            var args = new List<string> { "init", "--store", parseResult.GetValue(storeOpt)! };
            Add(args, "--tool", parseResult.GetValue(toolOpt));
            Add(args, "--tool-version", parseResult.GetValue(toolVersionOpt));
            Add(args, "--semantic-version", parseResult.GetValue(semanticVersionOpt));
            Add(args, "--organization", parseResult.GetValue(organizationOpt));
            Add(args, "--info-uri", parseResult.GetValue(infoUriOpt));
            AddRepeated(args, "--uri-base", parseResult.GetValue(uriBaseOpt));
            return RunHelper(parseResult.GetValue(helperOpt), args);
        });

        return cmd;
    }

    static Command CreateAddResultCommand()
    {
        var storeOpt = StoreOption();
        var helperOpt = HelperOption();
        var ruleIdOpt = new Option<string>("--rule-id") { Description = "Rule id this result is an instance of.", Required = true };
        var ruleNameOpt = new Option<string?>("--rule-name") { Description = "Human-readable rule name." };
        var messageOpt = new Option<string>("--message") { Description = "Result message text.", Required = true };
        var levelOpt = new Option<string?>("--level") { Description = "Result level: none|note|warning|error." };
        var fileOpt = new Option<string?>("--file") { Description = "Source file URI." };
        var uriBaseIdOpt = new Option<string?>("--uri-base-id") { Description = "uriBaseId for the artifact location." };
        var startLineOpt = new Option<int?>("--start-line") { Description = "1-based start line." };
        var startColOpt = new Option<int?>("--start-column") { Description = "1-based start column." };
        var endLineOpt = new Option<int?>("--end-line") { Description = "1-based end line." };
        var endColOpt = new Option<int?>("--end-column") { Description = "1-based end column." };
        var snippetOpt = new Option<string?>("--snippet") { Description = "Source snippet text." };
        var tagOpt = new Option<string[]>("--tag") { Description = "Tag (repeatable).", AllowMultipleArgumentsPerToken = false };
        var secSevOpt = new Option<string?>("--security-severity") { Description = "GitHub-style numeric severity." };
        var cvssOpt = new Option<string?>("--cvss") { Description = "CVSS vector string." };
        var propertyOpt = new Option<string[]>("--property") { Description = "Property entry (repeatable): key=value, or key:json=<raw json>.", AllowMultipleArgumentsPerToken = false };

        var cmd = new Command("add-result", "Add a result to the Dolt-backed working store.")
        {
            storeOpt, helperOpt, ruleIdOpt, ruleNameOpt, messageOpt, levelOpt, fileOpt, uriBaseIdOpt,
            startLineOpt, startColOpt, endLineOpt, endColOpt, snippetOpt, tagOpt, secSevOpt, cvssOpt, propertyOpt
        };

        cmd.SetAction(parseResult =>
        {
            var args = new List<string> { "add-result", "--store", parseResult.GetValue(storeOpt)! };
            Add(args, "--rule-id", parseResult.GetValue(ruleIdOpt));
            Add(args, "--rule-name", parseResult.GetValue(ruleNameOpt));
            Add(args, "--message", parseResult.GetValue(messageOpt));
            Add(args, "--level", parseResult.GetValue(levelOpt));
            Add(args, "--file", parseResult.GetValue(fileOpt));
            Add(args, "--uri-base-id", parseResult.GetValue(uriBaseIdOpt));
            Add(args, "--start-line", parseResult.GetValue(startLineOpt));
            Add(args, "--start-column", parseResult.GetValue(startColOpt));
            Add(args, "--end-line", parseResult.GetValue(endLineOpt));
            Add(args, "--end-column", parseResult.GetValue(endColOpt));
            Add(args, "--snippet", parseResult.GetValue(snippetOpt));
            AddRepeated(args, "--tag", parseResult.GetValue(tagOpt));
            Add(args, "--security-severity", parseResult.GetValue(secSevOpt));
            Add(args, "--cvss", parseResult.GetValue(cvssOpt));
            AddRepeated(args, "--property", parseResult.GetValue(propertyOpt));
            return RunHelper(parseResult.GetValue(helperOpt), args);
        });

        return cmd;
    }

    static Command CreateAddResultsCommand()
    {
        var storeOpt = StoreOption();
        var helperOpt = HelperOption();
        var inputOpt = new Option<FileInfo>("--input") { Description = "JSONL file containing one result object per line.", Required = true };

        var cmd = new Command("add-results", "Add many results to the Dolt-backed working store from JSONL.") { storeOpt, helperOpt, inputOpt };
        cmd.SetAction(parseResult =>
        {
            var args = new List<string> { "add-results", "--store", parseResult.GetValue(storeOpt)! };
            Add(args, "--input", parseResult.GetValue(inputOpt)!.FullName);
            return RunHelper(parseResult.GetValue(helperOpt), args);
        });

        return cmd;
    }

    static Command CreateCommitCommand()
    {
        var storeOpt = StoreOption();
        var helperOpt = HelperOption();
        var messageOpt = new Option<string>("--message") { Description = "Commit message.", Required = true };
        var allowEmptyOpt = new Option<bool>("--allow-empty") { Description = "Allow a commit when the working set has no changes." };

        var cmd = new Command("commit", "Create a Dolt commit for the working store.") { storeOpt, helperOpt, messageOpt, allowEmptyOpt };
        cmd.SetAction(parseResult =>
        {
            var args = new List<string> { "commit", "--store", parseResult.GetValue(storeOpt)! };
            Add(args, "--message", parseResult.GetValue(messageOpt));
            if (parseResult.GetValue(allowEmptyOpt)) args.Add("--allow-empty");
            return RunHelper(parseResult.GetValue(helperOpt), args);
        });
        return cmd;
    }

    static Command CreateDiffCommand()
    {
        var storeOpt = StoreOption();
        var helperOpt = HelperOption();
        var fromOpt = new Option<string>("--from") { Description = "Older Dolt revision.", DefaultValueFactory = _ => "HEAD" };
        var toOpt = new Option<string>("--to") { Description = "Newer Dolt revision.", DefaultValueFactory = _ => "WORKING" };
        var formatOpt = new Option<string>("--format") { Description = "Output format: summary|text|rows|json|tsv.", DefaultValueFactory = _ => "summary" };

        var cmd = new Command("diff", "Show Dolt changes in the working store.") { storeOpt, helperOpt, fromOpt, toOpt, formatOpt };
        cmd.SetAction(parseResult =>
        {
            var args = new List<string> { "diff", "--store", parseResult.GetValue(storeOpt)! };
            Add(args, "--from", parseResult.GetValue(fromOpt));
            Add(args, "--to", parseResult.GetValue(toOpt));
            Add(args, "--format", parseResult.GetValue(formatOpt));
            return RunHelper(parseResult.GetValue(helperOpt), args);
        });
        return cmd;
    }

    static Command CreateExportCommand()
    {
        var storeOpt = StoreOption();
        var helperOpt = HelperOption();
        var outputOpt = new Option<FileInfo>("--output") { Description = "Output .sarif file path.", Required = true };

        var cmd = new Command("export", "Export the Dolt-backed working store to a SARIF file.") { storeOpt, helperOpt, outputOpt };
        cmd.SetAction(parseResult =>
        {
            var args = new List<string> { "export", "--store", parseResult.GetValue(storeOpt)! };
            Add(args, "--output", parseResult.GetValue(outputOpt)!.FullName);
            return RunHelper(parseResult.GetValue(helperOpt), args);
        });
        return cmd;
    }

    static Option<string> StoreOption()
        => new("--store") { Description = "Path to the Dolt-backed SARIF store directory.", DefaultValueFactory = _ => ".sarif-dolt" };

    static Option<string?> HelperOption()
        => new("--helper") { Description = "Path to sarif-dolt helper. Defaults to SARIF_DOLT_HELPER, app-local helper, or PATH." };

    static int RunHelper(string? helperPath, IReadOnlyList<string> args)
    {
        var result = DoltHelperClient.Run(helperPath, args);
        if (!string.IsNullOrEmpty(result.StandardOutput))
            Console.Out.Write(result.StandardOutput);
        if (!string.IsNullOrEmpty(result.StandardError))
            Console.Error.Write(result.StandardError);

        if (result.ExitCode == DoltHelperClient.HelperNotFoundExitCode)
        {
            AnsiConsole.MarkupLine("[red]sarif-dolt helper was not found.[/]");
            AnsiConsole.MarkupLine("Build it from [bold]tools/sarif-dolt[/] and place it next to sarif-cli, on PATH, or set SARIF_DOLT_HELPER.");
        }

        return result.ExitCode;
    }

    static void Add<T>(List<string> args, string name, T? value)
    {
        if (value is null) return;
        var text = value.ToString();
        if (string.IsNullOrEmpty(text)) return;
        args.Add(name);
        args.Add(text);
    }

    static void AddRepeated(List<string> args, string name, string[]? values)
    {
        if (values is null) return;
        foreach (var value in values)
            Add(args, name, value);
    }
}
