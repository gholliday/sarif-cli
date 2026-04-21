using System.CommandLine;
using Sarif.Cli.Model;
using Spectre.Console;

namespace Sarif.Cli.Commands;

internal static class NewCommand
{
    internal static Command Create()
    {
        var fileArg = new Argument<FileInfo>("file") { Description = "Path for the new .sarif file." };
        var toolNameOpt = new Option<string>("--tool") { Description = "Tool driver name (e.g. 'MyAnalyzer').", Required = true };
        var toolVersionOpt = new Option<string?>("--tool-version") { Description = "Tool driver version." };
        var semanticVersionOpt = new Option<string?>("--semantic-version") { Description = "Tool driver semantic version." };
        var infoUriOpt = new Option<string?>("--info-uri") { Description = "Tool driver informationUri." };
        var organizationOpt = new Option<string?>("--organization") { Description = "Tool driver organization." };
        var uriBaseOpt = new Option<string[]>("--uri-base") { Description = "Declare an originalUriBaseId mapping (repeatable). Format: NAME=PATH (e.g. 'SRCROOT=file:///c:/repo/').", AllowMultipleArgumentsPerToken = false };
        var forceOpt = new Option<bool>("--force") { Description = "Overwrite if the file exists." };

        var cmd = new Command("new", "Create an empty SARIF log scaffold.")
        {
            fileArg, toolNameOpt, toolVersionOpt, semanticVersionOpt, infoUriOpt, organizationOpt, uriBaseOpt, forceOpt
        };

        cmd.SetAction(parseResult =>
        {
            var file = parseResult.GetValue(fileArg)!;
            var toolName = parseResult.GetValue(toolNameOpt)!;
            var toolVersion = parseResult.GetValue(toolVersionOpt);
            var semanticVersion = parseResult.GetValue(semanticVersionOpt);
            var infoUri = parseResult.GetValue(infoUriOpt);
            var organization = parseResult.GetValue(organizationOpt);
            var uriBases = parseResult.GetValue(uriBaseOpt);
            var force = parseResult.GetValue(forceOpt);

            if (file.Exists && !force)
            {
                AnsiConsole.MarkupLine($"[red]Refusing to overwrite[/] {Markup.Escape(file.FullName)} (use --force).");
                return 1;
            }

            Uri? infoUriValue = null;
            if (!string.IsNullOrEmpty(infoUri))
            {
                if (!Uri.TryCreate(infoUri, UriKind.Absolute, out infoUriValue))
                {
                    AnsiConsole.MarkupLine($"[red]Invalid --info-uri '{Markup.Escape(infoUri)}'.[/] Must be an absolute URI.");
                    return 1;
                }
            }

            Dictionary<string, ArtifactLocation>? originalUriBaseIds = null;
            if (uriBases is not null && uriBases.Length > 0)
            {
                originalUriBaseIds = new Dictionary<string, ArtifactLocation>(StringComparer.Ordinal);
                foreach (var entry in uriBases)
                {
                    int eq = entry.IndexOf('=');
                    if (eq <= 0)
                    {
                        AnsiConsole.MarkupLine($"[red]Invalid --uri-base '{Markup.Escape(entry)}'.[/] Format: NAME=PATH.");
                        return 1;
                    }
                    var name = entry[..eq];
                    var path = entry[(eq + 1)..];
                    if (!Uri.TryCreate(path, UriKind.RelativeOrAbsolute, out var pathUri))
                    {
                        AnsiConsole.MarkupLine($"[red]Invalid path in --uri-base '{Markup.Escape(entry)}'.[/]");
                        return 1;
                    }
                    originalUriBaseIds[name] = new ArtifactLocation { Uri = pathUri };
                }
            }

            var log = new SarifLog
            {
                Runs =
                {
                    new Run
                    {
                        Tool = new Tool
                        {
                            Driver = new ToolComponent
                            {
                                Name = toolName,
                                Version = toolVersion,
                                SemanticVersion = semanticVersion,
                                Organization = organization,
                                InformationUri = infoUriValue,
                                Rules = new List<ReportingDescriptor>()
                            }
                        },
                        OriginalUriBaseIds = originalUriBaseIds,
                        Results = new List<Result>()
                    }
                }
            };

            SarifFile.Save(log, file.FullName);
            AnsiConsole.MarkupLine($"[green]Created[/] {Markup.Escape(file.FullName)} [dim](tool: {Markup.Escape(toolName)})[/]");
            return 0;
        });
        return cmd;
    }
}
