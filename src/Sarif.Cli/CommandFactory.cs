using System.CommandLine;
using Sarif.Cli.Commands;

namespace Sarif.Cli;

/// <summary>
/// Builds the System.CommandLine command tree for the sarif-cli application.
/// </summary>
public static class CommandFactory
{
    /// <summary>
    /// Creates the root command with all subcommands registered.
    /// </summary>
    public static RootCommand CreateRootCommand()
    {
        var rootCommand = new RootCommand(
            "A CLI tool for constructing and inspecting SARIF (Static Analysis Results Interchange Format) v2.1.0 files. " +
            "Designed so AI assistants and humans can build SARIF logs incrementally without writing JSON by hand.");
        rootCommand.Add(NewCommand.Create());
        rootCommand.Add(OpenCommand.Create());
        rootCommand.Add(ListCommand.Create());
        rootCommand.Add(AddCommand.Create());
        rootCommand.Add(MergeCommand.Create());
        rootCommand.Add(ValidateCommand.Create());
        rootCommand.Add(ExamplesCommand.Create());
        return rootCommand;
    }
}
