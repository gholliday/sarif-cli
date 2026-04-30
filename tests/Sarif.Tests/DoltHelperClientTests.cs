using Sarif.Cli.Commands;
using Xunit;

namespace Sarif.Tests;

public class DoltHelperClientTests
{
    [Fact]
    public void ResolveExecutable_UsesExplicitHelperPath()
    {
        Assert.Equal("custom-helper", DoltHelperClient.ResolveExecutable("custom-helper"));
    }

    [Fact]
    public void Run_ReturnsHelperNotFoundExitCodeForMissingExecutable()
    {
        var result = DoltHelperClient.Run("sarif-dolt-helper-that-does-not-exist", Array.Empty<string>());

        Assert.Equal(DoltHelperClient.HelperNotFoundExitCode, result.ExitCode);
        Assert.Empty(result.StandardOutput);
        Assert.NotEmpty(result.StandardError);
    }

    [Fact]
    public void Run_PropagatesStdoutStderrAndExitCode()
    {
        var (shell, args) = ShellCommand("echo STDOUT && echo STDERR 1>&2 && exit 42");

        var result = DoltHelperClient.Run(shell, args);

        Assert.Equal(42, result.ExitCode);
        Assert.Contains("STDOUT", result.StandardOutput);
        Assert.Contains("STDERR", result.StandardError);
    }

    [Fact]
    public void Run_ReadsLargeStdoutAndStderrWithoutDeadlock()
    {
        var command = OperatingSystem.IsWindows()
            ? "(for /L %i in (1,1,2000) do @echo OUT%i) & (for /L %i in (1,1,2000) do @echo ERR%i 1>&2)"
            : "i=0; while [ $i -lt 2000 ]; do echo OUT$i; echo ERR$i >&2; i=$((i+1)); done";
        var (shell, args) = ShellCommand(command);

        var result = DoltHelperClient.Run(shell, args);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("OUT1999", result.StandardOutput);
        Assert.Contains("ERR1999", result.StandardError);
    }

    static (string Shell, string[] Args) ShellCommand(string command)
    {
        if (OperatingSystem.IsWindows())
        {
            var shell = Environment.GetEnvironmentVariable("ComSpec");
            return (string.IsNullOrWhiteSpace(shell) ? "cmd.exe" : shell, ["/d", "/c", command]);
        }

        return ("/bin/sh", ["-c", command]);
    }
}
