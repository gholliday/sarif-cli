using System.ComponentModel;
using System.Diagnostics;

namespace Sarif.Cli.Commands;

internal static class DoltHelperClient
{
    internal const int HelperNotFoundExitCode = 127;

    public static DoltHelperResult Run(string? helperPath, IReadOnlyList<string> args)
    {
        var executable = ResolveExecutable(helperPath);
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        foreach (var arg in args)
            startInfo.ArgumentList.Add(arg);

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
                return new DoltHelperResult(HelperNotFoundExitCode, "", $"Failed to start {executable}.{Environment.NewLine}");

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            process.WaitForExit();
            return new DoltHelperResult(
                process.ExitCode,
                stdoutTask.GetAwaiter().GetResult(),
                stderrTask.GetAwaiter().GetResult());
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 2 || ex.NativeErrorCode == 3)
        {
            return new DoltHelperResult(HelperNotFoundExitCode, "", $"{ex.Message}{Environment.NewLine}");
        }
        catch (FileNotFoundException ex)
        {
            return new DoltHelperResult(HelperNotFoundExitCode, "", $"{ex.Message}{Environment.NewLine}");
        }
    }

    internal static string ResolveExecutable(string? helperPath)
    {
        if (!string.IsNullOrWhiteSpace(helperPath))
            return helperPath;

        var env = Environment.GetEnvironmentVariable("SARIF_DOLT_HELPER");
        if (!string.IsNullOrWhiteSpace(env))
            return env;

        var fileName = OperatingSystem.IsWindows() ? "sarif-dolt.exe" : "sarif-dolt";
        var appLocal = Path.Combine(AppContext.BaseDirectory, fileName);
        return File.Exists(appLocal) ? appLocal : fileName;
    }
}

internal sealed record DoltHelperResult(int ExitCode, string StandardOutput, string StandardError);
