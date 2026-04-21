using System.Text.Json;
using Sarif.Cli.Model;

namespace Sarif.Cli;

/// <summary>
/// High-level file I/O for SARIF logs.
/// All serialisation goes through the source-generated <see cref="SarifJsonContext"/>
/// so this code is fully AOT- and trim-compatible.
/// </summary>
public static class SarifFile
{
    /// <summary>
    /// Loads a SARIF log from disk.
    /// </summary>
    public static SarifLog Load(string path)
    {
        using var stream = File.OpenRead(path);
        var log = JsonSerializer.Deserialize(stream, SarifJsonContext.Default.SarifLog);
        return log ?? throw new InvalidDataException($"File '{path}' did not contain a SARIF log.");
    }

    /// <summary>
    /// Saves a SARIF log to disk.
    /// </summary>
    public static void Save(SarifLog log, string path)
    {
        using var stream = File.Create(path);
        JsonSerializer.Serialize(stream, log, SarifJsonContext.Default.SarifLog);
    }

    /// <summary>
    /// Returns the first <see cref="Run"/> in the log, creating one if none exist.
    /// </summary>
    public static Run GetOrCreateFirstRun(SarifLog log)
    {
        if (log.Runs.Count == 0)
        {
            log.Runs.Add(new Run());
        }
        return log.Runs[0];
    }
}
