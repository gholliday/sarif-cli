using System.Text.Json.Serialization;

namespace Sarif.Cli.Model;

/// <summary>
/// System.Text.Json source-generated context for the SARIF authoring model.
/// Generates serializers at compile time so the runtime needs no reflection,
/// making the CLI fully AOT- and trim-safe.
/// </summary>
[JsonSourceGenerationOptions(
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    PropertyNameCaseInsensitive = false,
    NewLine = "\n")]
[JsonSerializable(typeof(SarifLog))]
public partial class SarifJsonContext : JsonSerializerContext
{
}
