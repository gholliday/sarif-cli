using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sarif.Cli.Model;

// SARIF v2.1.0 object model, scoped to the surface area observed across a
// corpus of real-world SARIF logs from common static-analysis and security
// scanning tools. Every type carries an AdditionalProperties extension bag so
// unknown fields round-trip verbatim — critical because we deliberately do
// not model every spec corner. Designed for System.Text.Json source
// generation, AOT- and trim-safe.
//
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
//
// PropertyBag is modelled as Dictionary<string, JsonElement> rather than a
// dedicated wrapper type so that arbitrary scalar/object/array values
// (including SARIF's commonly-used "tags": ["..."] and tool-specific
// extension keys like "ai/evidence") survive round-trips losslessly.

/// <summary>SARIF v2.1.0 root document.</summary>
public sealed class SarifLog
{
    [JsonPropertyName("$schema")]
    public string? Schema { get; set; } = "https://json.schemastore.org/sarif-2.1.0.json";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "2.1.0";

    [JsonPropertyName("runs")]
    public List<Run> Runs { get; set; } = new();

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A single tool invocation's worth of analysis output.</summary>
public sealed class Run
{
    [JsonPropertyName("tool")]
    public Tool Tool { get; set; } = new();

    [JsonPropertyName("invocations")]
    public List<Invocation>? Invocations { get; set; }

    [JsonPropertyName("artifacts")]
    public List<Artifact>? Artifacts { get; set; }

    [JsonPropertyName("logicalLocations")]
    public List<LogicalLocation>? LogicalLocations { get; set; }

    [JsonPropertyName("results")]
    public List<Result>? Results { get; set; }

    [JsonPropertyName("automationDetails")]
    public RunAutomationDetails? AutomationDetails { get; set; }

    [JsonPropertyName("versionControlProvenance")]
    public List<VersionControlDetails>? VersionControlProvenance { get; set; }

    [JsonPropertyName("originalUriBaseIds")]
    public Dictionary<string, ArtifactLocation>? OriginalUriBaseIds { get; set; }

    [JsonPropertyName("columnKind")]
    public string? ColumnKind { get; set; }

    [JsonPropertyName("redactionTokens")]
    public List<string>? RedactionTokens { get; set; }

    [JsonPropertyName("language")]
    public string? Language { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>The analysis tool: required driver + optional extensions.</summary>
public sealed class Tool
{
    [JsonPropertyName("driver")]
    public ToolComponent Driver { get; set; } = new();

    [JsonPropertyName("extensions")]
    public List<ToolComponent>? Extensions { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A driver, extension, taxonomy, or policy component of a tool.</summary>
public sealed class ToolComponent
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "unknown";

    [JsonPropertyName("fullName")]
    public string? FullName { get; set; }

    [JsonPropertyName("version")]
    public string? Version { get; set; }

    [JsonPropertyName("semanticVersion")]
    public string? SemanticVersion { get; set; }

    [JsonPropertyName("organization")]
    public string? Organization { get; set; }

    [JsonPropertyName("informationUri")]
    public Uri? InformationUri { get; set; }

    [JsonPropertyName("downloadUri")]
    public Uri? DownloadUri { get; set; }

    [JsonPropertyName("guid")]
    public string? Guid { get; set; }

    [JsonPropertyName("shortDescription")]
    public MultiformatMessageString? ShortDescription { get; set; }

    [JsonPropertyName("fullDescription")]
    public MultiformatMessageString? FullDescription { get; set; }

    [JsonPropertyName("rules")]
    public List<ReportingDescriptor>? Rules { get; set; }

    [JsonPropertyName("notifications")]
    public List<ReportingDescriptor>? Notifications { get; set; }

    [JsonPropertyName("taxa")]
    public List<ReportingDescriptor>? Taxa { get; set; }

    [JsonPropertyName("locations")]
    public List<ArtifactLocation>? Locations { get; set; }

    [JsonPropertyName("associatedComponent")]
    public ToolComponentReference? AssociatedComponent { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Reference to another <see cref="ToolComponent"/> in the same run.</summary>
public sealed class ToolComponentReference
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("index")]
    public int? Index { get; set; }

    [JsonPropertyName("guid")]
    public string? Guid { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Descriptor for a rule, notification, or taxon entry.</summary>
public sealed class ReportingDescriptor
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("guid")]
    public string? Guid { get; set; }

    [JsonPropertyName("shortDescription")]
    public MultiformatMessageString? ShortDescription { get; set; }

    [JsonPropertyName("fullDescription")]
    public MultiformatMessageString? FullDescription { get; set; }

    [JsonPropertyName("help")]
    public MultiformatMessageString? Help { get; set; }

    [JsonPropertyName("helpUri")]
    public Uri? HelpUri { get; set; }

    [JsonPropertyName("messageStrings")]
    public Dictionary<string, MultiformatMessageString>? MessageStrings { get; set; }

    [JsonPropertyName("defaultConfiguration")]
    public ReportingConfiguration? DefaultConfiguration { get; set; }

    [JsonPropertyName("relationships")]
    public List<ReportingDescriptorRelationship>? Relationships { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Reference to a rule/taxon descriptor.</summary>
public sealed class ReportingDescriptorReference
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("index")]
    public int? Index { get; set; }

    [JsonPropertyName("guid")]
    public string? Guid { get; set; }

    [JsonPropertyName("toolComponent")]
    public ToolComponentReference? ToolComponent { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A relationship between two reporting descriptors (e.g. CWE mapping).</summary>
public sealed class ReportingDescriptorRelationship
{
    [JsonPropertyName("target")]
    public ReportingDescriptorReference Target { get; set; } = new();

    [JsonPropertyName("kinds")]
    public List<string>? Kinds { get; set; }

    [JsonPropertyName("description")]
    public Message? Description { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Default configuration for a reporting descriptor.</summary>
public sealed class ReportingConfiguration
{
    [JsonPropertyName("level")]
    public FailureLevel? Level { get; set; }

    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("rank")]
    public double? Rank { get; set; }

    [JsonPropertyName("parameters")]
    public Dictionary<string, JsonElement>? Parameters { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Plain text + optional Markdown rendering.</summary>
public sealed class MultiformatMessageString
{
    [JsonPropertyName("text")]
    public string Text { get; set; } = "";

    [JsonPropertyName("markdown")]
    public string? Markdown { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A localised message, optionally argument-substituted from a rule template.</summary>
public sealed class Message
{
    [JsonPropertyName("text")]
    public string? Text { get; set; }

    [JsonPropertyName("markdown")]
    public string? Markdown { get; set; }

    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("arguments")]
    public List<string>? Arguments { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A single analysis result (alert/finding).</summary>
public sealed class Result
{
    [JsonPropertyName("ruleId")]
    public string? RuleId { get; set; }

    [JsonPropertyName("ruleIndex")]
    public int? RuleIndex { get; set; }

    [JsonPropertyName("rule")]
    public ReportingDescriptorReference? Rule { get; set; }

    [JsonPropertyName("kind")]
    public ResultKind? Kind { get; set; }

    [JsonPropertyName("level")]
    public FailureLevel? Level { get; set; }

    [JsonPropertyName("message")]
    public Message Message { get; set; } = new();

    [JsonPropertyName("locations")]
    public List<Location>? Locations { get; set; }

    [JsonPropertyName("relatedLocations")]
    public List<Location>? RelatedLocations { get; set; }

    [JsonPropertyName("logicalLocations")]
    public List<LogicalLocation>? LogicalLocations { get; set; }

    [JsonPropertyName("codeFlows")]
    public List<CodeFlow>? CodeFlows { get; set; }

    [JsonPropertyName("fixes")]
    public List<Fix>? Fixes { get; set; }

    [JsonPropertyName("guid")]
    public string? Guid { get; set; }

    [JsonPropertyName("correlationGuid")]
    public string? CorrelationGuid { get; set; }

    [JsonPropertyName("hostedViewerUri")]
    public Uri? HostedViewerUri { get; set; }

    [JsonPropertyName("rank")]
    public double? Rank { get; set; }

    [JsonPropertyName("baselineState")]
    public string? BaselineState { get; set; }

    [JsonPropertyName("partialFingerprints")]
    public Dictionary<string, string>? PartialFingerprints { get; set; }

    [JsonPropertyName("fingerprints")]
    public Dictionary<string, string>? Fingerprints { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Where a result occurred, in source/binary terms.</summary>
public sealed class Location
{
    [JsonPropertyName("id")]
    public int? Id { get; set; }

    [JsonPropertyName("physicalLocation")]
    public PhysicalLocation? PhysicalLocation { get; set; }

    [JsonPropertyName("logicalLocations")]
    public List<LogicalLocation>? LogicalLocations { get; set; }

    [JsonPropertyName("message")]
    public Message? Message { get; set; }

    [JsonPropertyName("annotations")]
    public List<Region>? Annotations { get; set; }

    [JsonPropertyName("relationships")]
    public List<LocationRelationship>? Relationships { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A relationship between two locations (e.g. taint propagation).</summary>
public sealed class LocationRelationship
{
    [JsonPropertyName("target")]
    public int Target { get; set; }

    [JsonPropertyName("kinds")]
    public List<string>? Kinds { get; set; }

    [JsonPropertyName("description")]
    public Message? Description { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A logical (program-element) location: namespace, class, function, etc.</summary>
public sealed class LogicalLocation
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("fullyQualifiedName")]
    public string? FullyQualifiedName { get; set; }

    [JsonPropertyName("decoratedName")]
    public string? DecoratedName { get; set; }

    [JsonPropertyName("kind")]
    public string? Kind { get; set; }

    [JsonPropertyName("parentIndex")]
    public int? ParentIndex { get; set; }

    [JsonPropertyName("index")]
    public int? Index { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Physical (artifact + region) location.</summary>
public sealed class PhysicalLocation
{
    [JsonPropertyName("artifactLocation")]
    public ArtifactLocation? ArtifactLocation { get; set; }

    [JsonPropertyName("region")]
    public Region? Region { get; set; }

    [JsonPropertyName("contextRegion")]
    public Region? ContextRegion { get; set; }

    [JsonPropertyName("address")]
    public Address? Address { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A binary or in-memory address (rare in source-only analysis).</summary>
public sealed class Address
{
    [JsonPropertyName("absoluteAddress")]
    public long? AbsoluteAddress { get; set; }

    [JsonPropertyName("relativeAddress")]
    public long? RelativeAddress { get; set; }

    [JsonPropertyName("length")]
    public long? Length { get; set; }

    [JsonPropertyName("kind")]
    public string? Kind { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("fullyQualifiedName")]
    public string? FullyQualifiedName { get; set; }

    [JsonPropertyName("offsetFromParent")]
    public long? OffsetFromParent { get; set; }

    [JsonPropertyName("index")]
    public int? Index { get; set; }

    [JsonPropertyName("parentIndex")]
    public int? ParentIndex { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Reference to an artifact (file) — either inline URI or by index.</summary>
public sealed class ArtifactLocation
{
    [JsonPropertyName("uri")]
    public Uri? Uri { get; set; }

    [JsonPropertyName("uriBaseId")]
    public string? UriBaseId { get; set; }

    [JsonPropertyName("index")]
    public int? Index { get; set; }

    [JsonPropertyName("description")]
    public Message? Description { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A region within an artifact: line/column or character offsets.</summary>
public sealed class Region
{
    [JsonPropertyName("startLine")]
    public int? StartLine { get; set; }

    [JsonPropertyName("startColumn")]
    public int? StartColumn { get; set; }

    [JsonPropertyName("endLine")]
    public int? EndLine { get; set; }

    [JsonPropertyName("endColumn")]
    public int? EndColumn { get; set; }

    [JsonPropertyName("charOffset")]
    public int? CharOffset { get; set; }

    [JsonPropertyName("charLength")]
    public int? CharLength { get; set; }

    [JsonPropertyName("byteOffset")]
    public long? ByteOffset { get; set; }

    [JsonPropertyName("byteLength")]
    public long? ByteLength { get; set; }

    [JsonPropertyName("snippet")]
    public ArtifactContent? Snippet { get; set; }

    [JsonPropertyName("message")]
    public Message? Message { get; set; }

    [JsonPropertyName("sourceLanguage")]
    public string? SourceLanguage { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Artifact content: text, binary (base64), or rendered Markdown.</summary>
public sealed class ArtifactContent
{
    [JsonPropertyName("text")]
    public string? Text { get; set; }

    [JsonPropertyName("binary")]
    public string? Binary { get; set; }

    [JsonPropertyName("rendered")]
    public MultiformatMessageString? Rendered { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>An artifact (file) referenced by a run.</summary>
public sealed class Artifact
{
    [JsonPropertyName("location")]
    public ArtifactLocation? Location { get; set; }

    [JsonPropertyName("description")]
    public Message? Description { get; set; }

    [JsonPropertyName("contents")]
    public ArtifactContent? Contents { get; set; }

    [JsonPropertyName("encoding")]
    public string? Encoding { get; set; }

    [JsonPropertyName("mimeType")]
    public string? MimeType { get; set; }

    [JsonPropertyName("sourceLanguage")]
    public string? SourceLanguage { get; set; }

    [JsonPropertyName("length")]
    public long? Length { get; set; }

    [JsonPropertyName("hashes")]
    public Dictionary<string, string>? Hashes { get; set; }

    [JsonPropertyName("roles")]
    public List<string>? Roles { get; set; }

    [JsonPropertyName("parentIndex")]
    public int? ParentIndex { get; set; }

    [JsonPropertyName("offset")]
    public long? Offset { get; set; }

    [JsonPropertyName("lastModifiedTimeUtc")]
    public string? LastModifiedTimeUtc { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>One execution of the tool against the analysis target(s).</summary>
public sealed class Invocation
{
    [JsonPropertyName("commandLine")]
    public string? CommandLine { get; set; }

    [JsonPropertyName("arguments")]
    public List<string>? Arguments { get; set; }

    [JsonPropertyName("startTimeUtc")]
    public string? StartTimeUtc { get; set; }

    [JsonPropertyName("endTimeUtc")]
    public string? EndTimeUtc { get; set; }

    [JsonPropertyName("exitCode")]
    public int? ExitCode { get; set; }

    [JsonPropertyName("exitCodeDescription")]
    public string? ExitCodeDescription { get; set; }

    [JsonPropertyName("exitSignalName")]
    public string? ExitSignalName { get; set; }

    [JsonPropertyName("exitSignalNumber")]
    public int? ExitSignalNumber { get; set; }

    /// <summary>Required per spec but treated as optional for tolerant deserialisation.</summary>
    [JsonPropertyName("executionSuccessful")]
    public bool? ExecutionSuccessful { get; set; }

    [JsonPropertyName("machine")]
    public string? Machine { get; set; }

    [JsonPropertyName("account")]
    public string? Account { get; set; }

    [JsonPropertyName("processId")]
    public int? ProcessId { get; set; }

    [JsonPropertyName("workingDirectory")]
    public ArtifactLocation? WorkingDirectory { get; set; }

    [JsonPropertyName("environmentVariables")]
    public Dictionary<string, string>? EnvironmentVariables { get; set; }

    [JsonPropertyName("toolExecutionNotifications")]
    public List<Notification>? ToolExecutionNotifications { get; set; }

    [JsonPropertyName("toolConfigurationNotifications")]
    public List<Notification>? ToolConfigurationNotifications { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A tool-emitted notification (e.g. "scanned 12 files, 3 errors").</summary>
public sealed class Notification
{
    [JsonPropertyName("descriptor")]
    public ReportingDescriptorReference? Descriptor { get; set; }

    [JsonPropertyName("associatedRule")]
    public ReportingDescriptorReference? AssociatedRule { get; set; }

    [JsonPropertyName("level")]
    public FailureLevel? Level { get; set; }

    [JsonPropertyName("message")]
    public Message Message { get; set; } = new();

    [JsonPropertyName("locations")]
    public List<Location>? Locations { get; set; }

    [JsonPropertyName("threadId")]
    public int? ThreadId { get; set; }

    [JsonPropertyName("timeUtc")]
    public string? TimeUtc { get; set; }

    [JsonPropertyName("exception")]
    public ExceptionData? Exception { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Captured exception associated with a notification.</summary>
public sealed class ExceptionData
{
    [JsonPropertyName("kind")]
    public string? Kind { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("stack")]
    public Stack? Stack { get; set; }

    [JsonPropertyName("innerExceptions")]
    public List<ExceptionData>? InnerExceptions { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A call stack snapshot.</summary>
public sealed class Stack
{
    [JsonPropertyName("message")]
    public Message? Message { get; set; }

    [JsonPropertyName("frames")]
    public List<StackFrame>? Frames { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A single stack frame.</summary>
public sealed class StackFrame
{
    [JsonPropertyName("location")]
    public Location? Location { get; set; }

    [JsonPropertyName("module")]
    public string? Module { get; set; }

    [JsonPropertyName("threadId")]
    public int? ThreadId { get; set; }

    [JsonPropertyName("parameters")]
    public List<string>? Parameters { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Identifies an automation pipeline that produced this run.</summary>
public sealed class RunAutomationDetails
{
    [JsonPropertyName("description")]
    public Message? Description { get; set; }

    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("guid")]
    public string? Guid { get; set; }

    [JsonPropertyName("correlationGuid")]
    public string? CorrelationGuid { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>Source-control coordinates for a run (repo URL, branch, revision).</summary>
public sealed class VersionControlDetails
{
    [JsonPropertyName("repositoryUri")]
    public Uri? RepositoryUri { get; set; }

    [JsonPropertyName("revisionId")]
    public string? RevisionId { get; set; }

    [JsonPropertyName("branch")]
    public string? Branch { get; set; }

    [JsonPropertyName("revisionTag")]
    public string? RevisionTag { get; set; }

    [JsonPropertyName("asOfTimeUtc")]
    public string? AsOfTimeUtc { get; set; }

    [JsonPropertyName("mappedTo")]
    public ArtifactLocation? MappedTo { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>An ordered series of program execution traces (taint flow, call graph).</summary>
public sealed class CodeFlow
{
    [JsonPropertyName("message")]
    public Message? Message { get; set; }

    [JsonPropertyName("threadFlows")]
    public List<ThreadFlow>? ThreadFlows { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>One thread's portion of a code flow.</summary>
public sealed class ThreadFlow
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("message")]
    public Message? Message { get; set; }

    [JsonPropertyName("initialState")]
    public Dictionary<string, MultiformatMessageString>? InitialState { get; set; }

    [JsonPropertyName("immutableState")]
    public Dictionary<string, MultiformatMessageString>? ImmutableState { get; set; }

    [JsonPropertyName("locations")]
    public List<ThreadFlowLocation>? Locations { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A single step in a thread flow.</summary>
public sealed class ThreadFlowLocation
{
    [JsonPropertyName("index")]
    public int? Index { get; set; }

    [JsonPropertyName("location")]
    public Location? Location { get; set; }

    [JsonPropertyName("stack")]
    public Stack? Stack { get; set; }

    [JsonPropertyName("kinds")]
    public List<string>? Kinds { get; set; }

    [JsonPropertyName("taxa")]
    public List<ReportingDescriptorReference>? Taxa { get; set; }

    [JsonPropertyName("module")]
    public string? Module { get; set; }

    [JsonPropertyName("state")]
    public Dictionary<string, MultiformatMessageString>? State { get; set; }

    [JsonPropertyName("nestingLevel")]
    public int? NestingLevel { get; set; }

    [JsonPropertyName("executionOrder")]
    public int? ExecutionOrder { get; set; }

    [JsonPropertyName("executionTimeUtc")]
    public string? ExecutionTimeUtc { get; set; }

    [JsonPropertyName("importance")]
    public string? Importance { get; set; }

    [JsonPropertyName("webRequest")]
    public Dictionary<string, JsonElement>? WebRequest { get; set; }

    [JsonPropertyName("webResponse")]
    public Dictionary<string, JsonElement>? WebResponse { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A proposed remediation for a result.</summary>
public sealed class Fix
{
    [JsonPropertyName("description")]
    public Message? Description { get; set; }

    [JsonPropertyName("artifactChanges")]
    public List<ArtifactChange>? ArtifactChanges { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A set of edits to a single artifact.</summary>
public sealed class ArtifactChange
{
    [JsonPropertyName("artifactLocation")]
    public ArtifactLocation ArtifactLocation { get; set; } = new();

    [JsonPropertyName("replacements")]
    public List<Replacement>? Replacements { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>A single edit: delete a region, optionally insert content in its place.</summary>
public sealed class Replacement
{
    [JsonPropertyName("deletedRegion")]
    public Region DeletedRegion { get; set; } = new();

    [JsonPropertyName("insertedContent")]
    public ArtifactContent? InsertedContent { get; set; }

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement>? Properties { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; set; }
}

/// <summary>SARIF v2.1.0 §3.27.10 — lowercase enum values per spec.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<FailureLevel>))]
public enum FailureLevel
{
    [JsonStringEnumMemberName("none")] None,
    [JsonStringEnumMemberName("note")] Note,
    [JsonStringEnumMemberName("warning")] Warning,
    [JsonStringEnumMemberName("error")] Error,
}

/// <summary>SARIF v2.1.0 §3.27.9 — distinguishes failures from informational results.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ResultKind>))]
public enum ResultKind
{
    [JsonStringEnumMemberName("notApplicable")] NotApplicable,
    [JsonStringEnumMemberName("pass")] Pass,
    [JsonStringEnumMemberName("fail")] Fail,
    [JsonStringEnumMemberName("review")] Review,
    [JsonStringEnumMemberName("open")] Open,
    [JsonStringEnumMemberName("informational")] Informational,
}
