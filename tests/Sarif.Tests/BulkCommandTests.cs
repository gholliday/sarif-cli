using System.Text.Json;
using Sarif.Cli.Commands;
using Sarif.Cli.Model;
using Xunit;

namespace Sarif.Tests;

public class BulkCommandTests
{
    static JsonElement Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    // ---------- BuildRule ----------

    [Fact]
    public void BuildRule_MinimalAddsRuleWithDefaultWarning()
    {
        var rules = new List<ReportingDescriptor>();
        var ok = BulkCommand.BuildRule(Parse("""{"id":"R1"}"""), rules, out var err);

        Assert.True(ok);
        Assert.Null(err);
        Assert.Single(rules);
        Assert.Equal("R1", rules[0].Id);
        Assert.Equal(FailureLevel.Warning, rules[0].DefaultConfiguration!.Level);
    }

    [Fact]
    public void BuildRule_FullPayloadPopulatesAllFields()
    {
        var rules = new List<ReportingDescriptor>();
        var ok = BulkCommand.BuildRule(Parse("""
            {"id":"R1","name":"X","shortDescription":"S","fullDescription":"F",
             "helpUri":"https://example.com/r1","helpText":"H","defaultLevel":"error",
             "tags":["sec","cwe-89"],"securitySeverity":"7.5","cvss":"CVSS:3.1/AV:N",
             "properties":{"confidence":"high","custom":42}}
            """), rules, out var err);

        Assert.True(ok);
        Assert.Null(err);
        var r = rules[0];
        Assert.Equal("X", r.Name);
        Assert.Equal("S", r.ShortDescription!.Text);
        Assert.Equal("F", r.FullDescription!.Text);
        Assert.Equal("H", r.Help!.Text);
        Assert.Equal("https://example.com/r1", r.HelpUri!.ToString());
        Assert.Equal(FailureLevel.Error, r.DefaultConfiguration!.Level);

        var props = r.Properties!;
        Assert.Equal("high", props["confidence"].GetString());
        Assert.Equal(42, props["custom"].GetInt32());
        Assert.Equal("7.5", props["security-severity"].GetString());
        Assert.Equal("CVSS:3.1/AV:N", props["cvssV3_1"].GetString());
        Assert.Equal(JsonValueKind.Array, props["tags"].ValueKind);
        Assert.Equal(2, props["tags"].GetArrayLength());
    }

    [Fact]
    public void BuildRule_RejectsMissingId()
    {
        var ok = BulkCommand.BuildRule(Parse("""{"name":"NoId"}"""), new List<ReportingDescriptor>(), out var err);
        Assert.False(ok);
        Assert.Contains("id", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildRule_RejectsDuplicateId()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" } };
        var ok = BulkCommand.BuildRule(Parse("""{"id":"R1"}"""), rules, out var err);
        Assert.False(ok);
        Assert.Contains("already exists", err);
    }

    [Fact]
    public void BuildRule_RejectsInvalidDefaultLevel()
    {
        var ok = BulkCommand.BuildRule(Parse("""{"id":"R1","defaultLevel":"oops"}"""), new List<ReportingDescriptor>(), out var err);
        Assert.False(ok);
        Assert.Contains("defaultLevel", err);
    }

    [Fact]
    public void BuildRule_RejectsRelativeHelpUri()
    {
        var ok = BulkCommand.BuildRule(Parse("""{"id":"R1","helpUri":"docs/r1"}"""), new List<ReportingDescriptor>(), out var err);
        Assert.False(ok);
        Assert.Contains("helpUri", err);
    }

    // ---------- BuildResult ----------

    [Fact]
    public void BuildResult_AutoResolvesRuleIndexFromRuleId()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" }, new() { Id = "R2" } };
        var results = new List<Result>();
        var ok = BulkCommand.BuildResult(Parse("""{"ruleId":"R2","message":"hi"}"""), rules, results, null, out var err);

        Assert.True(ok);
        Assert.Null(err);
        Assert.Equal(1, results[0].RuleIndex);
    }

    [Fact]
    public void BuildResult_AutoResolvesRuleIdFromRuleIndex()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" }, new() { Id = "R2" } };
        var results = new List<Result>();
        var ok = BulkCommand.BuildResult(Parse("""{"ruleIndex":1,"message":"hi"}"""), rules, results, null, out var err);

        Assert.True(ok);
        Assert.Null(err);
        Assert.Equal("R2", results[0].RuleId);
    }

    [Fact]
    public void BuildResult_RejectsMismatchedRuleIdAndIndex()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" } };
        var ok = BulkCommand.BuildResult(Parse("""{"ruleId":"R2","ruleIndex":0,"message":"hi"}"""), rules, new List<Result>(), null, out var err);
        Assert.False(ok);
        Assert.Contains("does not match", err);
    }

    [Fact]
    public void BuildResult_RejectsOutOfRangeRuleIndex()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" } };
        var ok = BulkCommand.BuildResult(Parse("""{"ruleIndex":5,"message":"hi"}"""), rules, new List<Result>(), null, out var err);
        Assert.False(ok);
        Assert.Contains("out of range", err);
    }

    [Fact]
    public void BuildResult_RejectsMissingMessage()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" } };
        var ok = BulkCommand.BuildResult(Parse("""{"ruleId":"R1"}"""), rules, new List<Result>(), null, out var err);
        Assert.False(ok);
        Assert.Contains("message", err);
    }

    [Fact]
    public void BuildResult_BuildsLocationWithRegionWhenLineGiven()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" } };
        var results = new List<Result>();
        var ok = BulkCommand.BuildResult(Parse("""
            {"ruleId":"R1","message":"hi","file":"src/x.cs","uriBaseId":"SRCROOT",
             "startLine":10,"startColumn":3,"endLine":12,"snippet":"if (x) {}"}
            """),
            rules, results,
            new Dictionary<string, ArtifactLocation> { ["SRCROOT"] = new() { Uri = new Uri("src/", UriKind.Relative) } },
            out var err);

        Assert.True(ok);
        Assert.Null(err);
        var loc = results[0].Locations![0].PhysicalLocation!;
        Assert.Equal("src/x.cs", loc.ArtifactLocation!.Uri!.ToString());
        Assert.Equal("SRCROOT", loc.ArtifactLocation!.UriBaseId);
        Assert.Equal(10, loc.Region!.StartLine);
        Assert.Equal(3, loc.Region!.StartColumn);
        Assert.Equal(12, loc.Region!.EndLine);
        Assert.Equal("if (x) {}", loc.Region!.Snippet!.Text);
    }

    [Fact]
    public void BuildResult_NoFileMeansNoLocations()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" } };
        var results = new List<Result>();
        var ok = BulkCommand.BuildResult(Parse("""{"ruleId":"R1","message":"hi"}"""), rules, results, null, out var err);
        Assert.True(ok);
        Assert.Null(results[0].Locations);
    }

    [Fact]
    public void BuildResult_HonorsExplicitLevel()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" } };
        var results = new List<Result>();
        var ok = BulkCommand.BuildResult(Parse("""{"ruleId":"R1","message":"hi","level":"error"}"""), rules, results, null, out var err);
        Assert.True(ok);
        Assert.Equal(FailureLevel.Error, results[0].Level);
    }

    [Fact]
    public void BuildResult_NullLevelLeftForCallerToInherit()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1", DefaultConfiguration = new() { Level = FailureLevel.Error } } };
        var results = new List<Result>();
        var ok = BulkCommand.BuildResult(Parse("""{"ruleId":"R1","message":"hi"}"""), rules, results, null, out var err);
        Assert.True(ok);
        // Null level on the result -> downstream code (list, GH code-scanning) inherits from rule.
        Assert.Null(results[0].Level);
    }

    [Fact]
    public void BuildResult_PropertiesBagMergesAllSources()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" } };
        var results = new List<Result>();
        var ok = BulkCommand.BuildResult(Parse("""
            {"ruleId":"R1","message":"hi","tags":["a","b"],"securitySeverity":"9.0",
             "cvss":"CVSS:3.1/X","properties":{"foo":"bar","n":1}}
            """), rules, results, null, out var err);

        Assert.True(ok);
        var props = results[0].Properties!;
        Assert.Equal("bar", props["foo"].GetString());
        Assert.Equal(1, props["n"].GetInt32());
        Assert.Equal(2, props["tags"].GetArrayLength());
        Assert.Equal("9.0", props["security-severity"].GetString());
        Assert.Equal("CVSS:3.1/X", props["cvssV3_1"].GetString());
    }

    [Fact]
    public void BuildResult_RejectsNonObjectProperties()
    {
        var rules = new List<ReportingDescriptor> { new() { Id = "R1" } };
        var ok = BulkCommand.BuildResult(Parse("""{"ruleId":"R1","message":"hi","properties":"oops"}"""), rules, new List<Result>(), null, out var err);
        Assert.False(ok);
        Assert.Contains("properties", err);
    }
}
