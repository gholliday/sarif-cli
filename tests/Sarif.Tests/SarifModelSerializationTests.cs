using Sarif.Cli;
using Sarif.Cli.Model;
using Xunit;

namespace Sarif.Tests;

public class SarifModelSerializationTests
{
    [Fact]
    public void SaveAndLoad_PreservesExtendedResultFields()
    {
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
                            Name = "test-tool"
                        }
                    },
                    Results = new List<Result>
                    {
                        new()
                        {
                            RuleId = "R1",
                            Kind = ResultKind.Fail,
                            Level = FailureLevel.Warning,
                            Message = new Message
                            {
                                Text = "result message"
                            },
                            Suppressions = new List<Suppression>
                            {
                                new()
                                {
                                    Guid = "suppression-1",
                                    Status = "accepted",
                                    Justification = "baseline suppression",
                                    Location = new Location
                                    {
                                        PhysicalLocation = new PhysicalLocation
                                        {
                                            ArtifactLocation = new ArtifactLocation
                                            {
                                                Uri = new Uri("src/file.cs", UriKind.Relative)
                                            },
                                            Region = new Region
                                            {
                                                StartLine = 7
                                            }
                                        }
                                    }
                                }
                            },
                            WebRequest = new WebRequest
                            {
                                Method = "GET",
                                Target = "https://example.test/api",
                                Headers = new Dictionary<string, string>
                                {
                                    ["Accept"] = "application/json"
                                },
                                Parameters = new Dictionary<string, string>
                                {
                                    ["q"] = "sample"
                                },
                                Body = new ArtifactContent
                                {
                                    Text = "request body"
                                }
                            },
                            WebResponse = new WebResponse
                            {
                                StatusCode = 200,
                                ReasonPhrase = "OK",
                                Headers = new Dictionary<string, string>
                                {
                                    ["Content-Type"] = "application/json"
                                },
                                Body = new ArtifactContent
                                {
                                    Text = "{\"ok\":true}"
                                }
                            },
                            Attachments = new List<Attachment>
                            {
                                new()
                                {
                                    Description = new Message
                                    {
                                        Text = "evidence"
                                    },
                                    ArtifactLocation = new ArtifactLocation
                                    {
                                        Uri = new Uri("artifacts/evidence.txt", UriKind.Relative)
                                    },
                                    Regions = new List<Region>
                                    {
                                        new()
                                        {
                                            StartLine = 1,
                                            EndLine = 2
                                        }
                                    }
                                }
                            },
                            WorkItemUris = new List<Uri>
                            {
                                new("https://example.test/workitems/123")
                            },
                            CodeFlows = new List<CodeFlow>
                            {
                                new()
                                {
                                    ThreadFlows = new List<ThreadFlow>
                                    {
                                        new()
                                        {
                                            Locations = new List<ThreadFlowLocation>
                                            {
                                                new()
                                                {
                                                    ExecutionOrder = 1,
                                                    Location = new Location
                                                    {
                                                        PhysicalLocation = new PhysicalLocation
                                                        {
                                                            ArtifactLocation = new ArtifactLocation
                                                            {
                                                                Uri = new Uri("src/file.cs", UriKind.Relative)
                                                            }
                                                        }
                                                    },
                                                    WebRequest = new WebRequest
                                                    {
                                                        Method = "POST",
                                                        Target = "https://example.test/step"
                                                    },
                                                    WebResponse = new WebResponse
                                                    {
                                                        StatusCode = 201,
                                                        ReasonPhrase = "Created"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        var path = Path.Combine(Path.GetTempPath(), $"sarif-model-{Guid.NewGuid():N}.sarif");

        try
        {
            SarifFile.Save(log, path);
            var roundTripped = SarifFile.Load(path);

            var run = Assert.Single(roundTripped.Runs);
            var result = Assert.Single(run.Results!);

            Assert.Equal(ResultKind.Fail, result.Kind);
            Assert.Equal(FailureLevel.Warning, result.Level);

            var suppression = Assert.Single(result.Suppressions!);
            Assert.Equal("accepted", suppression.Status);
            Assert.Equal("baseline suppression", suppression.Justification);
            Assert.Equal("src/file.cs", suppression.Location!.PhysicalLocation!.ArtifactLocation!.Uri!.ToString());

            Assert.Equal("GET", result.WebRequest!.Method);
            Assert.Equal("application/json", result.WebRequest.Headers!["Accept"]);
            Assert.Equal("sample", result.WebRequest.Parameters!["q"]);
            Assert.Equal("request body", result.WebRequest.Body!.Text);

            Assert.Equal(200, result.WebResponse!.StatusCode);
            Assert.Equal("OK", result.WebResponse.ReasonPhrase);
            Assert.Equal("application/json", result.WebResponse.Headers!["Content-Type"]);
            Assert.Equal("{\"ok\":true}", result.WebResponse.Body!.Text);

            var attachment = Assert.Single(result.Attachments!);
            Assert.Equal("evidence", attachment.Description!.Text);
            Assert.Equal("artifacts/evidence.txt", attachment.ArtifactLocation.Uri!.ToString());
            Assert.Equal(2, Assert.Single(attachment.Regions!).EndLine);

            Assert.Equal("https://example.test/workitems/123", Assert.Single(result.WorkItemUris!).ToString());

            var codeFlow = Assert.Single(result.CodeFlows!);
            var threadFlow = Assert.Single(codeFlow.ThreadFlows!);
            var threadLocation = Assert.Single(threadFlow.Locations!);

            Assert.Equal("POST", threadLocation.WebRequest!.Method);
            Assert.Equal("https://example.test/step", threadLocation.WebRequest.Target);
            Assert.Equal(201, threadLocation.WebResponse!.StatusCode);
            Assert.Equal("Created", threadLocation.WebResponse.ReasonPhrase);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
