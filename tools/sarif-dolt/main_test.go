package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRequiresInitializedStoreBeforeAddResult(t *testing.T) {
	err := run(context.Background(), "add-result", []string{
		"--store", t.TempDir(),
		"--rule-id", "TST001",
		"--message", "finding",
	})

	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected uninitialized store error, got %v", err)
	}
}

func TestRunRejectsInvalidPropertyJSON(t *testing.T) {
	ctx := context.Background()
	store := t.TempDir()
	mustRun(t, ctx, "init", "--store", store, "--tool", "TestAnalyzer")

	err := run(ctx, "add-result", []string{
		"--store", store,
		"--rule-id", "TST001",
		"--message", "finding",
		"--property", "evidence:json={",
	})

	if err == nil || !strings.Contains(err.Error(), "--property evidence") {
		t.Fatalf("expected invalid property JSON error, got %v", err)
	}
}

func TestRunRoundTripsStoreThroughDoltDiffAndSarifExport(t *testing.T) {
	ctx := context.Background()
	store := t.TempDir()
	output := filepath.Join(t.TempDir(), "out.sarif")

	mustRun(t, ctx, "init",
		"--store", store,
		"--tool", "TestAnalyzer",
		"--tool-version", "1.2.3",
		"--semantic-version", "1.2.3",
		"--organization", "Example Org",
		"--info-uri", "https://example.test/analyzer",
		"--uri-base", "SRCROOT=file:///c:/repo/")
	mustRun(t, ctx, "add-result",
		"--store", store,
		"--rule-id", "TST001",
		"--rule-name", "TestRule",
		"--message", "first finding",
		"--level", "error",
		"--file", "src/First.cs",
		"--uri-base-id", "SRCROOT",
		"--start-line", "12",
		"--start-column", "3",
		"--snippet", "first();",
		"--tag", "security",
		"--property", "confidence=high")
	mustRun(t, ctx, "commit", "--store", store, "--message", "baseline")
	mustRun(t, ctx, "add-result",
		"--store", store,
		"--rule-id", "TST001",
		"--message", "second finding",
		"--file", "src/Second.cs",
		"--start-line", "20")

	diffOutput, err := captureStdout(func() error {
		return run(ctx, "diff", []string{"--store", store, "--from", "HEAD", "--to", "WORKING"})
	})
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if !strings.Contains(diffOutput, "results") {
		t.Fatalf("expected diff output to include results table change, got %q", diffOutput)
	}
	rowDiffOutput, err := captureStdout(func() error {
		return run(ctx, "diff", []string{"--store", store, "--from", "HEAD", "--to", "WORKING", "--format", "json"})
	})
	if err != nil {
		t.Fatalf("row diff failed: %v", err)
	}
	var rowDiffs []rowDiffRecord
	if err := json.Unmarshal([]byte(rowDiffOutput), &rowDiffs); err != nil {
		t.Fatalf("row diff JSON was invalid: %v\n%s", err, rowDiffOutput)
	}
	if !containsResultDiff(rowDiffs, "inserted", "TST001", "second finding") {
		t.Fatalf("expected inserted result diff for second finding, got %#v", rowDiffs)
	}

	mustRun(t, ctx, "export", "--store", store, "--output", output)

	bytes, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}

	var log sarifLog
	if err := json.Unmarshal(bytes, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("expected SARIF version 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected one run, got %d", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "TestAnalyzer" {
		t.Fatalf("expected tool name TestAnalyzer, got %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "1.2.3" {
		t.Fatalf("expected tool version 1.2.3, got %q", run.Tool.Driver.Version)
	}
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected two results, got %d", len(run.Results))
	}
	if run.Results[0].Message.Text == "" || run.Results[1].Message.Text == "" {
		t.Fatalf("expected exported result messages, got %#v", run.Results)
	}
	if _, ok := run.OriginalURIBaseIDs["SRCROOT"]; !ok {
		t.Fatalf("expected SRCROOT uri base, got %#v", run.OriginalURIBaseIDs)
	}
}

func TestRunAddResultsFromJSONL(t *testing.T) {
	ctx := context.Background()
	store := t.TempDir()
	output := filepath.Join(t.TempDir(), "batch.sarif")
	input := filepath.Join(t.TempDir(), "results.jsonl")

	writeFile(t, input, strings.Join([]string{
		`{"ruleId":"BAT001","ruleName":"BatchRule","message":"first batch finding","level":"warning","file":"src/One.cs","uriBaseId":"SRCROOT","startLine":1,"startColumn":2,"tags":["batch"],"properties":{"iteration":1,"enabled":true}}`,
		`{"ruleId":"BAT001","message":"second batch finding","file":"src/Two.cs","startLine":2,"properties":{"iteration":2}}`,
	}, "\n"))

	mustRun(t, ctx, "init", "--store", store, "--tool", "BatchAnalyzer", "--uri-base", "SRCROOT=file:///c:/repo/")
	outputText, err := captureStdout(func() error {
		return run(ctx, "add-results", []string{"--store", store, "--input", input})
	})
	if err != nil {
		t.Fatalf("add-results failed: %v", err)
	}
	if !strings.Contains(outputText, "Added 2 results") {
		t.Fatalf("expected add-results summary, got %q", outputText)
	}
	mustRun(t, ctx, "export", "--store", store, "--output", output)

	bytes, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(bytes, &log); err != nil {
		t.Fatal(err)
	}
	if got := len(log.Runs[0].Results); got != 2 {
		t.Fatalf("expected two batch results, got %d", got)
	}
	if got := len(log.Runs[0].Tool.Driver.Rules); got != 1 {
		t.Fatalf("expected one unique batch rule, got %d", got)
	}
	if log.Runs[0].Results[0].RuleIndex == nil || *log.Runs[0].Results[0].RuleIndex != 0 {
		t.Fatalf("expected rule index on exported batch result, got %#v", log.Runs[0].Results[0])
	}
}

func TestRunAddResultsRejectsInvalidJSONLLevel(t *testing.T) {
	ctx := context.Background()
	store := t.TempDir()
	input := filepath.Join(t.TempDir(), "bad-results.jsonl")
	writeFile(t, input, `{"ruleId":"BAD001","message":"bad finding","level":"critical"}`)

	mustRun(t, ctx, "init", "--store", store, "--tool", "BatchAnalyzer")
	err := run(ctx, "add-results", []string{"--store", store, "--input", input})
	if err == nil || !strings.Contains(err.Error(), "line 1") || !strings.Contains(err.Error(), "invalid level") {
		t.Fatalf("expected line-specific invalid level error, got %v", err)
	}
}

func TestEncodePropertiesPreservesTypedValues(t *testing.T) {
	encoded, err := encodeProperties(
		[]string{"confidence=high", "count=42", "flag=true", `evidence:json={"score":0.95}`},
		[]string{"security", "test"},
		"8.5",
		"CVSS:3.1/AV:N",
	)
	if err != nil {
		t.Fatal(err)
	}

	var props map[string]any
	if err := json.Unmarshal([]byte(encoded), &props); err != nil {
		t.Fatal(err)
	}

	if props["confidence"] != "high" {
		t.Fatalf("confidence was not preserved: %#v", props["confidence"])
	}
	if props["count"] != float64(42) {
		t.Fatalf("count was not numeric: %#v", props["count"])
	}
	if props["flag"] != true {
		t.Fatalf("flag was not boolean: %#v", props["flag"])
	}
	if props["security-severity"] != "8.5" {
		t.Fatalf("security-severity missing: %#v", props)
	}
}

func mustRun(t *testing.T, ctx context.Context, command string, args ...string) {
	t.Helper()
	if err := run(ctx, command, args); err != nil {
		t.Fatalf("%s failed: %v", command, err)
	}
}

func containsResultDiff(records []rowDiffRecord, changeType, ruleID, message string) bool {
	for _, record := range records {
		if record.Record == "result" &&
			record.ChangeType == changeType &&
			record.RuleID == ruleID &&
			record.MessageText == message {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func captureStdout(fn func() error) (string, error) {
	old := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		return "", err
	}

	os.Stdout = write
	err = fn()
	closeErr := write.Close()
	os.Stdout = old

	bytes, readErr := io.ReadAll(read)
	if err != nil {
		return string(bytes), err
	}
	if closeErr != nil {
		return string(bytes), closeErr
	}
	return string(bytes), readErr
}
