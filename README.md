# sarif-cli

A small, AOT-compiled .NET CLI for **constructing and inspecting** SARIF v2.1.0
(Static Analysis Results Interchange Format) log files. Built so AI assistants
and humans can build SARIF logs incrementally, without writing JSON by hand.

This is **not** a competitor to the official
[Sarif.Multitool](https://www.nuget.org/packages/Sarif.Multitool/) — for
schema validation, merging, conversion from other tools' formats, querying,
and rebasing URIs you should still install and use Multitool. `sarif-cli`
focuses on the *authoring* gap.

## Why?

Hand-building SARIF JSON is a meaningful drag on AI-assisted security tooling
(observed at roughly a third of agent time on some workflows). The official
SDK is .NET-Framework-era, depends on `Newtonsoft.Json`, and isn't AOT- or
trim-compatible. `sarif-cli` is a hand-rolled minimal POCO model serialised
through System.Text.Json source generators, so:

- ✅ AOT-publishable (`dotnet publish -c Release -r <rid>` produces a single
  ~5 MB native exe with zero AOT/trim warnings)
- ✅ Round-trips arbitrary SARIF logs without losing data — unknown fields
  are preserved through `JsonExtensionData` bags on every type
- ✅ Targets `net10.0`, central package management, xunit.v3 tests

## Install

Once a release is published:

```sh
dotnet tool install --global sarif-cli
```

To build from source:

```sh
git clone https://github.com/gholliday/sarif-cli
cd sarif-cli
dotnet build -c Release
dotnet test
```

To produce a self-contained AOT executable:

```sh
dotnet publish src/Sarif.Cli -c Release -r win-x64
# output: artifacts/publish/Sarif.Cli/release_win-x64/sarif-cli.exe
```

(swap `win-x64` for `linux-x64`, `osx-arm64`, etc.)

## Usage

```sh
# Scaffold a new SARIF log with tool driver metadata.
# --uri-base declares run.originalUriBaseIds so per-result --uri-base-id values resolve.
sarif-cli new results.sarif \
  --tool MyAnalyzer --tool-version 1.0.0 \
  --info-uri https://example.com/myanalyzer \
  --uri-base SRCROOT=file:///c:/repo/

# Define rules on the driver. --tag, --security-severity and --cvss are
# shortcuts for the GitHub code-scanning property conventions; --property
# is the escape hatch (repeatable; supports key=value and key:json=<raw>).
sarif-cli add rule results.sarif \
  --id MA0001 --name AvoidEmptyCatch \
  --short-description "Empty catch blocks hide errors." \
  --default-level warning \
  --help-uri https://example.com/rules/MA0001 \
  --tag security --tag injection \
  --security-severity 8.5 \
  --cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \
  --property "confidence=high" \
  --property "evidence:json={\"score\":0.92}"

# Record results against those rules. Use --rule-index when scripting from
# a counter; --uri-base-id references a key declared on `new --uri-base`.
sarif-cli add result results.sarif \
  --rule-index 0 \
  --message "Catch block on line 42 swallows all exceptions." \
  --uri-base-id SRCROOT \
  --file src/Foo.cs --start-line 42 --start-column 9 --end-line 44 --end-column 10 \
  --snippet "catch { }" \
  --property "fingerprint=abc123"

# Inspect (text by default; --format json|tsv pipes cleanly).
sarif-cli open results.sarif
sarif-cli list rules results.sarif --no-wrap
sarif-cli list results results.sarif --rule-id MA0001 --format tsv
sarif-cli validate results.sarif --strict   # exit 2 on authoring slips

# Combine logs (concat semantics — leave richer merging to Sarif.Multitool).
sarif-cli merge a.sarif b.sarif --output combined.sarif

# Bulk-author from a JSONL source-of-truth file (one rule/result per line):
#   {"kind":"rule","id":"R1","name":"Foo","defaultLevel":"error","tags":["sec"]}
#   {"kind":"result","ruleId":"R1","message":"...","file":"src/a.cs","startLine":10}
sarif-cli add bulk findings.jsonl results.sarif
```

`sarif-cli examples` prints the same recipe at any time.

## Commands

| Command                   | Purpose                                              |
|---------------------------|------------------------------------------------------|
| `new <file>`              | Create an empty SARIF log scaffold (`--uri-base NAME=PATH`, repeatable) |
| `open <file>`             | Show a one-screen summary of a log                   |
| `list rules <file>`       | List rules; `--format text\|json\|tsv`, `--no-wrap`  |
| `list results <file>`     | List results; `--rule-id <id>` filter, `--format`    |
| `add rule <file> ...`     | Add a rule; `--tag`, `--security-severity`, `--cvss`, `--property` |
| `add result <file> ...`   | Add a result; `--rule-id` or `--rule-index`, `--uri-base-id`, `--property` |
| `add bulk <jsonl> <file>` | Bulk-import rules/results from a JSON-Lines file (`--continue-on-error`) |
| `validate <file>`         | Smoke-test + warn on unresolved ruleIds / empty URIs (`--strict`) |
| `merge <inputs>... -o <f>`| Concatenate the runs from multiple SARIF files       |
| `examples`                | Print a worked end-to-end example                    |

## A note on coverage

The model covers the SARIF v2.1.0 surface area observed across a corpus of
real-world logs from common SAST tools. Concepts not yet modelled
explicitly (e.g. `conversion`, `graphs`, `taxonomies`)
still **survive round-trip** — they ride through the
`AdditionalProperties` extension bag on each type — but can't be authored
through dedicated CLI options. PRs welcome.

## License

MIT — see [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md).
