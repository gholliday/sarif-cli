# sarif-dolt

`sarif-dolt` is the optional embedded-Dolt storage helper used by `sarif-cli db ...`.
It keeps Dolt and its packaging constraints out of the .NET Native AOT frontend while
still allowing a versioned SARIF working store.

Build with Go 1.26.2+, CGO enabled, a C compiler, and Dolt's pure-Go SQL
engine tag:

```powershell
$env:CGO_ENABLED = "1"
go build -tags=gms_pure_go -o sarif-dolt.exe .
```

On Windows ARM64, this was validated with LLVM-MinGW:

```powershell
winget install --id MartinStorsjo.LLVM-MinGW.UCRT --exact
$env:CGO_ENABLED = "1"
$env:CC = "aarch64-w64-mingw32-gcc"
go build -tags=gms_pure_go -o sarif-dolt.exe .
```

Put the resulting binary next to `sarif-cli`, on `PATH`, or set `SARIF_DOLT_HELPER`.

The helper currently implements the MVP store operations:

```powershell
sarif-cli db init --store .sarif-dolt --tool ExampleAnalyzer
sarif-cli db add-result --store .sarif-dolt --rule-id EX001 --message "Example finding" --file src\Program.cs --start-line 10
sarif-cli db add-results --store .sarif-dolt --input results.jsonl
sarif-cli db commit --store .sarif-dolt --message "Add example finding"
sarif-cli db diff --store .sarif-dolt --from HEAD --to WORKING --format json
sarif-cli db export --store .sarif-dolt --output results.sarif
```

`add-results` expects JSONL with fields that mirror `add-result` options:

```json
{"ruleId":"EX001","ruleName":"ExampleRule","message":"Example finding","level":"warning","file":"src/Program.cs","startLine":10,"tags":["example"],"properties":{"iteration":1}}
```

`diff` defaults to the original table-level summary. Use `--format text`,
`--format json`, or `--format tsv` for row-level `rules` and `results` changes.
