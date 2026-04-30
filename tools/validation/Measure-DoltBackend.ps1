param(
    [int]$Count = 100,
    [string]$SarifCliPath,
    [string]$HelperPath,
    [string]$Workspace,
    [switch]$KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
if (-not $Workspace) {
    $Workspace = Join-Path ([System.IO.Path]::GetTempPath()) ('sarif-dolt-validation-' + [Guid]::NewGuid().ToString('N'))
}
New-Item -ItemType Directory -Force -Path $Workspace | Out-Null

if (-not $SarifCliPath) {
    $SarifCliPath = Join-Path $repoRoot 'artifacts\bin\Sarif.Cli\release\sarif-cli.dll'
    if (-not (Test-Path $SarifCliPath)) {
        & dotnet build -c Release $repoRoot | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed.' }
    }
}

if (-not $HelperPath) {
    $HelperPath = Join-Path $repoRoot 'tools\sarif-dolt\sarif-dolt.exe'
    if (-not (Test-Path $HelperPath)) {
        Push-Location (Join-Path $repoRoot 'tools\sarif-dolt')
        try {
            $env:CGO_ENABLED = '1'
            & go build -tags=gms_pure_go -o sarif-dolt.exe .
            if ($LASTEXITCODE -ne 0) { throw 'go build failed.' }
        }
        finally {
            Pop-Location
        }
    }
}

function Invoke-SarifCli {
    param([string[]]$Arguments)

    if ($SarifCliPath.EndsWith('.dll', [StringComparison]::OrdinalIgnoreCase)) {
        & dotnet $SarifCliPath @Arguments | Out-Null
    }
    else {
        & $SarifCliPath @Arguments | Out-Null
    }
    if ($LASTEXITCODE -ne 0) {
        throw "sarif-cli $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Get-DirectorySize {
    param([string]$Path)

    if (-not (Test-Path $Path)) { return 0 }
    $sum = Get-ChildItem $Path -Recurse -File | Measure-Object -Property Length -Sum
    if ($null -eq $sum.Sum) { return 0 }
    return [int64]$sum.Sum
}

try {
    $fileSarif = Join-Path $Workspace 'file-results.sarif'
    $doltStore = Join-Path $Workspace 'dolt-store'
    $doltSarif = Join-Path $Workspace 'dolt-results.sarif'
    $doltBatchStore = Join-Path $Workspace 'dolt-batch-store'
    $doltBatchSarif = Join-Path $Workspace 'dolt-batch-results.sarif'
    $doltBatchInput = Join-Path $Workspace 'dolt-batch-results.jsonl'

    Invoke-SarifCli @('new', $fileSarif, '--tool', 'BenchAnalyzer', '--uri-base', 'SRCROOT=file:///c:/repo/', '--force')
    Invoke-SarifCli @('add', 'rule', $fileSarif, '--id', 'BENCH001', '--name', 'BenchmarkRule', '--default-level', 'warning')

    $fileWatch = [System.Diagnostics.Stopwatch]::StartNew()
    for ($i = 1; $i -le $Count; $i++) {
        Invoke-SarifCli @(
            'add', 'result', $fileSarif,
            '--rule-id', 'BENCH001',
            '--message', "Benchmark finding $i",
            '--file', "src/File$i.cs",
            '--uri-base-id', 'SRCROOT',
            '--start-line', "$i",
            '--property', "iteration=$i"
        )
    }
    $fileWatch.Stop()
    Invoke-SarifCli @('validate', $fileSarif, '--strict')

    Invoke-SarifCli @('db', 'init', '--helper', $HelperPath, '--store', $doltStore, '--tool', 'BenchAnalyzer', '--uri-base', 'SRCROOT=file:///c:/repo/')

    $doltWatch = [System.Diagnostics.Stopwatch]::StartNew()
    for ($i = 1; $i -le $Count; $i++) {
        Invoke-SarifCli @(
            'db', 'add-result',
            '--helper', $HelperPath,
            '--store', $doltStore,
            '--rule-id', 'BENCH001',
            '--rule-name', 'BenchmarkRule',
            '--message', "Benchmark finding $i",
            '--file', "src/File$i.cs",
            '--uri-base-id', 'SRCROOT',
            '--start-line', "$i",
            '--property', "iteration=$i"
        )
    }
    $doltWatch.Stop()
    Invoke-SarifCli @('db', 'export', '--helper', $HelperPath, '--store', $doltStore, '--output', $doltSarif)
    Invoke-SarifCli @('validate', $doltSarif, '--strict')

    $jsonl = for ($i = 1; $i -le $Count; $i++) {
        [pscustomobject]@{
            ruleId = 'BENCH001'
            ruleName = 'BenchmarkRule'
            message = "Benchmark finding $i"
            file = "src/File$i.cs"
            uriBaseId = 'SRCROOT'
            startLine = $i
            properties = [ordered]@{
                iteration = $i
            }
        } | ConvertTo-Json -Compress
    }
    Set-Content -Path $doltBatchInput -Value $jsonl -Encoding UTF8

    Invoke-SarifCli @('db', 'init', '--helper', $HelperPath, '--store', $doltBatchStore, '--tool', 'BenchAnalyzer', '--uri-base', 'SRCROOT=file:///c:/repo/')
    $doltBatchWatch = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-SarifCli @('db', 'add-results', '--helper', $HelperPath, '--store', $doltBatchStore, '--input', $doltBatchInput)
    $doltBatchWatch.Stop()
    Invoke-SarifCli @('db', 'export', '--helper', $HelperPath, '--store', $doltBatchStore, '--output', $doltBatchSarif)
    Invoke-SarifCli @('validate', $doltBatchSarif, '--strict')

    $fileLog = Get-Content $fileSarif -Raw | ConvertFrom-Json
    $doltLog = Get-Content $doltSarif -Raw | ConvertFrom-Json
    $doltBatchLog = Get-Content $doltBatchSarif -Raw | ConvertFrom-Json
    $fileResults = @($fileLog.runs[0].results).Count
    $doltResults = @($doltLog.runs[0].results).Count
    $doltBatchResults = @($doltBatchLog.runs[0].results).Count

    if ($fileResults -ne $Count) { throw "File backend produced $fileResults result(s), expected $Count." }
    if ($doltResults -ne $Count) { throw "Dolt backend produced $doltResults result(s), expected $Count." }
    if ($doltBatchResults -ne $Count) { throw "Dolt batch backend produced $doltBatchResults result(s), expected $Count." }

    [pscustomobject]@{
        count = $Count
        fileAddSeconds = [Math]::Round($fileWatch.Elapsed.TotalSeconds, 3)
        doltAddSeconds = [Math]::Round($doltWatch.Elapsed.TotalSeconds, 3)
        doltBatchAddSeconds = [Math]::Round($doltBatchWatch.Elapsed.TotalSeconds, 3)
        fileSarifBytes = (Get-Item $fileSarif).Length
        doltExportSarifBytes = (Get-Item $doltSarif).Length
        doltBatchExportSarifBytes = (Get-Item $doltBatchSarif).Length
        doltStoreBytes = Get-DirectorySize $doltStore
        doltBatchStoreBytes = Get-DirectorySize $doltBatchStore
        fileResults = $fileResults
        doltResults = $doltResults
        doltBatchResults = $doltBatchResults
        workspace = $Workspace
    } | ConvertTo-Json
}
finally {
    if (-not $KeepArtifacts -and (Test-Path $Workspace)) {
        Remove-Item $Workspace -Recurse -Force
    }
}
