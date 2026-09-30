param(
    [ValidateSet('smoke','quick','full')][string]$Mode = 'smoke',
    [string]$Dataset,
    [switch]$DownloadEnron
)
$ErrorActionPreference = 'Stop'
$pythonExe = if ($env:PYTHON_BINARY) { $env:PYTHON_BINARY } else { 'python' }
$runArgs = @((Join-Path $PSScriptRoot 'reproduce.py'), '--mode', $Mode)
if ($Dataset) { $runArgs += @('--dataset', $Dataset) }
if ($DownloadEnron) { $runArgs += '--download-enron' }
& $pythonExe @runArgs
exit $LASTEXITCODE
