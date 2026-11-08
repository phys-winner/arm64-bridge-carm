[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.:-]+$')][string]$Serial,
    [string]$BuildDirectory,
    [string]$SdkRoot = "$env:LOCALAPPDATA/Android/Sdk"
)
$ErrorActionPreference = 'Stop'
$Bridge = Split-Path $PSScriptRoot -Parent
$GameRoot = Split-Path $Bridge -Parent
$Game = Split-Path $GameRoot -Leaf
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $Bridge 'build_arm64' }
$Binary = Join-Path $BuildDirectory 'bridge_regression'
if (-not (Test-Path -LiteralPath $Binary)) { throw 'Build the native bridge with -BuildTests first.' }
$Adb = Join-Path $SdkRoot 'platform-tools/adb.exe'
$Remote = "/data/local/tmp/$Game-bridge-regression"
$Log = Join-Path (Split-Path $BuildDirectory -Parent) "regression_$Serial.log"
Set-Content -LiteralPath $Log -Value "Component regression: $Game on $Serial"
function Invoke-Adb {
    param([string[]]$NativeArgs)
    & $Adb -s $Serial @NativeArgs 2>&1 | Tee-Object -FilePath $Log -Append
    if ($LASTEXITCODE -ne 0) { throw "adb/test failed ($LASTEXITCODE): $NativeArgs" }
}
Invoke-Adb @('push', $Binary, $Remote)
Invoke-Adb @('shell', 'chmod', '755', $Remote)
# Bound a broken condition/atomic implementation; no game package is launched.
Invoke-Adb @('shell', 'timeout', '90', $Remote)
Write-Output "Test log: $Log"
