[CmdletBinding()]
param(
    [string]$SdkRoot,
    [string]$NdkVersion = '27.2.12479018',
    [string]$CmakeVersion = '3.22.1',
    [string]$AndroidPlatform = 'android-26',
    [string]$BridgeTarget = 'arm32_bridge',
    [string]$DynarmicSourceDirectory,
    [switch]$AllowNetwork,
    [switch]$BuildTests,
    [switch]$CollisionProbe,
    [switch]$EnableBridgeLogs,
    [switch]$TestForceExternalObb,
    [string]$BuildDirectory,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$Project = $PSScriptRoot
if ($BridgeTarget -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
    throw "invalid bridge target name: $BridgeTarget"
}
if (-not $SdkRoot) {
    $SdkRoot = if ($env:ANDROID_SDK_ROOT) {
        $env:ANDROID_SDK_ROOT
    }
    else {
        Join-Path $env:LOCALAPPDATA 'Android\Sdk'
    }
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $Project 'dist'
}

$Ndk = Join-Path $SdkRoot "ndk\$NdkVersion"
$CmakeRoot = Join-Path $SdkRoot "cmake\$CmakeVersion"
$Cmake = Join-Path $CmakeRoot 'bin\cmake.exe'
$Ninja = Join-Path $CmakeRoot 'bin\ninja.exe'
$Toolchain = Join-Path $Ndk 'build\cmake\android.toolchain.cmake'
$LlvmBin = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$Strip = Join-Path $LlvmBin 'llvm-strip.exe'
$Readelf = Join-Path $LlvmBin 'llvm-readelf.exe'
$Build = if ($BuildDirectory) { [IO.Path]::GetFullPath($BuildDirectory) } else { Join-Path $Project 'build_arm64' }
$BuiltLibrary = Join-Path $Build "lib$BridgeTarget.so"
$OutputLibrary = Join-Path $OutputDirectory "lib$BridgeTarget.so"

foreach ($Required in @($Cmake, $Ninja, $Toolchain, $Strip, $Readelf)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "missing build dependency: $Required"
    }
}

$CmakeArgs = @(
    '-S', $Project,
    '-B', $Build,
    '-G', 'Ninja',
    "-DCMAKE_MAKE_PROGRAM=$Ninja",
    "-DCMAKE_TOOLCHAIN_FILE=$Toolchain",
    "-DBRIDGE_TARGET=$BridgeTarget",
    '-DANDROID_ABI=arm64-v8a',
    "-DANDROID_PLATFORM=$AndroidPlatform",
    '-DANDROID_STL=c++_static',
    '-DCMAKE_BUILD_TYPE=Release',
    "-DBRIDGE_BUILD_TESTS=$($BuildTests.IsPresent.ToString().ToUpperInvariant())"
    "-DBRIDGE_ENABLE_LOGS=$($EnableBridgeLogs.IsPresent.ToString().ToUpperInvariant())"
    "-DBRIDGE_ENABLE_COLLISION_PROBE=$($CollisionProbe.IsPresent.ToString().ToUpperInvariant())"
    "-DBRIDGE_TEST_FORCE_EXTERNAL_OBB=$($TestForceExternalObb.IsPresent.ToString().ToUpperInvariant())"
)

if ($DynarmicSourceDirectory) {
    $DynarmicCmake = Join-Path $DynarmicSourceDirectory 'CMakeLists.txt'
    if (-not (Test-Path -LiteralPath $DynarmicCmake -PathType Leaf)) {
        throw "Dynarmic source is missing CMakeLists.txt: $DynarmicSourceDirectory"
    }
    $CmakeArgs += "-DFETCHCONTENT_SOURCE_DIR_DYNARMIC=$DynarmicSourceDirectory"
    $CmakeArgs += '-DFETCHCONTENT_FULLY_DISCONNECTED=ON'
}
elseif (Test-Path -LiteralPath (Join-Path $Project 'third_party\dynarmic\CMakeLists.txt') -PathType Leaf) {
    $BundledDynarmic = Join-Path $Project 'third_party\dynarmic'
    $CmakeArgs += "-DFETCHCONTENT_SOURCE_DIR_DYNARMIC=$BundledDynarmic"
    $CmakeArgs += '-DFETCHCONTENT_FULLY_DISCONNECTED=ON'
}
elseif (Test-Path -LiteralPath (Join-Path $Build '_deps\dynarmic-src\CMakeLists.txt') -PathType Leaf) {
    $CmakeArgs += '-DFETCHCONTENT_FULLY_DISCONNECTED=ON'
}
elseif (-not $AllowNetwork) {
    throw 'Dynarmic is not cached. Pass -DynarmicSourceDirectory <path> or explicitly approve the first fetch with -AllowNetwork.'
}

New-Item -ItemType Directory -Path $Build -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

& $Cmake @CmakeArgs
if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed: $LASTEXITCODE"
}

& $Cmake --build $Build --config Release --parallel
if ($LASTEXITCODE -ne 0) {
    throw "ARM64 bridge build failed: $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $BuiltLibrary -PathType Leaf)) {
    throw "bridge output is missing: $BuiltLibrary"
}

Copy-Item -LiteralPath $BuiltLibrary -Destination $OutputLibrary -Force
& $Strip --strip-unneeded $OutputLibrary
if ($LASTEXITCODE -ne 0) {
    throw "llvm-strip failed: $LASTEXITCODE"
}

$Header = (& $Readelf -h $OutputLibrary) -join "`n"
if ($Header -notmatch 'Class:\s+ELF64' -or $Header -notmatch 'Machine:\s+AArch64') {
    throw 'bridge is not ELF64 AArch64'
}
$Loads = & $Readelf -lW $OutputLibrary | Select-String '^\s*LOAD\s'
if (-not $Loads) {
    throw 'bridge has no PT_LOAD segments'
}
foreach ($Load in $Loads) {
    if ($Load.Line -notmatch '\s(0x[0-9a-fA-F]+)\s*$') {
        throw "unable to parse PT_LOAD alignment: $($Load.Line)"
    }
    $Alignment = [Convert]::ToUInt64($Matches[1].Substring(2), 16)
    if ($Alignment -lt 0x4000) {
        throw "PT_LOAD alignment below 16 KiB: $($Load.Line)"
    }
}

Get-Item -LiteralPath $OutputLibrary | Select-Object FullName, Length, LastWriteTime
Get-FileHash -Algorithm SHA256 -LiteralPath $OutputLibrary
