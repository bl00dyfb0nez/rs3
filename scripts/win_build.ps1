#Requires -Version 5.1
param(
    [int]$Cores = 0
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Clear-Host throws when the script's output is redirected to a file, and with
# ErrorActionPreference = Stop that would end the run before it starts.
try { Clear-Host } catch { }

function Print-Elapsed {
    param([datetime]$Start)

    $Elapsed = (Get-Date) - $Start

    Write-Host ''
    Write-Host ('Total build time: {0}h {1}m {2}s' -f
        [int]$Elapsed.TotalHours,
        $Elapsed.Minutes,
        $Elapsed.Seconds)
}

$StartTime = Get-Date

# ============================================================
# Visual Studio Detection
# ============================================================
$VsVarsPath = $null

$UninstallKeys = @(
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

:vsSearch foreach ($BaseKey in $UninstallKeys) {
    foreach ($SubKey in (Get-ChildItem $BaseKey -ErrorAction SilentlyContinue)) {
        $DisplayName = $SubKey.GetValue('DisplayName', '')
        if ($DisplayName -like '*Visual Studio*') {
            $InstallLocation = $SubKey.GetValue('InstallLocation', '')
            if ($InstallLocation) {
                $Candidate = Join-Path $InstallLocation 'VC\Auxiliary\Build\vcvars64.bat'
                if (Test-Path $Candidate) {
                    $VsVarsPath = $Candidate
                    break vsSearch
                }
            }
        }
    }
}

if (-not $VsVarsPath) {
    # Write-Host, not Write-Error: ErrorActionPreference is Stop, so Write-Error
    # would terminate before the message below is ever shown.
    Write-Host 'ERROR: Visual Studio with the C++ workload was not found.'
    Write-Host 'Install Visual Studio (Desktop development with C++) and try again.'
    Read-Host 'Press Enter to exit'
    exit 1
}

Write-Host "Using VS environment: $VsVarsPath"

# vcvars64.bat calls vswhere by name, so its folder has to be on PATH before the
# batch file runs; otherwise every build starts with a "vswhere.exe is not
# recognized" line that has nothing to do with the build.
$VsWhereDir = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer'
if (Test-Path (Join-Path $VsWhereDir 'vswhere.exe')) {
    $env:PATH = "$VsWhereDir;$env:PATH"
}

# Import VS environment variables by running vcvars64.bat and capturing the env
$TempFile = [System.IO.Path]::GetTempFileName() + '.bat'
@"
@echo off
call "$VsVarsPath"
set
"@ | Set-Content $TempFile -Encoding ASCII

cmd /c $TempFile | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}
Remove-Item $TempFile -Force

# ============================================================
# CMake / Ninja Detection
# Neither tool is on PATH on a stock Windows install. The Qt
# installer ships both, so fall back to its Tools folder (and the
# usual standalone CMake location) before giving up.
# ============================================================
function Resolve-Tool {
    param([string]$Name, [string[]]$Candidates)

    $Existing = Get-Command $Name -ErrorAction SilentlyContinue
    if ($Existing) {
        return $Existing.Source
    }

    foreach ($Candidate in $Candidates) {
        if (Test-Path $Candidate) {
            return $Candidate
        }
    }

    return $null
}

$CMakePath = Resolve-Tool 'cmake' @(
    'C:\Qt\Tools\CMake_64\bin\cmake.exe',
    'C:\Qt\Tools\CMake_32\bin\cmake.exe',
    'C:\Program Files\CMake\bin\cmake.exe'
)

$NinjaPath = Resolve-Tool 'ninja' @(
    'C:\Qt\Tools\Ninja\ninja.exe'
)

if (-not $CMakePath -or -not $NinjaPath) {
    Write-Host 'ERROR: CMake and Ninja are required to build RPCS3.'
    if (-not $CMakePath) { Write-Host 'CMake was not found.' }
    if (-not $NinjaPath) { Write-Host 'Ninja was not found.' }
    Write-Host 'Install CMake and Ninja (the Qt installer ships both under C:\Qt\Tools).'
    Read-Host 'Press Enter to exit'
    exit 1
}

$env:PATH = "$(Split-Path $CMakePath);$(Split-Path $NinjaPath);$env:PATH"
Write-Host "Using CMake: $CMakePath"
Write-Host "Using Ninja: $NinjaPath"

# ============================================================
# Qt Detection
# ============================================================
$QtRoot = $null

if ($env:Qt6_ROOT -and (Test-Path (Join-Path $env:Qt6_ROOT 'lib\cmake\Qt6\Qt6Config.cmake'))) {
    $QtRoot = $env:Qt6_ROOT
    Write-Host "Found Qt6 from environment variable: $env:Qt6_ROOT"
}

if (-not $QtRoot) {
    # A kit is only usable when its Qt6Config.cmake is present: a Qt installer
    # that only laid down one component leaves a kit directory behind without
    # it, and picking that one fails at configure time with a message that says
    # nothing about the real cause.  Every kit is checked and the ones skipped
    # are named, so a half-installed Qt is visible here rather than later.
    $Kits = @()

    foreach ($Drive in 'C','D','E','F','G','H') {
        $QtBase = "${Drive}:\Qt"
        if (-not (Test-Path $QtBase)) { continue }

        foreach ($VersionDir in (Get-ChildItem $QtBase -Directory -Filter '6.*' -ErrorAction SilentlyContinue)) {
            foreach ($KitDir in (Get-ChildItem $VersionDir.FullName -Directory -ErrorAction SilentlyContinue)) {
                $Config = Join-Path $KitDir.FullName 'lib\cmake\Qt6\Qt6Config.cmake'

                $Kits += [pscustomobject]@{
                    Path   = $KitDir.FullName
                    Name   = $KitDir.Name
                    Usable = Test-Path $Config
                }
            }
        }
    }

    foreach ($Kit in $Kits) {
        if (-not $Kit.Usable) {
            Write-Host "Skipping incomplete Qt kit: $($Kit.Path)"
        }
    }

    # The MSVC kit is the one RPCS3 builds against on Windows; a MinGW or clang
    # kit is only reported so the error below can name it.
    $MsvcKit = $Kits | Where-Object { $_.Usable -and $_.Name -like 'msvc*' } | Select-Object -First 1

    if ($MsvcKit) {
        $QtRoot = $MsvcKit.Path
    }

    if (-not $QtRoot) {
        $MinGwKit = $Kits | Where-Object { $_.Usable -and $_.Name -like 'mingw*' } | Select-Object -First 1

        if ($MinGwKit) {
            Write-Host "Only a MinGW Qt kit is complete here: $($MinGwKit.Path)"
        }
    }

    if ($QtRoot) {
        Write-Host "Found Qt6 at: $QtRoot"
    }
}

if (-not $QtRoot) {
    Write-Host @'
ERROR: No complete Qt6 MSVC kit was found.
RPCS3 builds against the msvc2022_64 kit; the message above names any kit that
is present but incomplete. Install the full Qt 6 MSVC 2022 64-bit kit, or set
Qt6_ROOT to one:
Example: [System.Environment]::SetEnvironmentVariable('Qt6_ROOT','C:\Qt\<version>\msvc2022_64','User')
'@
    Read-Host 'Press Enter to exit'
    exit 1
}

# ============================================================
# Vulkan SDK Detection
# CMake's FindVulkan only reads the VULKAN_SDK environment
# variable. A shell started before the SDK install never has it,
# and the build then quietly drops the Vulkan renderer. Read the
# value the installer registered, then fall back to the kits on
# disk (newest first).
# ============================================================
if (-not $env:VULKAN_SDK) {
    foreach ($Scope in 'Machine', 'User') {
        $Registered = [System.Environment]::GetEnvironmentVariable('VULKAN_SDK', $Scope)
        if ($Registered -and (Test-Path (Join-Path $Registered 'Include\vulkan\vulkan.h'))) {
            $env:VULKAN_SDK = $Registered
            break
        }
    }
}

if (-not $env:VULKAN_SDK) {
    $SdkDirs = Get-ChildItem 'C:\VulkanSDK' -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'Include\vulkan\vulkan.h') } |
        Sort-Object Name -Descending

    if ($SdkDirs) {
        $env:VULKAN_SDK = $SdkDirs[0].FullName
    }
}

if ($env:VULKAN_SDK) {
    Write-Host "Found Vulkan SDK at: $env:VULKAN_SDK"
} else {
    Write-Host 'WARNING: No Vulkan SDK found (VULKAN_SDK unset, nothing under C:\VulkanSDK).'
    Write-Host '         RPCS3 will be compiled without Vulkan support and only offer OpenGL.'
}

# ============================================================
# Build Configuration
# ============================================================
if ($Cores -le 0) {
    $Cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
}

$SourceDir = Split-Path -Parent $PSScriptRoot
$BuildDir  = Join-Path $SourceDir 'build'

# ============================================================
# Selective Clean (SDL3 export conflict fix)
# Only wipe SDL3 folder to avoid the export() CMake 4.x conflict
# while preserving all other compiled objects (LLVM, ffmpeg, etc.)
# ============================================================
$SdlDir = Join-Path $BuildDir '3rdparty\libsdl-org'
if (Test-Path $SdlDir) {
    Write-Host ''
    Write-Host 'Cleaning SDL3 build cache to prevent export conflicts...'
    Remove-Item $SdlDir -Recurse -Force
    Write-Host 'SDL3 clean done.'
}

if (-not (Test-Path $BuildDir)) {
    New-Item $BuildDir -ItemType Directory | Out-Null
}

# ============================================================
# CMake Configure
# Always runs: it is idempotent and takes seconds, and it is the
# only way a changed environment (a new Qt kit, a freshly
# installed Vulkan SDK) reaches the cache. Skipping it while
# CMakeCache.txt exists is how this build ended up with
# USE_VULKAN=ON but "libvulkan was not found".
# ============================================================
Write-Host ''
Write-Host "Configuring CMake with $Cores cores..."
Write-Host "Qt6 Root: $QtRoot"
Write-Host ''

& cmake $SourceDir -G 'Ninja Multi-Config' `
    -DBUILD_LLVM=ON `
    -DUSE_SYSTEM_CURL=OFF `
    -DUSE_SYSTEM_ZLIB=OFF `
    -DUSE_SYSTEM_LIBPNG=OFF `
    -DUSE_SYSTEM_SDL=OFF `
    -DUSE_VULKAN=ON `
    "-DQt6_ROOT=$QtRoot" `
    "-DCMAKE_PREFIX_PATH=$QtRoot" `
    -B $BuildDir

if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Host 'ERROR: CMake configuration failed!'
    Print-Elapsed $StartTime
    Read-Host 'Press Enter to exit'
    exit 1
}

# ============================================================
# Build
# Ninja will only recompile files that have actually changed.
# ============================================================
Write-Host ''
Write-Host "Building with $Cores cores..."

& cmake --build $BuildDir --config Release --parallel $Cores

if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Host 'ERROR: Build failed!'
    Print-Elapsed $StartTime
    Read-Host 'Press Enter to exit'
    exit 1
}

Write-Host ''
Write-Host "Build complete! Output is in `"$BuildDir\bin\`""
Print-Elapsed $StartTime
Read-Host 'Press Enter to exit'
exit 0
