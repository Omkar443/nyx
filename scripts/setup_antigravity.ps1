# setup_antigravity.ps1 - Complete Antigravity setup script for NYX Security Intelligence Engine
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$RepoDir = Split-Path -Parent $PSScriptRoot
$SkillsSource = Join-Path $RepoDir 'skills'

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Setting up NYX Security Intelligence Engine for Antigravity" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path -LiteralPath $SkillsSource)) {
    throw "Skills directory not found at $SkillsSource"
}

$skillDirs = Get-ChildItem -LiteralPath $SkillsSource -Directory
Write-Host "Found $($skillDirs.Count) skills in repository." -ForegroundColor Green
Write-Host ""

# Define target paths for Antigravity, Agents/Codex, NYX AI, and Workspace
$HomeDir = $HOME
$TargetPaths = @(
    @{ Path = (Join-Path $HomeDir ".gemini\config\skills"); Label = "Antigravity Global Skills (~/.gemini/config/skills)" },
    @{ Path = (Join-Path $HomeDir ".agents\skills"); Label = "Global Agent Skills (~/.agents/skills)" },
    @{ Path = (Join-Path $HomeDir ".claude\skills"); Label = "NYX AI Code Skills (~/.claude/skills)" },
    @{ Path = (Join-Path $RepoDir ".agents\skills"); Label = "Workspace Agent Skills (.agents/skills)" }
)

foreach ($target in $TargetPaths) {
    $dest = $target.Path
    $label = $target.Label
    Write-Host "Syncing skills to: $dest ($label)..." -ForegroundColor Yellow
    if (-not (Test-Path -LiteralPath $dest)) {
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
    }
    
    $installedCount = 0
    foreach ($sd in $skillDirs) {
        $skillName = $sd.Name
        $targetSkillDir = Join-Path $dest $skillName
        
        # Copy skill folder recursively
        Copy-Item -LiteralPath $sd.FullName -Destination $targetSkillDir -Recurse -Force
        $installedCount++
    }
    Write-Host "  + Successfully installed $installedCount skills into $label" -ForegroundColor Green
}

Write-Host ""
Write-Host "Running main install script (install.ps1 -All)..." -ForegroundColor Yellow
powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "install.ps1") -All -NoProfile

Write-Host ""
Write-Host "Verifying NYX CLI installation..." -ForegroundColor Yellow
try {
    $nyxOutput = python -m nyx_cli.cli catalog 2>&1
    Write-Host "  + NYX CLI functional!" -ForegroundColor Green
} catch {
    Write-Host "  ! NYX CLI test returned warning/error: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Antigravity Bug Hunter Setup Complete!" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
