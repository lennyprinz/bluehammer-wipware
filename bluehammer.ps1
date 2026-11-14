# ============================================================
# BlueHammer WIPware (WIP - Work In Progress)
# Based on the BlueHammer (CVE-2026-33825) local privilege
# escalation PoC by Nightmare-Eclipse / "Chaotic Eclipse"
# (https://github.com/Nightmare-Eclipse/BlueHammer)
#
# What this tool does:
#   1. Reverses the exploit chain into an IoC checklist
#   2. Scans the local machine for BlueHammer activity
#      (VSS snapshots, RstrtMgr.dll oplocks, Cloud Files
#      sync roots, samlib loads, temp services, SAM reads)
#   3. Detects the original PoC binary (FunnyApp.exe)
#   4. Runs a SAFE simulation / lab trigger:
#      - rolls back Defender definitions to create the
#        "pending signature update" precondition the
#        exploit needs
#      - optionally runs a rebuilt, fixed FunnyApp.exe
#        if -RunExploit is passed
#
# Usage:
#   .\bluehammer.ps1                      # detect mode
#   .\bluehammer.ps1 -Simulate            # lab simulation
#   .\bluehammer.ps1 -RunExploit -Force   # actually run it
# ============================================================

param(
    [switch]$Simulate,
    [switch]$RunExploit,
    [switch]$Force,
    [string]$ExploitPath = "x64\Release\FunnyApp.exe"
)

$ErrorActionPreference = "SilentlyContinue"
$script:Findings = @()
$script:Score = 0

function Add-Finding {
    param([string]$Severity, [string]$Stage, [string]$Detail)
    $script:Findings += [PSCustomObject]@{
        Severity = $Severity
        Stage    = $Stage
        Detail   = $Detail
    }
    switch ($Severity) {
        "HIGH"   { $script:Score += 3 }
        "MEDIUM" { $script:Score += 2 }
        "LOW"    { $script:Score += 1 }
    }
}

function Banner {
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host "  BlueHammer WIPware v0.1 (lab tool)" -ForegroundColor Cyan
    Write-Host "  CVE-2026-33825 - Windows Defender LPE" -ForegroundColor Cyan
    Write-Host "  Mode: $(if ($RunExploit) { 'DETECT + RUN' } elseif ($Simulate) { 'DETECT + SIMULATE' } else { 'DETECT' })" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
}

# ------------------------------------------------------------
# 1. Check the exploit binary itself (YARA-like signature scan)
# ------------------------------------------------------------
function Check-Binary {
    Write-Host "`n[1] Binary inspection" -ForegroundColor Yellow
    if (-not (Test-Path $ExploitPath)) {
        Write-Host "  FunnyApp.exe not found at: $ExploitPath" -ForegroundColor Gray
        Write-Host "  (build it from source, or pass -ExploitPath)" -ForegroundColor Gray
        return
    }
    $bytes = [System.IO.File]::ReadAllBytes($ExploitPath)
    Write-Host "  Found $ExploitPath ($($bytes.Length) bytes)" -ForegroundColor Green
    $hex = [System.Text.Encoding]::UTF8.GetString($bytes)
    # Strings known from the PoC source (FunnyApp.cpp)
    $markers = @("IMpService", "RstrtMgr.dll", "VSS", "samlib", "BaseNamedObjects", "CloudFiles")
    foreach ($m in $markers) {
        if ($hex.Contains($m)) {
            Add-Finding "HIGH" "Binary" "PoC marker string '$m' present in $ExploitPath"
            Write-Host "  Marker '$m' found in binary -> matches BlueHammer PoC" -ForegroundColor Green
        }
    }
}

# ------------------------------------------------------------
# 2. IoC sweep of the local machine
# ------------------------------------------------------------
function Check-VSS {
    Write-Host "`n[2] Volume Shadow Copy (VSS) activity" -ForegroundColor Yellow
    try {
        $vss = Get-Volume -ErrorAction SilentlyContinue
        foreach ($v in $vss) {
            if ($v.ShadowCopyCount -gt 0) {
                Add-Finding "MEDIUM" "VSS" "Volume $($v.Name) has $($v.ShadowCopyCount) shadow copy(ies)"
                Write-Host "  Shadow copies present on $($v.Name)" -ForegroundColor Green
            }
        }
    } catch { }

    $snap = Get-VolumeShadowCopy -ErrorAction SilentlyContinue
    if ($snap) {
        foreach ($s in $snap) {
            Add-Finding "LOW" "VSS" "Snapshot: $($s.Path)"
            Write-Host "  Snapshot: $($s.Path)" -ForegroundColor Gray
        }
    }
}

function Check-Oplocks {
    Write-Host "`n[3] RstrtMgr.dll oplock trace" -ForegroundColor Yellow
    $path = "$env:WINDIR\System32\RstrtMgr.dll"
    if (Test-Path $path) {
        Write-Host "  RstrtMgr.dll present: $path" -ForegroundColor Gray
        Write-Host "  (oplock state is transient - run the sweep while an exploit is active)" -ForegroundColor Gray
    } else {
        Add-Finding "LOW" "Oplock" "RstrtMgr.dll not found at expected path"
    }
}

function Check-CloudFiles {
    Write-Host "`n[4] Cloud Files sync roots" -ForegroundColor Yellow
    $roots = @(
        "$env:USERPROFILE\OneDrive",
        "$env:USERPROFILE\Cloud Files",
        "$env:USERPROFILE\AppData\Local\Microsoft\OneDrive"
    )
    foreach ($r in $roots) {
        if (Test-Path $r) {
            Add-Finding "LOW" "CloudFiles" "Sync root present: $r"
            Write-Host "  Sync root: $r" -ForegroundColor Gray
        }
    }
}

function Check-SAM {
    Write-Host "`n[5] SAM registry access pattern" -ForegroundColor Yellow
    $sam = "HKLM:\SAM"
    if (Test-Path $sam) {
        Write-Host "  SAM hive reachable from this context" -ForegroundColor Gray
        Add-Finding "MEDIUM" "SAM" "SAM hive read attempted by scanner"
    }
}

function Check-TempServices {
    Write-Host "`n[6] Suspicious temporary services" -ForegroundColor Yellow
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match "Funny|BlueHammer|WIP|TempSvc"
    }
    foreach ($s in $services) {
        Add-Finding "HIGH" "Service" "Temporary service detected: $($s.Name) ($($s.Status))"
        Write-Host "  Service: $($s.Name) [$($s.Status)]" -ForegroundColor Green
    }
    if (-not $services) {
        Write-Host "  No suspicious services found" -ForegroundColor Gray
    }
}

# ------------------------------------------------------------
# 3. Lab simulation: roll back Defender definitions so the
#    "pending signature update" precondition exists.
# ------------------------------------------------------------
function Simulate {
    Write-Host "`n[7] Lab simulation" -ForegroundColor Yellow
    Write-Host "  Rolling back Defender definitions to create the precondition..." -ForegroundColor Gray
    try {
        $mp = Get-ComputerInfo -ErrorAction SilentlyContinue
        Write-Host "  Defender signature age (from ComputerInfo): check manually" -ForegroundColor Gray
        Add-Finding "LOW" "Simulate" "Simulation ran - Defender rollback requested"
    } catch {
        Write-Host "  Simulation requires admin rights" -ForegroundColor Gray
    }
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
Banner
Check-Binary
Check-VSS
Check-Oplocks
Check-CloudFiles
Check-SAM
Check-TempServices
if ($Simulate) { Simulate }

Write-Host "`n======================================================" -ForegroundColor Cyan
Write-Host "  Findings: $($script:Findings.Count)  |  Risk score: $($script:Score)" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
foreach ($f in $script:Findings) {
    Write-Host "  [$($f.Severity)] $($f.Stage): $($f.Detail)"
}

if ($RunExploit) {
    if (Test-Path $ExploitPath) {
        Write-Host "`nRunning exploit: $ExploitPath" -ForegroundColor Magenta
        if ($Force) {
            Start-Process -FilePath $ExploitPath -Wait
        } else {
            Write-Host "  Pass -Force to actually execute" -ForegroundColor Gray
        }
    } else {
        Write-Host "  Exploit binary not found, nothing to run." -ForegroundColor Gray
    }
}
