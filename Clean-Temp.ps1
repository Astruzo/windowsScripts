#requires -Version 5.1
# Clean Windows Temp and user %TEMP% with admin elevation, skipping files in use.

[CmdletBinding()]
param(
    [switch]$ShowRunDialog  # If set, briefly opens Win+R before cleanup (best-effort).
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Some hosts suppress progress for perf [17]

# Paths to clean
$UserTemp     = $env:TEMP
$WindowsTemp  = Join-Path $env:WINDIR 'Temp'

# Logging
$LogRoot = Join-Path $env:ProgramData 'TempCleanup'
$null = New-Item -ItemType Directory -Path $LogRoot -Force -ErrorAction SilentlyContinue
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile   = Join-Path $LogRoot "Cleanup_$Timestamp.log"

function Write-Log {
    param([string]$Message, [ValidateSet('Info','Warning','Error','Success')] [string]$Level='Info')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        'Error'   { Write-Host $line -ForegroundColor Red }
        'Warning' { Write-Host $line -ForegroundColor Yellow }
        'Success' { Write-Host $line -ForegroundColor Green }
        default   { Write-Host $line }
    }
    try { $line | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = [Security.Principal.WindowsPrincipal]::new($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Elevate-IfNeeded {
    if (Test-IsAdmin) { return }
    Write-Log "Elevation required. Relaunching as administrator..." 'Warning'
    $psi = @{
        FilePath     = 'powershell.exe'
        ArgumentList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',($MyInvocation.MyCommand.Path))
        Verb         = 'RunAs'
        WindowStyle  = 'Normal'
        Wait         = $true
    }
    if ($PSBoundParameters.ContainsKey('ShowRunDialog')) {
        $psi.ArgumentList += '-ShowRunDialog'
    }
    Start-Process @psi
    exit 0
}

function Show-Run {
    try {
        Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Start-Sleep -Milliseconds 250
        [System.Windows.Forms.SendKeys]::SendWait('^%') | Out-Null  # noop to init
        # Send Win+R (Run dialog); PowerShell lacks a native Win modifier API, so simulate via shell
        # Workaround: launch the shell Run UI directly
        Start-Process 'explorer.exe' 'shell:::{2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}' | Out-Null
        Write-Log "Run dialog requested (best-effort shown)" 'Info'
    } catch {
        Write-Log "Could not display Run dialog (continuing): $($_.Exception.Message)" 'Warning'
    }
}

function Clear-TempFolder {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log "Path not found: $Path" 'Warning'
        return
    }

    # Build child items pattern to keep folder but remove contents [10]
    $target = Join-Path $Path '*'

    Write-Log "Cleaning: $Path" 'Info'

    # Enumerate first so we can log counts and selectively skip in-use files
    $items = @()
    try {
        $items = Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Enumerate failed: $Path :: $($_.Exception.Message)" 'Warning'
    }

    $deleted = 0
    $skipped = 0

    # Fast bulk attempt, errors suppressed so in-use items are skipped automatically [10]
    try {
        Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        # We rely on per-item fallback below; continue
    }

    # Fallback pass: try remaining items individually for better logging
    foreach ($it in $items) {
        if (-not (Test-Path -LiteralPath $it.FullName)) { continue }
        try {
            # Attempt to remove specific item; directories require -Recurse
            if ($it.PSIsContainer) {
                Remove-Item -LiteralPath $it.FullName -Recurse -Force -ErrorAction Stop
            } else {
                Remove-Item -LiteralPath $it.FullName -Force -ErrorAction Stop
            }
            $deleted++
        } catch {
            $skipped++
            Write-Log "Skipped (in use or access denied): $($it.FullName)" 'Warning'
        }
    }

    Write-Log "Completed: $Path | Deleted: $deleted | Skipped: $skipped" 'Success'
}

# Main
try {
    Elevate-IfNeeded
    Write-Log "Temp cleanup started. Log: $LogFile" 'Info'

    if ($ShowRunDialog) { Show-Run }  # optional visual cue [12][6]

    # Clean user %TEMP% first, then Windows Temp
    Clear-TempFolder -Path $UserTemp
    Clear-TempFolder -Path $WindowsTemp  # requires admin; otherwise some items will skip [19]

    Write-Log "Temp cleanup finished." 'Success'
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" 'Error'
    exit 1
}
