#requires -Version 5.1
<#
.SYNOPSIS
    Automated Windows Update installation with elevation, logging, exclusions, consent timeout, retries, and reboot handling.
.DESCRIPTION
    - Elevates to admin automatically
    - Comprehensive transcript + log
    - User confirmation with timeout or forced
    - Robust retry logic for NuGet/module setup
    - Microsoft Update service registration
    - Native PSWindowsUpdate exclusions
    - Multi-source reboot pending detection + module status
.PARAMETER ForceUpdate
    Bypass user confirmation and install updates automatically.
.PARAMETER ExcludeKBs
    Array of KB IDs to exclude (e.g., @('KB5000001','KB5000002')).
.PARAMETER ExcludeTitles
    Array of substrings to exclude by title (e.g., @('OneDrive','Preview')).
.PARAMETER ExcludeCategories
    Array of categories to exclude (e.g., @('Drivers','Definition Updates')).
.PARAMETER TimeoutMinutes
    Prompt timeout in minutes (default 5).
.PARAMETER MaxRetries
    Max retry attempts for provider/module actions (default 3).
.EXAMPLES
    .\WindowsUpdateScript.ps1
    .\WindowsUpdateScript.ps1 -ForceUpdate
    .\WindowsUpdateScript.ps1 -ExcludeKBs @('KB5000001') -TimeoutMinutes 10
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ForceUpdate,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeKBs = @(),

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeTitles = @(),

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeCategories = @(),

    [Parameter(Mandatory = $false)]
    [ValidateRange(1,60)]
    [int]$TimeoutMinutes = 5,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1,10)]
    [int]$MaxRetries = 3
)
# Fail fast + quiet progress
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Logging
$logDir = Join-Path $env:ProgramData 'PSWindowsUpdate'
$dateStamp = Get-Date -Format 'yyyy-MM-dd'
$timeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$log = Join-Path $logDir "UpdateLog_$dateStamp.log"
$transcript = Join-Path $logDir "Transcript_$timeStamp.txt"

# Ensure log directory
try { New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

#region Helper Functions
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$ts] [$Level] $Message"
    switch ($Level) {
        'Error'   { Write-Host $entry -ForegroundColor Red }
        'Warning' { Write-Host $entry -ForegroundColor Yellow }
        'Success' { Write-Host $entry -ForegroundColor Green }
        default   { Write-Host $entry }
    }
    try { $entry | Out-File -FilePath $log -Append -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Log "Failed to check administrator status: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Start-ElevatedProcess {
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $scriptPath)
        if ($ForceUpdate) { $args += '-ForceUpdate' }
        if ($ExcludeKBs.Count -gt 0) { $args += '-ExcludeKBs'; $args += ($ExcludeKBs -join ',') }
        if ($ExcludeTitles.Count -gt 0) { $args += '-ExcludeTitles'; $args += ($ExcludeTitles -join ',') }
        if ($ExcludeCategories.Count -gt 0) { $args += '-ExcludeCategories'; $args += ($ExcludeCategories -join ',') }
        if ($PSBoundParameters.ContainsKey('TimeoutMinutes')) { $args += '-TimeoutMinutes'; $args += $TimeoutMinutes }
        if ($PSBoundParameters.ContainsKey('MaxRetries')) { $args += '-MaxRetries'; $args += $MaxRetries }
        Write-Log "Elevating to administrator..." -Level Warning
        Start-Process -FilePath 'powershell.exe' -ArgumentList $args -Verb RunAs -Wait
        exit 0
    } catch {
        Write-Log "Failed to elevate: $($_.Exception.Message)" -Level Error
        exit 1
    }
}

function Initialize-Prerequisites {
    Write-Log "Initializing prerequisites..."
    # TLS 1.2
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Log "TLS 1.2 enabled" -Level Success
    } catch { Write-Log "Failed to set TLS 1.2: $($_.Exception.Message)" -Level Warning }

    # NuGet provider
    $retry = 0
    do {
        try {
            if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
                Write-Log "Installing NuGet provider (attempt $($retry+1)/$MaxRetries)..."
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -Confirm:$false | Out-Null
                Write-Log "NuGet provider installed" -Level Success
            }
            break
        } catch {
            $retry++
            Write-Log "NuGet provider failed (attempt $retry): $($_.Exception.Message)" -Level Warning
            if ($retry -ge $MaxRetries) { throw "NuGet provider setup failed after $MaxRetries attempts: $($_.Exception.Message)" }
            Start-Sleep -Seconds (5 * $retry)
        }
    } while ($retry -lt $MaxRetries)

    # PSGallery trust
    try {
        $psg = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($psg -and $psg.InstallationPolicy -ne 'Trusted') {
            Write-Log "Trusting PSGallery..."
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Write-Log "PSGallery trusted" -Level Success
        }
    } catch { Write-Log "Could not set PSGallery as trusted: $($_.Exception.Message)" -Level Warning }

    # Install PSWindowsUpdate
    $retry = 0
    do {
        try {
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Write-Log "Installing PSWindowsUpdate (attempt $($retry+1)/$MaxRetries)..."
                Install-Module -Name PSWindowsUpdate -Scope AllUsers -Force -AllowClobber -Confirm:$false
                Write-Log "PSWindowsUpdate installed" -Level Success
            }
            break
        } catch {
            $retry++
            Write-Log "Failed to install PSWindowsUpdate (attempt $retry): $($_.Exception.Message)" -Level Warning
            if ($retry -ge $MaxRetries) { throw "PSWindowsUpdate install failed after $MaxRetries attempts: $($_.Exception.Message)" }
            Start-Sleep -Seconds (5 * $retry)
        }
    } while ($retry -lt $MaxRetries)

    # Import module
    try { Import-Module PSWindowsUpdate -Force; Write-Log "PSWindowsUpdate imported" -Level Success }
    catch { throw "Failed to import PSWindowsUpdate: $($_.Exception.Message)" }

    # Microsoft Update service (explicit)
    try {
        # ServiceID: Microsoft Update
        $muId = '7971f918-a847-4430-9279-4a52d1efe18d'
        Add-WUServiceManager -ServiceID $muId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Microsoft Update service configured" -Level Success
    } catch { Write-Log "Could not configure Microsoft Update service: $($_.Exception.Message)" -Level Warning }
}

function Get-UserConsent {
    if ($ForceUpdate) { Write-Log "ForceUpdate specified - skipping confirmation"; return $true }
    Write-Log "Requesting user consent..."
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $message = "Install available Windows updates now?`n`nSystem may reboot automatically.`n`nThis dialog times out in $TimeoutMinutes minute(s) and defaults to YES."
        $caption = "Windows Update - Confirmation"
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $TimeoutMinutes * 60 * 1000
        $form = $null
        $timer.Add_Tick({
            Write-Log "Prompt timed out after $TimeoutMinutes minute(s) - proceeding" -Level Warning
            if ($form) { $form.DialogResult = [System.Windows.Forms.DialogResult]::Yes }
            $timer.Stop()
        })
        $timer.Start()
        $result = [System.Windows.Forms.MessageBox]::Show($message,$caption,[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Question)
        $timer.Stop(); $timer.Dispose()
        $proceed = ($result -eq [System.Windows.Forms.DialogResult]::Yes)
        Write-Log "User response: $(if ($proceed) {'Accepted'} else {'Declined'})"
        return $proceed
    } catch {
        Write-Log "GUI prompt failed, falling back to console: $($_.Exception.Message)" -Level Warning
        try {
            $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
            Write-Host "`nWindows Update - Confirmation" -ForegroundColor Cyan
            Write-Host "================================" -ForegroundColor Cyan
            Write-Host "Install updates now? Reboot may occur." -ForegroundColor Yellow
            Write-Host "`nTimeout in $TimeoutMinutes minute(s). Default: YES" -ForegroundColor Red
            Write-Host "`nPress Y or N then Enter: " -NoNewline
            do {
                if ([Console]::KeyAvailable) {
                    $k = [Console]::ReadKey($true)
                    if ($k.KeyChar -in 'Y','y') { Write-Host "Y" -ForegroundColor Green; return $true }
                    if ($k.KeyChar -in 'N','n') { Write-Host "N" -ForegroundColor Red; return $false }
                }
                Start-Sleep -Milliseconds 100
            } while ((Get-Date) -lt $deadline)
            Write-Host "`nTimeout reached - proceeding" -ForegroundColor Yellow
            Write-Log "Prompt timed out after $TimeoutMinutes minute(s) - proceeding" -Level Warning
            return $true
        } catch {
            Write-Log "Console prompt failed: $($_.Exception.Message)" -Level Warning
            Write-Log "Defaulting to proceed" -Level Warning
            return $true
        }
    }
}

function Test-RebootPending {
    # Multi-source detection: registry, CBS, WU, SCCM
    $pending = $false
    $reasons = New-Object System.Collections.Generic.List[string]

    try {
        if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue) {
            $pending = $true; $reasons.Add('Windows Update')
        }
    } catch {}
    try {
        if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue) {
            $pending = $true; $reasons.Add('Component Based Servicing')
        }
    } catch {}
    try {
        if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations' -ErrorAction SilentlyContinue) {
            $pending = $true; $reasons.Add('Pending File Rename Operations')
        }
    } catch {}

    # SCCM/ConfigMgr
    try {
        if (Get-CimInstance -ClassName CCM_ClientUtilities -Namespace 'root\ccm\clientsdk' -ErrorAction SilentlyContinue) {
            $r = Invoke-CimMethod -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -Namespace 'root\ccm\clientsdk' -ErrorAction SilentlyContinue
            if ($r -and $r.RebootPending) { $pending = $true; $reasons.Add('SCCM Client') }
        }
    } catch {}

    # Module-derived status
    $wuReboot = $null
    try {
        $wuReboot = Get-WURebootStatus -ErrorAction SilentlyContinue
        if ($wuReboot -and ($wuReboot.RebootRequired -or $wuReboot.RebootScheduled)) {
            $pending = $true
            if ($wuReboot.RebootRequired) { $reasons.Add('Get-WURebootStatus: RebootRequired') }
            if ($wuReboot.RebootScheduled) { $reasons.Add('Get-WURebootStatus: RebootScheduled') }
        }
    } catch {}

    return @{
        RebootPending = $pending
        Reasons       = $reasons.ToArray()
        ModuleStatus  = $wuReboot
    }
}

function Install-WindowsUpdates {
    Write-Log "Starting Windows Update installation..." -Level Info

    # Build native exclusion filters
    $notKb = @()
    if ($ExcludeKBs.Count -gt 0) {
        # Normalize: strip leading 'KB'
        $notKb = $ExcludeKBs | ForEach-Object { $_ -replace '^KB','' }
    }
    $notTitle = $ExcludeTitles
    $notCategory = $ExcludeCategories

    try {
        # Enumerate updates with Microsoft Update and apply native "Not*" filters
        Write-Log "Scanning for available updates..."
        $params = @{
            MicrosoftUpdate = $true
            Verbose         = $false
            ErrorAction     = 'Stop'
        }
        if ($notKb.Count -gt 0)    { $params['NotKBArticleID'] = $notKb }
        if ($notTitle.Count -gt 0) { $params['NotTitle']      = $notTitle }
        if ($notCategory.Count -gt 0){$params['NotCategory']  = $notCategory }

        $updates = Get-WindowsUpdate @params
        if (-not $updates) {
            Write-Log "No updates available" -Level Success
            return $true
        }

        Write-Log "Found $($updates.Count) update(s) to install:" -Level Info
        foreach ($u in $updates) {
            $sizeMb = if ($u.Size -gt 0) { "{0:N2} MB" -f ($u.Size/1MB) } else { "unknown size" }
            Write-Log "  - $($u.Title) ($sizeMb)" -Level Info
        }

        # Persist the list
        $updates | Select-Object Title, Size, Description, KBArticleIDs, Categories |
            ConvertTo-Json -Depth 3 | Out-File -FilePath $log -Append -Encoding UTF8

        # Install with AcceptAll + AutoReboot
        Write-Log "Installing updates (AcceptAll + AutoReboot). System may reboot automatically..." -Level Info

        # Use Install-WindowsUpdate directly with same exclusion flags for parity
        $installParams = @{
            MicrosoftUpdate = $true
            AcceptAll       = $true
            AutoReboot      = $true
            Confirm         = $false
            Verbose         = $true
            ErrorAction     = 'Continue'
        }
        if ($notKb.Count -gt 0)      { $installParams['NotKBArticleID'] = $notKb }
        if ($notTitle.Count -gt 0)   { $installParams['NotTitle']      = $notTitle }
        if ($notCategory.Count -gt 0){ $installParams['NotCategory']   = $notCategory }

        $installResult = Install-WindowsUpdate @installParams 2>&1
        $installResult | Out-File -FilePath $log -Append -Encoding UTF8

        # Basic result parsing (best-effort; module output varies)
        $success = ($installResult | Where-Object { $_ -match 'Status:\s*Succeeded|successfully installed' }).Count
        $failed  = ($installResult | Where-Object { $_ -match 'Status:\s*Failed|failed' }).Count
        if ($failed -eq 0) {
            Write-Log "Updates installed successfully (Succeeded=$success, Failed=$failed)" -Level Success
            return $true
        } else {
            Write-Log "Some updates failed (Succeeded=$success, Failed=$failed)" -Level Warning
            return $false
        }
    } catch {
        Write-Log "Installation failed: $($_.Exception.Message)" -Level Error
        Write-Log "Full error: $($_.Exception.ToString())" -Level Error
        return $false
    }
}

function Show-CompletionMessage {
    $status = Test-RebootPending
    $needsReboot = $status.RebootPending
    $reasonsText = if ($status.Reasons -and $status.Reasons.Count -gt 0) { $status.Reasons -join ', ' } else { 'None detected' }
    $modStr = if ($status.ModuleStatus) {
        "ModuleStatus: RebootRequired=$($status.ModuleStatus.RebootRequired); RebootScheduled=$($status.ModuleStatus.RebootScheduled)"
    } else { "ModuleStatus: unavailable" }

    if ($needsReboot) {
        $message = "Updates installed.`n`nA reboot is required to complete installation.`nReasons: $reasonsText`n$modStr`n`nIf automatic reboot was enabled, the system may restart automatically."
        $title = "Windows Update - Reboot Required"
        $icon = [System.Windows.Forms.MessageBoxIcon]::Warning
        Write-Log "Updates complete - reboot required. Reasons: $reasonsText; $modStr" -Level Warning
    } else {
        $message = "Updates installed successfully.`n`nNo reboot required at this time.`n$modStr"
        $title = "Windows Update - Completed"
        $icon = [System.Windows.Forms.MessageBoxIcon]::Information
        Write-Log "Updates complete - no reboot required. $modStr" -Level Success
    }

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        [System.Windows.Forms.MessageBox]::Show($message, $title, [System.Windows.Forms.MessageBoxButtons]::OK, $icon) | Out-Null
    } catch {
        Write-Host "`n$title" -ForegroundColor $(if ($needsReboot) { 'Yellow' } else { 'Green' })
        Write-Host $('=' * $title.Length) -ForegroundColor $(if ($needsReboot) { 'Yellow' } else { 'Green' })
        Write-Host $message
    }
}
#endregion

#region Main
try {
    # Transcript
    try {
        Start-Transcript -Path $transcript -Append -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Transcript started: $transcript"
    } catch { Write-Log "Could not start transcript: $($_.Exception.Message)" -Level Warning }

    Write-Log "Windows Update Script Started" -Level Info
    Write-Log "Parameters: ForceUpdate=$ForceUpdate, ExcludeKBs=$($ExcludeKBs -join ','), ExcludeTitles=$($ExcludeTitles -join ','), ExcludeCategories=$($ExcludeCategories -join ','), TimeoutMinutes=$TimeoutMinutes, MaxRetries=$MaxRetries" -Level Info

    if (-not (Test-IsAdministrator)) {
        Write-Log "Administrator required; elevating..." -Level Warning
        Start-ElevatedProcess
        # Elevated instance continues; current exits in Start-ElevatedProcess
    }

    Write-Log "Running with administrator privileges" -Level Success

    try {
        Initialize-Prerequisites
        Write-Log "Prerequisites initialized" -Level Success
    } catch {
        Write-Log "Failed to initialize prerequisites: $($_.Exception.Message)" -Level Error
        exit 1
    }

    if (-not (Get-UserConsent)) {
        Write-Log "User declined update installation"
        exit 0
    }

    Write-Log "User confirmed. Proceeding..." -Level Info
    $ok = Install-WindowsUpdates

    if ($ok) {
        Show-CompletionMessage
        Write-Log "Windows Update process completed successfully" -Level Success
        $exitCode = 0
    } else {
        Write-Log "Windows Update process completed with errors" -Level Error
        $exitCode = 2
    }
} catch {
    Write-Log "Critical error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    $exitCode = 1
} finally {
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null; Write-Log "Transcript stopped" } catch {}
    Write-Log "Script execution completed with exit code: $exitCode"
    exit $exitCode
}
#endregion
