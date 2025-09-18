<#
.SYNOPSIS
    Opinionated Windows 10 hardening script designed for CyberPatriot style competitions.

.DESCRIPTION
    Automates a core set of defensive actions that are frequently required during
    CyberPatriot or similar defensive hardening events.  The script focuses on
    quickly enabling built-in protections, locking down local accounts, and
    preparing a report for the team to review.  It intentionally avoids any
    destructive changes and records every step to make scoring and manual review
    easier.

.PARAMETER AuthorizedAdmins
    Local accounts (without the computer name prefix) that are allowed to remain
    in the local Administrators group.  All other local members will be removed
    when -ForceRemediation is supplied.

.PARAMETER AuthorizedUsers
    Local accounts that are expected to exist.  Accounts not listed here will be
    highlighted in the log for manual review.

.PARAMETER AuthorizedRemoteDesktopUsers
    Local accounts permitted to use Remote Desktop.  If -ForceRemediation is
    provided, all other local members of the "Remote Desktop Users" group will be
    removed.

.PARAMETER OutputDirectory
    Directory that will store the log and transcript files created during the
    hardening session.

.PARAMETER ForceRemediation
    Removes unauthorized accounts from privileged groups without prompting.  By
    default the script only reports issues for manual review.

.PARAMETER SkipRestorePoint
    Do not attempt to create a system restore point.  Use this only if System
    Protection is disabled or the environment prohibits restore point creation.

.PARAMETER SkipTranscript
    Do not start a PowerShell transcript.  The custom log file is still created.

.EXAMPLE
    .\Windows10-Hardening.ps1 -AuthorizedAdmins 'Administrator','CyberAdmin' \
        -AuthorizedUsers 'Administrator','CyberAdmin','Student01','Student02' \
        -AuthorizedRemoteDesktopUsers 'CyberAdmin' -ForceRemediation

    Executes the hardening routine, keeps the listed accounts in privileged
    groups, and automatically removes all other local administrators or Remote
    Desktop users.
#>
[CmdletBinding()]
param(
    [string[]]$AuthorizedAdmins = @('Administrator'),
    [string[]]$AuthorizedUsers = @('Administrator', 'DefaultAccount', 'WDAGUtilityAccount'),
    [string[]]$AuthorizedRemoteDesktopUsers = @(),
    [string]$OutputDirectory = (Join-Path -Path $env:SystemDrive -ChildPath 'CyberPatriot'),
    [switch]$ForceRemediation,
    [switch]$SkipRestorePoint,
    [switch]$SkipTranscript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Script:LogFile = $null
$Script:TranscriptPath = $null

function Test-IsAdministrator {
    <#
        .SYNOPSIS
            Confirms the script is running with administrative privileges.
    #>
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Initialize-HardeningSession {
    param(
        [string]$Path,
        [switch]$SkipTranscript
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logPath = Join-Path -Path $Path -ChildPath "Hardening_$timestamp.log"
    $null = New-Item -Path $logPath -ItemType File -Force

    $Script:LogFile = $logPath

    if (-not $SkipTranscript.IsPresent) {
        $transcriptPath = Join-Path -Path $Path -ChildPath "HardeningTranscript_$timestamp.txt"
        try {
            Start-Transcript -Path $transcriptPath -Force | Out-Null
            $Script:TranscriptPath = $transcriptPath
        }
        catch {
            Write-Log -Message "Unable to start PowerShell transcript: $_" -Level Warning
            $Script:TranscriptPath = $null
        }
    }

    Write-Log -Message "Logging initialized at $logPath" -Level Info
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"
    Write-Host $entry
    if ($null -ne $Script:LogFile) {
        Add-Content -Path $Script:LogFile -Value $entry -Encoding UTF8
    }
}

function Invoke-HardeningStep {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    Write-Log -Message "Starting: $Name"
    try {
        & $Action
        Write-Log -Message "Completed: $Name"
    }
    catch {
        Write-Log -Message "Failed: $Name. $_" -Level Error
    }
}

function New-CheckpointIfAvailable {
    param([string]$Description)

    if ($SkipRestorePoint.IsPresent) {
        Write-Log -Message 'SkipRestorePoint specified. Restore point creation skipped.' -Level Warning
        return
    }

    try {
        Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS'
        Write-Log -Message 'System restore point created.'
    }
    catch {
        Write-Log -Message "Unable to create a restore point. $_" -Level Warning
    }
}

function Set-RegistryDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Set-WindowsUpdatePolicy {
    Write-Log -Message 'Configuring Windows Update policy.'
    Set-Service -Name 'wuauserv' -StartupType Automatic
    try { Start-Service -Name 'wuauserv' } catch {}

    $updatePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Set-RegistryDword -Path $updatePath -Name 'NoAutoUpdate' -Value 0
    Set-RegistryDword -Path $updatePath -Name 'AUOptions' -Value 4   # Auto download and schedule install
    Set-RegistryDword -Path $updatePath -Name 'ScheduledInstallDay' -Value 0
    Set-RegistryDword -Path $updatePath -Name 'ScheduledInstallTime' -Value 3

    Write-Log -Message 'Triggering a Windows Update scan.'
    try {
        UsoClient StartScan | Out-Null
    }
    catch {
        Write-Log -Message 'UsoClient not available to trigger scan.' -Level Warning
    }
}

function Enable-FirewallProfiles {
    Write-Log -Message 'Enabling Windows Defender Firewall for all profiles.'
    $profiles = @('Domain', 'Private', 'Public')
    foreach ($profile in $profiles) {
        Set-NetFirewallProfile -Profile $profile -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True
    }
}

function Harden-WindowsDefender {
    Write-Log -Message 'Applying Microsoft Defender Antivirus settings.'
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableIntrusionPreventionSystem $false -DisableScriptScanning $false -MAPSReporting Advanced -SubmitSamplesConsent AlwaysPrompt -EnableControlledFolderAccess Disabled
        Set-MpPreference -ScanScheduleDay 0 -ScanScheduleTime 180
        Update-MpSignature | Out-Null
        Start-MpScan -ScanType QuickScan | Out-Null
    }
    catch {
        Write-Log -Message "Unable to configure Microsoft Defender. $_" -Level Warning
    }
}

function Set-LocalAccountPolicies {
    Write-Log -Message 'Setting local password and account policies.'
    $cmd = 'net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30'
    try {
        $result = cmd.exe /c $cmd
        if ($result) {
            foreach ($line in $result) {
                Write-Log -Message $line
            }
        }
    }
    catch {
        Write-Log -Message "Failed to configure account policies. $_" -Level Error
    }
}

function ConvertTo-SimpleAccountName {
    param([string]$AccountName)

    if ($AccountName -match '^[^\\]+\\(.+)$') {
        return $Matches[1]
    }
    return $AccountName
}

function Test-IsAuthorizedAccount {
    param(
        [string]$AccountName,
        [string[]]$AuthorizedList
    )

    if (-not $AuthorizedList -or $AuthorizedList.Count -eq 0) {
        return $true
    }

    $simple = ConvertTo-SimpleAccountName -AccountName $AccountName
    foreach ($authorized in $AuthorizedList) {
        if ($simple.Equals($authorized, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Invoke-LocalAccountAudit {
    param(
        [string[]]$Admins,
        [string[]]$Users,
        [string[]]$RemoteDesktop,
        [switch]$Force
    )

    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop

    $localUsers = Get-LocalUser | Sort-Object Name
    Write-Log -Message "Local user accounts: $($localUsers.Name -join ', ')"

    foreach ($user in $localUsers) {
        if (-not (Test-IsAuthorizedAccount -AccountName $user.Name -AuthorizedList $Users)) {
            Write-Log -Message "Unexpected local account discovered: $($user.Name)" -Level Warning
        }

        if (-not $user.Enabled) {
            continue
        }

        if ($user.PasswordNeverExpires) {
            try {
                Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
                Write-Log -Message "Password expiration re-enabled for $($user.Name)."
            }
            catch {
                Write-Log -Message "Unable to update password policy for $($user.Name). $_" -Level Warning
            }
        }
    }

    $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    if ($null -ne $guest -and $guest.Enabled) {
        try {
            Disable-LocalUser -Name 'Guest'
            Write-Log -Message 'Guest account disabled.'
        }
        catch {
            Write-Log -Message 'Failed to disable the Guest account.' -Level Warning
        }
    }

    foreach ($groupName in @('Administrators', 'Remote Desktop Users')) {
        try {
            $members = Get-LocalGroupMember -Group $groupName
        }
        catch {
            Write-Log -Message "Unable to enumerate $groupName. $_" -Level Warning
            continue
        }

        if (-not $members) {
            Write-Log -Message "No members detected in $groupName."
            continue
        }

        $authorized = if ($groupName -eq 'Administrators') { $Admins } else { $RemoteDesktop }
        foreach ($member in $members) {
            $simpleName = ConvertTo-SimpleAccountName -AccountName $member.Name
            if (-not (Test-IsAuthorizedAccount -AccountName $member.Name -AuthorizedList $authorized)) {
                $message = "$simpleName is not authorized in $groupName."
                Write-Log -Message $message -Level Warning
                if ($Force.IsPresent) {
                    try {
                        Remove-LocalGroupMember -Group $groupName -Member $member -Confirm:$false
                        Write-Log -Message "Removed $simpleName from $groupName."
                    }
                    catch {
                        Write-Log -Message "Failed to remove $simpleName from $groupName. $_" -Level Warning
                    }
                }
            }
        }
    }
}

function Disable-InsecureServices {
    $servicesToDisable = @(
        @{ Name = 'RemoteRegistry'; Description = 'Remote Registry service'; StartupType = 'Disabled' },
        @{ Name = 'TlntSvr'; Description = 'Telnet service'; StartupType = 'Disabled' },
        @{ Name = 'TermService'; Description = 'Remote Desktop Services'; StartupType = 'Disabled' },
        @{ Name = 'SSDPSRV'; Description = 'SSDP Discovery'; StartupType = 'Disabled' },
        @{ Name = 'upnphost'; Description = 'UPnP Device Host'; StartupType = 'Disabled' },
        @{ Name = 'SharedAccess'; Description = 'Internet Connection Sharing'; StartupType = 'Disabled' }
    )

    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service.Name -ErrorAction Stop
            if ($svc.StartType -ne $service.StartupType) {
                Set-Service -Name $service.Name -StartupType $service.StartupType
            }
            if ($svc.Status -eq 'Running' -and $service.StartupType -eq 'Disabled') {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
            }
            Write-Log -Message "Configured service $($service.Name) ($($service.Description)) to startup type $($service.StartupType)."
        }
        catch {
            Write-Log -Message "Unable to adjust service $($service.Name). $_" -Level Warning
        }
    }
}

function Disable-RemoteAccessFeatures {
    Write-Log -Message 'Disabling Remote Assistance and Remote Desktop.'
    try {
        Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
    }
    catch {
        Write-Log -Message 'Could not update Remote Assistance setting.' -Level Warning
    }

    try {
        Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
    }
    catch {
        Write-Log -Message 'Could not disable Remote Desktop.' -Level Warning
    }

    try {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Value 1 -Force
    }
    catch {
        Write-Log -Message 'Failed to enforce Remote Desktop credential protection.' -Level Warning
    }
}

function Set-AuditPolicyBaseline {
    Write-Log -Message 'Configuring Windows auditing policies.'
    $categories = @(
        'Account Logon',
        'Account Management',
        'DS Access',
        'Logon/Logoff',
        'Object Access',
        'Policy Change',
        'Privilege Use',
        'System'
    )

    foreach ($category in $categories) {
        try {
            auditpol.exe /set /category:"$category" /success:enable /failure:enable | Out-Null
        }
        catch {
            Write-Log -Message "Failed to set audit policy for $category. $_" -Level Warning
        }
    }
}

function Harden-WindowsFeatures {
    Write-Log -Message 'Removing legacy Windows features that are commonly vulnerable.'
    $features = @(
        'SMB1Protocol',
        'TelnetClient'
    )

    foreach ($feature in $features) {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null
            Write-Log -Message "Disabled Windows optional feature: $feature."
        }
        catch {
            Write-Log -Message "Unable to disable optional feature $feature. $_" -Level Warning
        }
    }
}

function Clear-TemporaryDirectories {
    Write-Log -Message 'Clearing temporary files to reclaim disk space.'
    $paths = @($env:TEMP, "$env:SystemRoot\Temp")

    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        try {
            Get-ChildItem -Path $path -Recurse -Force -ErrorAction Stop | Remove-Item -Force -Recurse -ErrorAction Stop
            Write-Log -Message "Cleared temporary directory: $path"
        }
        catch {
            Write-Log -Message "Unable to fully clear $path. $_" -Level Warning
        }
    }
}

if (-not (Test-IsAdministrator)) {
    throw 'Administrative privileges are required to run this script. Right-click PowerShell and choose "Run as administrator".'
}

Initialize-HardeningSession -Path $OutputDirectory -SkipTranscript:$SkipTranscript
Write-Log -Message 'CyberPatriot hardening script started.'

try {
    Invoke-HardeningStep -Name 'Create system restore point' -Action { New-CheckpointIfAvailable -Description 'CyberPatriot Hardening' }
    Invoke-HardeningStep -Name 'Configure Windows Update' -Action { Set-WindowsUpdatePolicy }
    Invoke-HardeningStep -Name 'Enable firewall profiles' -Action { Enable-FirewallProfiles }
    Invoke-HardeningStep -Name 'Harden Microsoft Defender' -Action { Harden-WindowsDefender }
    Invoke-HardeningStep -Name 'Apply local password policy' -Action { Set-LocalAccountPolicies }
    Invoke-HardeningStep -Name 'Audit local accounts' -Action { Invoke-LocalAccountAudit -Admins $AuthorizedAdmins -Users $AuthorizedUsers -RemoteDesktop $AuthorizedRemoteDesktopUsers -Force:$ForceRemediation }
    Invoke-HardeningStep -Name 'Disable unnecessary services' -Action { Disable-InsecureServices }
    Invoke-HardeningStep -Name 'Disable remote access features' -Action { Disable-RemoteAccessFeatures }
    Invoke-HardeningStep -Name 'Configure audit policy' -Action { Set-AuditPolicyBaseline }
    Invoke-HardeningStep -Name 'Disable risky Windows features' -Action { Harden-WindowsFeatures }
    Invoke-HardeningStep -Name 'Clear temporary directories' -Action { Clear-TemporaryDirectories }
}
finally {
    Write-Log -Message 'CyberPatriot hardening script completed.'
    if ($Script:TranscriptPath) {
        try { Stop-Transcript | Out-Null } catch {}
    }
}

Write-Log -Message 'Review the generated log file and transcript for manual follow-up tasks.'
