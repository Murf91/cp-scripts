<#
.SYNOPSIS
    Opinionated Windows Server hardening script for CyberPatriot-style competitions.

.DESCRIPTION
    Automates core defensive tasks commonly required on standalone Windows Server
    images used in CyberPatriot or similar hardening challenges. The script
    concentrates on enabling platform security features, auditing privileged
    accounts, and documenting changes for the team. All actions are recorded to a
    log file so that graders and teammates can quickly review the work.

.PARAMETER AuthorizedAdmins
    Local accounts (without the computer name prefix) that should remain in the
    local Administrators group. Others are removed only when -ForceRemediation is
    specified.

.PARAMETER AuthorizedUsers
    Local accounts that are expected to exist on the server. Accounts not listed
    are flagged in the log for manual review.

.PARAMETER AuthorizedRemoteDesktopUsers
    Local accounts allowed to stay in the Remote Desktop Users group. With
    -ForceRemediation, other local members of that group are removed.

.PARAMETER AuthorizedRemoteManagementUsers
    Local accounts that may remain in the Remote Management Users group. All
    other local members are optionally removed when -ForceRemediation is
    supplied.

.PARAMETER OutputDirectory
    Directory that will store the hardening log and optional PowerShell
    transcript.

.PARAMETER ForceRemediation
    Removes unauthorized members from privileged groups instead of just
    reporting on them.

.PARAMETER SkipRestorePoint
    Skip creating a system restore point. Use this if the feature is disabled or
    not permitted in the environment.

.PARAMETER SkipTranscript
    Do not record a PowerShell transcript. The custom log file is still
    produced.

.EXAMPLE
    .\WindowsServer-Hardening.ps1 -AuthorizedAdmins 'Administrator','CyberAdmin' \
        -AuthorizedUsers 'Administrator','CyberAdmin','SvcAccount' \
        -AuthorizedRemoteDesktopUsers 'CyberAdmin' -ForceRemediation

    Executes the hardening routine for Windows Server, preserving the supplied
    accounts in privileged groups and automatically removing other local
    administrators or remote access users.
#>
[CmdletBinding()]
param(
    [string[]]$AuthorizedAdmins = @('Administrator'),
    [string[]]$AuthorizedUsers = @('Administrator', 'DefaultAccount'),
    [string[]]$AuthorizedRemoteDesktopUsers = @(),
    [string[]]$AuthorizedRemoteManagementUsers = @(),
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
            Verifies the script is running with administrative privileges.
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
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
    $logPath = Join-Path -Path $Path -ChildPath "ServerHardening_$timestamp.log"
    $null = New-Item -Path $logPath -ItemType File -Force
    $Script:LogFile = $logPath

    if (-not $SkipTranscript.IsPresent) {
        $transcriptPath = Join-Path -Path $Path -ChildPath "ServerHardeningTranscript_$timestamp.txt"
        try {
            Start-Transcript -Path $transcriptPath -Force | Out-Null
            $Script:TranscriptPath = $transcriptPath
        }
        catch {
            Write-Log -Message "Unable to start PowerShell transcript: $_" -Level Warning
            $Script:TranscriptPath = $null
        }
    }

    Write-Log -Message "Logging initialized at $logPath"
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')][string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"
    Write-Host $entry
    if ($Script:LogFile) {
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
    Write-Log -Message 'Configuring Windows Update for automatic security patching.'
    Set-Service -Name 'wuauserv' -StartupType Automatic
    try { Start-Service -Name 'wuauserv' } catch {}

    $updatePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Set-RegistryDword -Path $updatePath -Name 'NoAutoUpdate' -Value 0
    Set-RegistryDword -Path $updatePath -Name 'AUOptions' -Value 4
    Set-RegistryDword -Path $updatePath -Name 'ScheduledInstallDay' -Value 0
    Set-RegistryDword -Path $updatePath -Name 'ScheduledInstallTime' -Value 3

    try {
        UsoClient StartScan | Out-Null
    }
    catch {
        Write-Log -Message 'UsoClient not available to trigger Windows Update scan.' -Level Warning
    }
}

function Enable-FirewallProfiles {
    Write-Log -Message 'Enabling Windows Defender Firewall for all profiles.'
    foreach ($profile in @('Domain', 'Private', 'Public')) {
        Set-NetFirewallProfile -Profile $profile -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True
    }
}

function Harden-WindowsDefender {
    Write-Log -Message 'Applying Microsoft Defender Antivirus configuration.'
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableIntrusionPreventionSystem $false -DisableScriptScanning $false -MAPSReporting Advanced -SubmitSamplesConsent AlwaysPrompt
        Set-MpPreference -ScanScheduleDay 0 -ScanScheduleTime 180
        Update-MpSignature | Out-Null
        Start-MpScan -ScanType QuickScan | Out-Null
    }
    catch {
        Write-Log -Message "Unable to configure Microsoft Defender. $_" -Level Warning
    }
}

function Set-LocalAccountPolicies {
    Write-Log -Message 'Setting local password and account lockout policies.'
    $command = 'net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30'
    try {
        $result = cmd.exe /c $command
        foreach ($line in $result) { Write-Log -Message $line }
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
    foreach ($entry in $AuthorizedList) {
        if ($simple.Equals($entry, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Invoke-LocalAccountAudit {
    param(
        [string[]]$Admins,
        [string[]]$Users,
        [hashtable]$GroupAuthorizations,
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
                Write-Log -Message "Unable to update password settings for $($user.Name). $_" -Level Warning
            }
        }
    }

    $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) {
        try {
            Disable-LocalUser -Name 'Guest'
            Write-Log -Message 'Guest account disabled.'
        }
        catch {
            Write-Log -Message 'Failed to disable the Guest account.' -Level Warning
        }
    }

    foreach ($groupName in $GroupAuthorizations.Keys) {
        try {
            $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop
        }
        catch {
            Write-Log -Message "Unable to enumerate group $groupName. $_" -Level Warning
            continue
        }

        if (-not $members) {
            Write-Log -Message "No members detected in $groupName."
            continue
        }

        $authorized = $GroupAuthorizations[$groupName]
        foreach ($member in $members) {
            if (-not (Test-IsAuthorizedAccount -AccountName $member.Name -AuthorizedList $authorized)) {
                $simple = ConvertTo-SimpleAccountName -AccountName $member.Name
                Write-Log -Message "$simple is not authorized in $groupName." -Level Warning
                if ($Force.IsPresent) {
                    try {
                        Remove-LocalGroupMember -Group $groupName -Member $member -Confirm:$false
                        Write-Log -Message "Removed $simple from $groupName."
                    }
                    catch {
                        Write-Log -Message "Failed to remove $simple from $groupName. $_" -Level Warning
                    }
                }
            }
        }
    }
}

function Harden-RemoteAccessFeatures {
    Write-Log -Message 'Hardening Remote Desktop and Remote Assistance settings.'
    try {
        Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
    }
    catch {
        Write-Log -Message 'Unable to disable Remote Assistance.' -Level Warning
    }

    try {
        Set-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Value 1
        Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
        Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 2
        Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fSingleSessionPerUser' -Value 1
    }
    catch {
        Write-Log -Message 'Failed to harden Remote Desktop authentication requirements.' -Level Warning
    }
}

function Harden-WinRM {
    Write-Log -Message 'Hardening Windows Remote Management (WinRM).' 
    try {
        Disable-PSRemoting -Force -ErrorAction Stop
        Write-Log -Message 'PowerShell remoting disabled. Re-enable if competition tasks require it.'
    }
    catch {
        Write-Log -Message "Unable to disable PowerShell remoting. $_" -Level Warning
    }

    try {
        Set-Service -Name 'WinRM' -StartupType Manual
        Stop-Service -Name 'WinRM' -Force -ErrorAction SilentlyContinue
        Write-Log -Message 'WinRM service set to manual start and stopped.'
    }
    catch {
        Write-Log -Message "Could not adjust WinRM service. $_" -Level Warning
    }

    try {
        $servicePath = 'WSMan:\localhost\Service'
        Set-Item -Path "$servicePath\AllowUnencrypted" -Value $false -Force
        Set-Item -Path "$servicePath\Auth\Basic" -Value $false -Force
        Set-Item -Path "$servicePath\Auth\CredSSP" -Value $false -Force
    }
    catch {
        Write-Log -Message 'Failed to tighten WinRM authentication settings.' -Level Warning
    }
}

function Disable-InsecureServices {
    $services = @(
        @{ Name = 'RemoteRegistry'; Description = 'Remote Registry service'; StartupType = 'Disabled' },
        @{ Name = 'SSDPSRV'; Description = 'SSDP Discovery'; StartupType = 'Disabled' },
        @{ Name = 'upnphost'; Description = 'UPnP Device Host'; StartupType = 'Disabled' },
        @{ Name = 'SNMP'; Description = 'Simple Network Management Protocol'; StartupType = 'Disabled' },
        @{ Name = 'SNMPTRAP'; Description = 'SNMP Trap'; StartupType = 'Disabled' },
        @{ Name = 'TlntSvr'; Description = 'Telnet service'; StartupType = 'Disabled' }
    )

    foreach ($service in $services) {
        try {
            $svc = Get-Service -Name $service.Name -ErrorAction Stop
            if ($svc.StartType -ne $service.StartupType) {
                Set-Service -Name $service.Name -StartupType $service.StartupType
            }
            if ($svc.Status -eq 'Running' -and $service.StartupType -eq 'Disabled') {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
            }
            Write-Log -Message "Configured $($service.Name) ($($service.Description)) to startup type $($service.StartupType)."
        }
        catch {
            Write-Log -Message "Service $($service.Name) not present or could not be modified." -Level Warning
        }
    }
}

function Set-SecurityOptions {
    Write-Log -Message 'Applying local security option hardening.'
    try {
        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Set-RegistryDword -Path $lsaPath -Name 'LimitBlankPasswordUse' -Value 1
        Set-RegistryDword -Path $lsaPath -Name 'LmCompatibilityLevel' -Value 5
        Set-RegistryDword -Path $lsaPath -Name 'NoLMHash' -Value 1
        Set-RegistryDword -Path $lsaPath -Name 'RestrictAnonymous' -Value 1
        Set-RegistryDword -Path $lsaPath -Name 'RestrictAnonymousSAM' -Value 1
        Set-RegistryDword -Path $lsaPath -Name 'DisableDomainCreds' -Value 1
        Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0
        Set-RegistryDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1
    }
    catch {
        Write-Log -Message "Failed to apply security option registry settings. $_" -Level Warning
    }
}

function Disable-LegacyProtocols {
    Write-Log -Message 'Disabling legacy network protocols (SMBv1, PowerShell v2).' 
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Log -Message 'Unable to disable SMB1Protocol optional feature.' -Level Warning
    }

    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
    }
    catch {
        Write-Log -Message 'Set-SmbServerConfiguration not available or failed.' -Level Warning
    }

    try {
        Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -NoRestart -ErrorAction Stop | Out-Null
        Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Log -Message 'Unable to disable Windows PowerShell v2 components.' -Level Warning
    }
}

function Set-AuditPolicyBaseline {
    Write-Log -Message 'Configuring Windows auditing policies for servers.'
    $categories = @(
        'Account Logon',
        'Account Management',
        'DS Access',
        'Logon/Logoff',
        'Object Access',
        'Policy Change',
        'Privilege Use',
        'System',
        'Detailed Tracking'
    )

    foreach ($category in $categories) {
        try {
            auditpol.exe /set /category:"$category" /success:enable /failure:enable | Out-Null
        }
        catch {
            Write-Log -Message "Failed to configure audit category $category. $_" -Level Warning
        }
    }
}

function Set-EventLogRetention {
    Write-Log -Message 'Increasing Application, System, and Security event log sizes.'
    $settings = @{ Application = 196608; System = 196608; Security = 262144 }
    foreach ($logName in $settings.Keys) {
        try {
            Limit-EventLog -LogName $logName -MaximumSize $settings[$logName] -OverflowAction OverwriteAsNeeded
            Write-Log -Message "Configured $logName log to $($settings[$logName]) KB with overwrite as needed."
        }
        catch {
            Write-Log -Message "Unable to adjust event log $logName. $_" -Level Warning
        }
    }
}

function Enable-PowerShellLogging {
    Write-Log -Message 'Enabling PowerShell module and script block logging.'
    try {
        $basePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
        Set-RegistryDword -Path (Join-Path $basePath 'ScriptBlockLogging') -Name 'EnableScriptBlockLogging' -Value 1
        Set-RegistryDword -Path (Join-Path $basePath 'ModuleLogging') -Name 'EnableModuleLogging' -Value 1
        $moduleLoggingPath = Join-Path $basePath 'ModuleLogging'
        New-ItemProperty -Path $moduleLoggingPath -Name 'ModuleNames' -Value '*' -PropertyType String -Force | Out-Null
    }
    catch {
        Write-Log -Message 'Failed to enable PowerShell logging policies.' -Level Warning
    }
}

function Write-ServerRoleSummary {
    Write-Log -Message 'Documenting installed server roles and key features.'
    try {
        Import-Module ServerManager -ErrorAction Stop
        $roles = Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' }
        $features = Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq 'Feature' -and $_.Name -match 'FS-|Remote-|Web-' }
        if ($roles) {
            Write-Log -Message "Installed roles: $($roles.DisplayName -join ', ')"
        }
        else {
            Write-Log -Message 'No server roles detected as installed.'
        }

        if ($features) {
            Write-Log -Message "Notable installed features: $($features.DisplayName -join ', ')"
        }
    }
    catch {
        Write-Log -Message 'ServerManager module not available; skipping role summary.' -Level Warning
    }
}

function Clear-TemporaryDirectories {
    Write-Log -Message 'Clearing temporary directories to reclaim disk space.'
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
    throw 'Administrative privileges are required to run this script. Launch PowerShell as an administrator.'
}

Initialize-HardeningSession -Path $OutputDirectory -SkipTranscript:$SkipTranscript
Write-Log -Message 'Windows Server CyberPatriot hardening started.'

$groupAuthorizations = @{
    'Administrators' = $AuthorizedAdmins
    'Remote Desktop Users' = $AuthorizedRemoteDesktopUsers
    'Remote Management Users' = $AuthorizedRemoteManagementUsers
}

try {
    Invoke-HardeningStep -Name 'Create system restore point' -Action { New-CheckpointIfAvailable -Description 'CyberPatriot Server Hardening' }
    Invoke-HardeningStep -Name 'Configure Windows Update' -Action { Set-WindowsUpdatePolicy }
    Invoke-HardeningStep -Name 'Enable firewall profiles' -Action { Enable-FirewallProfiles }
    Invoke-HardeningStep -Name 'Harden Microsoft Defender' -Action { Harden-WindowsDefender }
    Invoke-HardeningStep -Name 'Apply password policy' -Action { Set-LocalAccountPolicies }
    Invoke-HardeningStep -Name 'Audit local accounts and groups' -Action { Invoke-LocalAccountAudit -Admins $AuthorizedAdmins -Users $AuthorizedUsers -GroupAuthorizations $groupAuthorizations -Force:$ForceRemediation }
    Invoke-HardeningStep -Name 'Harden remote access features' -Action { Harden-RemoteAccessFeatures }
    Invoke-HardeningStep -Name 'Lock down WinRM' -Action { Harden-WinRM }
    Invoke-HardeningStep -Name 'Disable insecure services' -Action { Disable-InsecureServices }
    Invoke-HardeningStep -Name 'Apply security option registry settings' -Action { Set-SecurityOptions }
    Invoke-HardeningStep -Name 'Disable legacy protocols and features' -Action { Disable-LegacyProtocols }
    Invoke-HardeningStep -Name 'Configure audit policy' -Action { Set-AuditPolicyBaseline }
    Invoke-HardeningStep -Name 'Increase event log retention' -Action { Set-EventLogRetention }
    Invoke-HardeningStep -Name 'Enable PowerShell logging' -Action { Enable-PowerShellLogging }
    Invoke-HardeningStep -Name 'Record server roles and features' -Action { Write-ServerRoleSummary }
    Invoke-HardeningStep -Name 'Clear temporary directories' -Action { Clear-TemporaryDirectories }
}
finally {
    Write-Log -Message 'Windows Server CyberPatriot hardening completed.'
    if ($Script:TranscriptPath) {
        try { Stop-Transcript | Out-Null } catch {}
    }
}

Write-Log -Message 'Review the generated log for follow-up tasks and manual verification.'
