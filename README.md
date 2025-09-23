# CyberPatriot Hardening Scripts

This repository contains ready-to-run hardening automation for Windows 10,
Windows Server, Ubuntu, and Debian-based Linux images that appear in CyberPatriot-style
defensive competitions. Each script focuses on quickly configuring built-in
protections, auditing local accounts, and generating a report that teammates can
review for follow-up tasks.

## Windows Server hardening script (`WindowsServer-Hardening.ps1`)

### Usage

1. Copy `WindowsServer-Hardening.ps1` to the target Windows Server machine.
2. Launch PowerShell **as an administrator**.
3. Review the authorized account lists for the image and update the command.
4. Execute the script. Example:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\WindowsServer-Hardening.ps1 -AuthorizedAdmins 'Administrator','CyberAdmin' `
       -AuthorizedUsers 'Administrator','CyberAdmin','SvcAccount' `
       -AuthorizedRemoteDesktopUsers 'CyberAdmin' `
       -AuthorizedRemoteManagementUsers 'CyberAdmin' -ForceRemediation
   ```

5. Review the generated log and transcript in `C:\CyberPatriot` (or the value of
   the `-OutputDirectory` parameter) for follow-up tasks.

### Parameters

| Parameter | Description |
| --- | --- |
| `-AuthorizedAdmins` | Whitelisted local accounts that should stay in the local Administrators group. |
| `-AuthorizedUsers` | Local accounts that are expected to exist on the system; unexpected accounts are flagged. |
| `-AuthorizedRemoteDesktopUsers` | Accounts that may remain in the Remote Desktop Users group. |
| `-AuthorizedRemoteManagementUsers` | Accounts that may remain in the Remote Management Users group for WinRM. |
| `-OutputDirectory` | Destination for the log and transcript. Default is `C:\CyberPatriot`. |
| `-ForceRemediation` | Remove unauthorized members from privileged local groups automatically. |
| `-SkipRestorePoint` | Skip the attempt to create a system restore point. |
| `-SkipTranscript` | Skip PowerShell transcription; the custom log file is still produced. |

### Hardening actions performed

* Create a dedicated log directory and optional PowerShell transcript for the session.
* Attempt to create a system restore point for safety.
* Configure Windows Update services and schedule, then trigger scans, downloads, and installs.
* Enable Windows Defender Firewall on all profiles.
* Apply Microsoft Defender Antivirus preferences, update signatures, and start a quick scan.
* Enforce password, account lockout, and password history policies.
* Audit local accounts as well as Administrators, Remote Desktop Users, and Remote Management Users groups with optional remediation.
* Harden Remote Desktop settings, enforce single-session usage, disable Remote Assistance, and turn off Remote Desktop sharing unless the image requires it.
* Disable PowerShell remoting, configure WinRM to manual start, and block weak authentication methods.
* Disable legacy or insecure services such as Remote Registry, SNMP, Telnet, SSDP, and UPnP when present.
* Apply security option registry settings to restrict anonymous access, prevent LM hashes, hide the last logged-on user, and require digitally signed SMB communications.
* Disable administrative root shares to prevent exposing the system drive through default shares.
* Disable SMBv1, remove Windows PowerShell v2 components, and attempt to disable the SMBv1 server stack.
* Remove optional media playback features and uninstall prohibited software such as Hola VPN, Web Companion, VLC, and L0phtCrack when detected.
* Attempt to upgrade Inkscape and GIMP through Winget or Chocolatey when they are installed.
* Enforce the Firefox popup blocker through enterprise policies when Firefox is present.
* Configure advanced audit policies, expand event log sizes, and enable PowerShell script block and module logging.
* Record the list of installed roles and notable features for team review.
* Clear temporary directories to reclaim disk space.

### Manual follow-up checklist

After the script finishes:

* Review the generated log for warnings about unexpected accounts, services, or registry settings that could not be applied.
* Validate installed roles, features, and services against the competition readme, enabling any that are explicitly required.
* Confirm remote access requirements for the image (RDP, WinRM) and re-enable components if the scoring guide mandates it.
* Inspect shared folders, scheduled tasks, and startup programs for unapproved items.
* Remove unapproved applications, browser extensions, and media files.
* Verify Inkscape and GIMP versions if they remain installed when no automated package manager was available.
* Verify Windows Defender Antivirus and Windows Update successfully complete scans shortly after hardening.

## Windows 10 hardening script (`Windows10-Hardening.ps1`)

### Usage

1. Copy `Windows10-Hardening.ps1` to the target Windows 10 machine.
2. Launch PowerShell **as an administrator**.
3. Review the lists of authorized accounts for the image and update the command
   accordingly.
4. Execute the script. Example:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\Windows10-Hardening.ps1 -AuthorizedAdmins 'Administrator','CyberAdmin' `
       -AuthorizedUsers 'Administrator','CyberAdmin','Student01','Student02' `
       -AuthorizedRemoteDesktopUsers 'CyberAdmin' -ForceRemediation
   ```

5. Review the generated log and transcript in `C:\CyberPatriot` (or the value of
   the `-OutputDirectory` parameter) for follow-up tasks.

### Parameters

| Parameter | Description |
| --- | --- |
| `-AuthorizedAdmins` | Whitelisted local accounts that should stay in the local Administrators group. |
| `-AuthorizedUsers` | Local accounts that are expected to exist on the system; unexpected accounts are flagged. |
| `-AuthorizedRemoteDesktopUsers` | Accounts that may remain in the Remote Desktop Users group. |
| `-OutputDirectory` | Destination for the log and transcript. Default is `C:\CyberPatriot`. |
| `-ForceRemediation` | Remove unauthorized members from privileged local groups automatically. |
| `-SkipRestorePoint` | Skip the attempt to create a system restore point. |
| `-SkipTranscript` | Skip PowerShell transcription; a custom log file is still produced. |

### Hardening actions performed

* Create a dedicated log directory and optional PowerShell transcript for the session.
* Attempt to create a system restore point for safety.
* Configure Windows Update services and schedule.
* Enable Windows Defender Firewall on all profiles.
* Apply Microsoft Defender Antivirus preferences, update signatures, and start a quick scan.
* Enforce common password and account lockout policies.
* Audit local accounts, disable the built-in Guest account, and optionally remove unauthorized administrators or Remote Desktop users.
* Disable legacy or rarely-used services such as Remote Registry, Telnet, SSDP, and Internet Connection Sharing.
* Disable Remote Assistance and Remote Desktop, and block credential caching for RDP.
* Enable audit policy categories for success and failure events.
* Disable vulnerable Windows optional features including SMBv1 and the Telnet client.
* Clear temporary directories to reclaim disk space.

### Manual follow-up checklist

The script is intentionally conservative. After it finishes:

* Review the generated log for warnings that call out unexpected accounts, services, or configuration issues.
* Validate local users, groups, and shares against the CyberPatriot readme for the image.
* Uninstall unapproved applications and browser extensions.
* Check installed updates and, if permitted, install any critical patches that remain outstanding.
* Review scheduled tasks, startup items, and running processes for anomalies.
* Confirm required services (e.g., print spooler on images where it is needed) remain enabled.

The log captures each action taken so that team members and graders can quickly
verify what was changed and what still needs manual attention.

## Ubuntu hardening script (`Ubuntu-Hardening.sh`)

### Usage

1. Copy `Ubuntu-Hardening.sh` to the target Ubuntu workstation or server image.
2. Review the authorized account lists and decide whether to skip Fail2Ban, snap, or desktop tweaks.
3. Run the script as root (or with `sudo`). Example:

   ```bash
   sudo ./Ubuntu-Hardening.sh \
     --authorized-admins "root,cyberadmin" \
     --authorized-users "cyberadmin,student01,student02" \
     --force-remediation \
     --skip-desktop-hardening
   ```

4. Inspect the generated log in `/var/log/cyberpatriot` (or the value supplied
   to `--output-directory`) for follow-up actions.

### Parameters

| Parameter | Description |
| --- | --- |
| `--authorized-admins` | Comma-separated local accounts allowed to remain in the sudo/admin group. |
| `--authorized-users` | Expected interactive (UID ≥ 1000) local accounts; other accounts are flagged. |
| `--sudo-group` | Name of the privileged group to audit. Defaults to `sudo`. |
| `--output-directory` | Directory where logs are written. Defaults to `/var/log/cyberpatriot`. |
| `--force-remediation` | Remove unauthorized sudo members and lock unexpected accounts automatically. |
| `--skip-fail2ban` | Skip installing/configuring Fail2Ban if competition rules forbid it. |
| `--skip-snap` | Skip snap refresh and policy configuration if snaps are restricted. |
| `--skip-desktop-hardening` | Skip GNOME/lightdm guest restrictions and screen lock policies for server-only images. |

### Hardening actions performed

* Create a timestamped log and capture system context for competition reporting.
* Refresh the APT package index, apply upgrades, and install baseline security tooling (UFW, unattended upgrades, AppArmor, auditd, pwquality, needrestart, optional Fail2Ban).
* Configure unattended-upgrades to pull security, updates, and Extended Security Maintenance channels.
* Reset the UFW firewall to deny inbound traffic by default while preserving SSH access, then enable logging.
* Harden the OpenSSH daemon with stricter authentication, idle, and forwarding policies.
* Enforce password-complexity controls via `pam_pwquality` and tighten `/etc/login.defs` settings.
* Audit interactive users and sudo-group membership against the supplied allow-lists with optional automatic remediation.
* Enable AppArmor enforcement, deploy auditd baseline rules, and refresh them.
* Refresh snap packages, limit retained revisions, and schedule overnight refresh windows when snaps are present.
* Disable guest logins, automatic logins, and enforce GNOME screen-lock behavior when a desktop environment is detected.
* Purge insecure legacy networking or remote-control packages (telnet, rsh, vino, etc.) and disable associated services.
* Clean package caches to reclaim disk space after hardening.

### Manual follow-up checklist

After the script completes:

* Review `/var/log/cyberpatriot` for warnings about unexpected accounts, services, or skipped tasks (snap/desktop/AppArmor).
* Confirm sudo membership, interactive accounts, and SSH access align with the competition readme.
* Verify AppArmor and auditd are active (`aa-status --summary`, `service auditd status`) and that Fail2Ban is protecting SSH if enabled.
* Check `snap list` and `snap refresh --time` to ensure competition requirements for snaps are satisfied or to adjust schedules if needed.
* Validate desktop behavior (login screen, idle lock, screen blanking) matches scoring requirements when a GUI is present.
* Inspect running services, open ports, scheduled tasks, and installed applications for items that must remain enabled for scoring.
* Remove disallowed software, media files, and browser extensions not handled automatically.


## Debian-based Linux hardening script (`Debian-Hardening.sh`)

### Usage

1. Copy `Debian-Hardening.sh` to the target Debian workstation or derivative server. For Ubuntu desktop-focused images, use `Ubuntu-Hardening.sh`.
2. Review the authorized administrator and user lists for the image.
3. Run the script as root (or with `sudo`). Example:

   ```bash
   sudo ./Debian-Hardening.sh \
     --authorized-admins "root,cyberadmin" \
     --authorized-users "cyberadmin,student01,student02" \
     --force-remediation
   ```

4. Inspect the generated log in `/var/log/cyberpatriot` (or the value supplied
   to `--output-directory`) for follow-up actions.

### Parameters

| Parameter | Description |
| --- | --- |
| `--authorized-admins` | Comma-separated local accounts allowed to remain in the sudo/admin group. |
| `--authorized-users` | Expected interactive (UID ≥ 1000) local accounts; other accounts are flagged. |
| `--sudo-group` | Name of the privileged group to audit. Defaults to `sudo`. |
| `--output-directory` | Directory where logs are written. Defaults to `/var/log/cyberpatriot`. |
| `--force-remediation` | Remove unauthorized sudo members and lock unexpected accounts automatically. |
| `--skip-fail2ban` | Skip installing/configuring Fail2Ban if competition rules forbid it. |

### Hardening actions performed

* Create a timestamped log in a protected directory for competition reporting.
* Refresh the APT package index and apply available upgrades.
* Install baseline security packages including `ufw`, `unattended-upgrades`, `auditd`, `libpam-pwquality`, and optionally `fail2ban`.
* Enable and tune unattended upgrades for daily security patching.
* Reset and enable the UFW firewall with default deny inbound rules while preserving SSH access.
* Configure Fail2Ban with a hardened SSH jail (unless skipped).
* Harden the OpenSSH daemon to block root logins, limit authentication attempts, and disable unnecessary forwarding features.
* Enforce password-complexity requirements via `pam_pwquality` and tighten `/etc/login.defs` settings.
* Audit interactive users and sudo-group members against the supplied allow-lists, optionally removing or locking unauthorized accounts.
* Purge insecure legacy network packages and disable common unnecessary services such as `avahi-daemon`, `rpcbind`, or `vsftpd` when present.
* Enable `auditd` with baseline rules that monitor identity-related files and privileged command execution.
* Clean package caches to reclaim disk space.

### Manual follow-up checklist

After the script completes:

* Review `/var/log/cyberpatriot` for warnings that call out unexpected accounts or services.
* Verify sudo access and group memberships against the competition readme.
* Inspect running services with `systemctl --type=service` and disable anything not required by the scenario.
* Confirm firewall rules meet the scoring checklist (e.g., allow required web or database ports if specified).
* Remove disallowed applications, browser extensions, and media files.
* Check `fail2ban-client status` (if enabled) and `/var/log/audit/` to ensure monitoring components are active.
