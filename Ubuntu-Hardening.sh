#!/usr/bin/env bash
# shellcheck disable=SC2312
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
umask 077

AUTHORIZED_ADMINS=("root")
AUTHORIZED_USERS=()
AUTHORIZED_SUDO_GROUP="sudo"
OUTPUT_DIR="/var/log/cyberpatriot"
FORCE_REMEDIATION=0
SKIP_FAIL2BAN=0
SKIP_SNAP=0
SKIP_DESKTOP=0
LOG_FILE=""
declare -a WARNINGS=()

usage() {
    cat <<'USAGE'
Usage: Ubuntu-Hardening.sh [options]

Options:
  --authorized-admins "user1,user2"   Comma-separated list of accounts allowed in the sudo/admin group (default: root only).
  --authorized-users "user1,user2"    Comma-separated list of interactive local accounts expected to exist (UID >= 1000).
  --sudo-group GROUP                  Name of the administrative group to audit (default: sudo).
  --output-directory PATH             Directory for logs (default: /var/log/cyberpatriot).
  --force-remediation                 Automatically remove or disable unauthorized accounts from privileged groups.
  --skip-fail2ban                     Do not configure Fail2Ban even if installed.
  --skip-snap                         Skip snap refresh and policy configuration.
  --skip-desktop-hardening            Skip desktop environment tweaks (useful on server-only images).
  -h, --help                          Display this help message.
USAGE
}

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

parse_csv_list() {
    local -n ref="$1"
    local csv="$2"
    local i trimmed
    IFS=',' read -ra ref <<< "$csv"
    for i in "${!ref[@]}"; do
        trimmed="$(trim "${ref[$i]}")"
        if [[ -n "$trimmed" ]]; then
            ref[$i]="$trimmed"
        else
            unset 'ref[$i]'
        fi
    done
    if (( ${#ref[@]} > 0 )); then
        ref=("${ref[@]}")
    else
        ref=()
    fi
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --authorized-admins)
                [[ $# -lt 2 ]] && { echo "Missing value for --authorized-admins" >&2; exit 1; }
                parse_csv_list AUTHORIZED_ADMINS "$2"
                shift 2
                ;;
            --authorized-users)
                [[ $# -lt 2 ]] && { echo "Missing value for --authorized-users" >&2; exit 1; }
                parse_csv_list AUTHORIZED_USERS "$2"
                shift 2
                ;;
            --sudo-group)
                [[ $# -lt 2 ]] && { echo "Missing value for --sudo-group" >&2; exit 1; }
                AUTHORIZED_SUDO_GROUP="$2"
                shift 2
                ;;
            --output-directory)
                [[ $# -lt 2 ]] && { echo "Missing value for --output-directory" >&2; exit 1; }
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --force-remediation)
                FORCE_REMEDIATION=1
                shift
                ;;
            --skip-fail2ban)
                SKIP_FAIL2BAN=1
                shift
                ;;
            --skip-snap)
                SKIP_SNAP=1
                shift
                ;;
            --skip-desktop-hardening)
                SKIP_DESKTOP=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                usage
                exit 1
                ;;
        esac
    done
}

ensure_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local entry="[$timestamp] [$level] $message"
    echo "$entry"
    if [[ -n "$LOG_FILE" ]]; then
        printf '%s\n' "$entry" >> "$LOG_FILE"
    fi
}

log_info() {
    log "INFO" "$@"
}

log_warn() {
    log "WARN" "$@"
    WARNINGS+=("$*")
}

log_error() {
    log "ERROR" "$@"
    WARNINGS+=("$*")
}

run_step() {
    local description="$1"
    shift
    log_info "Starting: $description"
    local errexit_set=0
    if [[ $- == *e* ]]; then
        errexit_set=1
        set +e
    fi
    "$@"
    local status=$?
    if (( errexit_set )); then
        set -e
    fi
    if (( status == 0 )); then
        log_info "Completed: $description"
    else
        log_error "Failed: $description (exit code $status)"
    fi
    return 0
}

initialize_logging() {
    install -d -m 700 "$OUTPUT_DIR"
    local timestamp
    timestamp="$(date '+%Y%m%d_%H%M%S')"
    LOG_FILE="$OUTPUT_DIR/ubuntu_hardening_${timestamp}.log"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    log_info "Log file initialized at $LOG_FILE"
}

array_contains() {
    local -n arr="$1"
    local seek="$2"
    local item
    for item in "${arr[@]:-}"; do
        if [[ "$item" == "$seek" ]]; then
            return 0
        fi
    done
    return 1
}

update_package_index() {
    apt-get update
}

upgrade_packages() {
    apt-get -y upgrade
}

install_security_packages() {
    local packages=(
        "ufw"
        "unattended-upgrades"
        "apt-listchanges"
        "apt-transport-https"
        "debsums"
        "needrestart"
        "libpam-pwquality"
        "auditd"
        "apparmor"
        "apparmor-utils"
        "dconf-cli"
    )
    if (( SKIP_FAIL2BAN == 0 )); then
        packages+=("fail2ban")
    fi
    apt-get install -y "${packages[@]}"
}

configure_unattended_upgrades() {
    local distro_codename
    distro_codename="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
    local auto_conf="/etc/apt/apt.conf.d/20auto-upgrades"
    cat <<'EOF2' > "$auto_conf"
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF2
    chmod 644 "$auto_conf"

    local unattended_conf="/etc/apt/apt.conf.d/51unattended-upgrades-cyberpatriot"
    cat <<EOF2 > "$unattended_conf"
Unattended-Upgrade::Origins-Pattern {
        "o=Ubuntu,a=${distro_codename}-security";
        "o=Ubuntu,a=${distro_codename}-updates";
        "o=UbuntuESMApps";
        "o=UbuntuESMInfra";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF2
    chmod 644 "$unattended_conf"

    if command -v dpkg-reconfigure >/dev/null 2>&1; then
        dpkg-reconfigure -f noninteractive unattended-upgrades
    fi
}

configure_ufw() {
    if ! command -v ufw >/dev/null 2>&1; then
        log_warn "ufw is not installed; skipping firewall configuration."
        return 0
    fi

    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    if systemctl is-enabled ssh >/dev/null 2>&1 || systemctl status ssh >/dev/null 2>&1; then
        ufw allow OpenSSH
    elif command -v sshd >/dev/null 2>&1; then
        ufw allow 22/tcp
    fi
    ufw logging medium
    ufw --force enable
}

configure_fail2ban() {
    if (( SKIP_FAIL2BAN == 1 )); then
        log_warn "Fail2Ban configuration skipped by request."
        return 0
    fi

    if ! command -v fail2ban-client >/dev/null 2>&1; then
        log_warn "Fail2Ban is not installed; skipping configuration."
        return 0
    fi

    local jail_dir="/etc/fail2ban/jail.d"
    install -d -m 755 "$jail_dir"
    local jail_file="$jail_dir/cyberpatriot-hardening.conf"
    cat <<'EOF2' > "$jail_file"
[DEFAULT]
bantime = 15m
findtime = 10m
maxretry = 5
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = systemd
EOF2
    chmod 640 "$jail_file"
    systemctl enable --now fail2ban
    systemctl restart fail2ban
}

set_assignment_value() {
    local file="$1" key="$2" value="$3"
    if grep -Eq "^\s*${key}\s*=" "$file"; then
        sed -i "s|^\s*${key}\s*=.*|${key} = ${value}|" "$file"
    else
        printf '%s = %s\n' "$key" "$value" >> "$file"
    fi
}

set_space_value() {
    local file="$1" key="$2" value="$3"
    if grep -Eq "^\s*${key}\\b" "$file"; then
        sed -i "s|^\s*${key}\\b.*|${key}\t${value}|" "$file"
    else
        printf '%s\t%s\n' "$key" "$value" >> "$file"
    fi
}

enforce_password_policy() {
    local pam_file="/etc/pam.d/common-password"
    if [[ ! -f "$pam_file" ]]; then
        log_warn "Unable to locate $pam_file; skipping password policy enforcement."
        return 0
    fi

    if grep -Eq '^\s*password\s+requisite\s+pam_pwquality\.so' "$pam_file"; then
        sed -i 's#^\s*password\s\+requisite\s\+pam_pwquality\.so.*#password    requisite     pam_pwquality.so retry=3 enforce_for_root#g' "$pam_file"
    else
        sed -i '1i password    requisite     pam_pwquality.so retry=3 enforce_for_root' "$pam_file"
    fi

    local pwquality_conf="/etc/security/pwquality.conf"
    touch "$pwquality_conf"
    chmod 600 "$pwquality_conf"
    set_assignment_value "$pwquality_conf" "minlen" "12"
    set_assignment_value "$pwquality_conf" "dcredit" "-1"
    set_assignment_value "$pwquality_conf" "ucredit" "-1"
    set_assignment_value "$pwquality_conf" "lcredit" "-1"
    set_assignment_value "$pwquality_conf" "ocredit" "-1"
    set_assignment_value "$pwquality_conf" "minclass" "4"
    set_assignment_value "$pwquality_conf" "retry" "3"
}

update_login_defs() {
    local login_defs="/etc/login.defs"
    if [[ ! -f "$login_defs" ]]; then
        log_warn "Unable to locate $login_defs; skipping login policy update."
        return 0
    fi

    set_space_value "$login_defs" "PASS_MAX_DAYS" "90"
    set_space_value "$login_defs" "PASS_MIN_DAYS" "10"
    set_space_value "$login_defs" "PASS_WARN_AGE" "7"
    set_space_value "$login_defs" "LOGIN_RETRIES" "5"
    set_space_value "$login_defs" "LOGIN_TIMEOUT" "60"
}

harden_ssh() {
    if ! command -v sshd >/dev/null 2>&1; then
        log_warn "OpenSSH server is not installed; skipping SSH hardening."
        return 0
    fi

    local conf_dir="/etc/ssh/sshd_config.d"
    install -d -m 755 "$conf_dir"
    local conf_file="$conf_dir/99-cyberpatriot-hardening.conf"
    cat <<'EOF2' > "$conf_file"
# CyberPatriot competition hardening defaults
PermitRootLogin no
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
AllowTcpForwarding no
EOF2
    chmod 600 "$conf_file"
    systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || log_warn "Unable to reload the SSH daemon automatically."
}

audit_interactive_users() {
    if (( ${#AUTHORIZED_USERS[@]} == 0 )); then
        log_warn "No authorized user list supplied; skipping interactive account whitelist check."
        return 0
    fi

    local unexpected=()
    local user uid shell
    while IFS=':' read -r user _ uid _ _ _ shell; do
        if (( uid >= 1000 )) && [[ "$user" != "nobody" ]]; then
            if ! array_contains AUTHORIZED_USERS "$user"; then
                unexpected+=("$user")
            fi
        fi
    done < /etc/passwd

    local account
    if (( ${#unexpected[@]} > 0 )); then
        for account in "${unexpected[@]}"; do
            log_warn "Unexpected interactive account detected: $account"
            if (( FORCE_REMEDIATION == 1 )); then
                if passwd -S "$account" >/dev/null 2>&1 && passwd -S "$account" | grep -q '\sL\s'; then
                    log_info "Account $account is already locked."
                elif passwd -l "$account" >/dev/null 2>&1; then
                    log_info "Account $account locked."
                else
                    log_error "Failed to lock account $account."
                fi
            fi
        done
    else
        log_info "All interactive accounts are authorized."
    fi

    local expected
    for expected in "${AUTHORIZED_USERS[@]}"; do
        if ! id "$expected" >/dev/null 2>&1; then
            log_warn "Authorized interactive account missing: $expected"
        fi
    done
}

audit_admin_group() {
    if [[ -z "$AUTHORIZED_SUDO_GROUP" ]]; then
        log_warn "No sudo group specified; skipping admin group audit."
        return 0
    fi

    local group_entry
    if ! group_entry="$(getent group "$AUTHORIZED_SUDO_GROUP")"; then
        log_warn "Group $AUTHORIZED_SUDO_GROUP not found."
        return 0
    fi

    local members
    members="$(echo "$group_entry" | awk -F: '{print $4}')"
    IFS=',' read -ra members <<< "$members"

    local member
    for member in "${members[@]}"; do
        [[ -z "$member" ]] && continue
        if ! array_contains AUTHORIZED_ADMINS "$member"; then
            log_warn "Unauthorized administrator in $AUTHORIZED_SUDO_GROUP: $member"
            if (( FORCE_REMEDIATION == 1 )); then
                if gpasswd -d "$member" "$AUTHORIZED_SUDO_GROUP" >/dev/null 2>&1; then
                    log_info "Removed $member from $AUTHORIZED_SUDO_GROUP."
                else
                    log_error "Failed to remove $member from $AUTHORIZED_SUDO_GROUP."
                fi
            fi
        fi
    done

    local admin
    for admin in "${AUTHORIZED_ADMINS[@]}"; do
        if [[ "$admin" == "root" ]]; then
            continue
        fi
        if ! id "$admin" >/dev/null 2>&1; then
            log_warn "Authorized administrator account missing: $admin"
        fi
    done
}

remove_insecure_packages() {
    local packages=(telnet rsh-client rsh-server talk xinetd nis tftp tftpd inetutils-inetd vsftpd ftp rlogin rcp rwho rusers remmina vino gnome-remote-desktop)
    local to_remove=()
    local pkg
    for pkg in "${packages[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            to_remove+=("$pkg")
        fi
    done
    if (( ${#to_remove[@]} > 0 )); then
        apt-get purge -y "${to_remove[@]}"
    else
        log_info "No insecure desktop or network packages found to purge."
    fi
}

disable_insecure_services() {
    local services=(avahi-daemon cups nfs-server rpcbind vsftpd bluetooth smbd nmbd telnet.socket tftp.service gdm-vino.service vino-server.service)
    local svc
    for svc in "${services[@]}"; do
        if systemctl list-unit-files "$svc" >/dev/null 2>&1 || systemctl list-unit-files "$svc.service" >/dev/null 2>&1; then
            if systemctl is-enabled "$svc" >/dev/null 2>&1; then
                systemctl disable --now "$svc"
                log_info "Disabled $svc."
            elif systemctl is-enabled "$svc.service" >/dev/null 2>&1; then
                systemctl disable --now "$svc.service"
                log_info "Disabled $svc.service."
            fi
        fi
    done
}

cleanup_packages() {
    apt-get autoremove -y
    apt-get autoclean -y
}

reload_audit_rules() {
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load
    elif systemctl restart auditd >/dev/null 2>&1; then
        return 0
    else
        log_warn "Unable to reload auditd rules automatically; please reload manually."
    fi
}

enable_auditd() {
    if ! command -v auditctl >/dev/null 2>&1; then
        log_warn "auditd is not installed; skipping auditing configuration."
        return 0
    fi

    local rules_dir="/etc/audit/rules.d"
    install -d -m 755 "$rules_dir"
    local rules_file="$rules_dir/99-cyberpatriot.rules"
    cat <<'EOF2' > "$rules_file"
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /var/log/auth.log -p wa -k auth
-a always,exit -F arch=b64 -S execve -C uid!=euid -k identity
-a always,exit -F arch=b64 -S setuid,setgid -k privileged
EOF2
    chmod 640 "$rules_file"
    systemctl enable --now auditd
    reload_audit_rules
}

configure_snap_updates() {
    if (( SKIP_SNAP == 1 )); then
        log_warn "Snap refresh skipped by request."
        return 0
    fi
    if ! command -v snap >/dev/null 2>&1; then
        log_warn "snapd is not installed; skipping snap refresh."
        return 0
    fi

    snap set system refresh.timer="00:00-04:00/weekly"
    snap set system refresh.retain=2
    snap refresh
}

set_ini_option() {
    local file="$1" section="$2" key="$3" value="$4"
    if ! command -v python3 >/dev/null 2>&1; then
        log_warn "python3 unavailable to manage $file; please adjust $section/$key manually."
        return 0
    fi
    python3 - "$file" "$section" "$key" "$value" <<'PYTHON'
import configparser
import os
import sys

path, section, key, value = sys.argv[1:5]
config = configparser.ConfigParser()
config.optionxform = str
if os.path.exists(path):
    config.read(path)
if section not in config:
    config[section] = {}
config[section][key] = value
with open(path, 'w', encoding='utf-8') as fh:
    config.write(fh)
PYTHON
    chmod 644 "$file"
}

disable_gdm_guest() {
    local conf="/etc/gdm3/custom.conf"
    local conf_dir
    conf_dir="$(dirname "$conf")"
    if [[ ! -d "$conf_dir" ]]; then
        log_warn "GDM not installed; skipping guest login hardening."
        return 0
    fi
    set_ini_option "$conf" "daemon" "AllowGuest" "false"
    set_ini_option "$conf" "daemon" "AutomaticLoginEnable" "false"
}

disable_lightdm_guest() {
    local conf_dir="/etc/lightdm/lightdm.conf.d"
    if [[ -d "$conf_dir" ]]; then
        local conf_file="$conf_dir/50-no-guest.conf"
        cat <<'EOF2' > "$conf_file"
[Seat:*]
allow-guest=false
autologin-user=
EOF2
        chmod 644 "$conf_file"
    fi
}

configure_gnome_lockdown() {
    local dconf_dir="/etc/dconf/db/local.d"
    install -d -m 755 "$dconf_dir"
    local settings_file="$dconf_dir/00-cyberpatriot"
    cat <<'EOF2' > "$settings_file"
[org/gnome/desktop/screensaver]
lock-enabled=true
idle-activation-enabled=true

[org/gnome/desktop/session]
idle-delay=uint32 300

[org/gnome/settings-daemon/plugins/power]
sleep-inactive-ac-timeout=900
sleep-inactive-ac-type='blank'
EOF2
    chmod 644 "$settings_file"
    if command -v dconf >/dev/null 2>&1; then
        dconf update
    else
        log_warn "dconf command not available; GNOME lockdown settings written but database not refreshed."
    fi
}

harden_desktop_environment() {
    if (( SKIP_DESKTOP == 1 )); then
        log_warn "Desktop environment hardening skipped by request."
        return 0
    fi

    if [[ ! -d /usr/share/xsessions && ! -d /usr/share/wayland-sessions ]]; then
        log_warn "No desktop sessions detected; skipping desktop-specific hardening."
        return 0
    fi

    disable_gdm_guest
    disable_lightdm_guest
    configure_gnome_lockdown
}

enable_apparmor() {
    if systemctl list-unit-files apparmor.service >/dev/null 2>&1; then
        systemctl enable --now apparmor
    else
        log_warn "AppArmor service not available on this system."
        return 0
    fi

    if command -v aa-status >/dev/null 2>&1; then
        local summary
        summary="$(aa-status --summary 2>/dev/null)"
        if [[ -n "$summary" ]]; then
            log_info "AppArmor status: $summary"
        fi
    fi
}

auditing_summary() {
    if (( ${#WARNINGS[@]} > 0 )); then
        log_info "Hardening completed with ${#WARNINGS[@]} warning(s). Review the log for details."
    else
        log_info "Hardening completed without warnings."
    fi
    log_info "Full log: $LOG_FILE"
}

summarize_findings() {
    log_info "=============================================="
    auditing_summary
    if (( ${#WARNINGS[@]} > 0 )); then
        for warning in "${WARNINGS[@]}"; do
            log_info " - $warning"
        done
    fi
    log_info "=============================================="
}

record_system_overview() {
    local hostname
    hostname="$(hostname 2>/dev/null || echo "unknown")"
    log_info "Hostname: $hostname"

    if command -v lsb_release >/dev/null 2>&1; then
        log_info "Distribution: $(lsb_release -ds)"
    elif [[ -r /etc/os-release ]]; then
        log_info "Distribution: $(. /etc/os-release && echo "$PRETTY_NAME")"
    fi

    log_info "Kernel: $(uname -sr)"
    log_info "Force remediation: $([[ $FORCE_REMEDIATION -eq 1 ]] && echo enabled || echo disabled)"
    log_info "Fail2Ban configuration: $([[ $SKIP_FAIL2BAN -eq 1 ]] && echo skipped || echo enabled)"
    log_info "Snap refresh: $([[ $SKIP_SNAP -eq 1 ]] && echo skipped || echo enabled)"
    log_info "Desktop hardening: $([[ $SKIP_DESKTOP -eq 1 ]] && echo skipped || echo enabled)"
    log_info "Authorized admins: ${AUTHORIZED_ADMINS[*]:-(none)}"
    if (( ${#AUTHORIZED_USERS[@]} > 0 )); then
        log_info "Authorized users: ${AUTHORIZED_USERS[*]}"
    else
        log_info "Authorized users: (not specified)"
    fi
}

main() {
    parse_arguments "$@"
    ensure_root
    initialize_logging
    record_system_overview

    run_step "Updating APT package index" update_package_index
    run_step "Upgrading installed packages" upgrade_packages
    run_step "Installing Ubuntu security packages" install_security_packages
    run_step "Configuring unattended upgrades" configure_unattended_upgrades
    run_step "Configuring UFW firewall" configure_ufw
    run_step "Configuring Fail2Ban" configure_fail2ban
    run_step "Hardening SSH daemon" harden_ssh
    run_step "Enforcing password quality policies" enforce_password_policy
    run_step "Updating login.defs controls" update_login_defs
    run_step "Auditing interactive users" audit_interactive_users
    run_step "Auditing administrator group" audit_admin_group
    run_step "Enabling AppArmor enforcement" enable_apparmor
    run_step "Configuring snap updates" configure_snap_updates
    run_step "Applying desktop environment hardening" harden_desktop_environment
    run_step "Removing insecure packages" remove_insecure_packages
    run_step "Disabling insecure services" disable_insecure_services
    run_step "Enabling auditd monitoring" enable_auditd
    run_step "Cleaning package cache" cleanup_packages

    summarize_findings
}

main "$@"
