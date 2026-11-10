#!/usr/bin/env bash

# Read-only host triage for the reported unitstore indicators.
# No process killing, file deletion, package installation, or firewall changes.

set -u
set -o pipefail
export LC_ALL=C
umask 077

SCRIPT_FILE="$(readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
# Capture a nohup wrapper log before tee replaces stdout.
WRAPPER_LOG="$(readlink "/proc/$$/fd/1" 2>/dev/null || true)"
START_TS="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown)"
if [[ -d /root && -w /root ]]; then
    LOG_FILE="/root/unitstore-scan-${START_TS}.log"
    SUMMARY_FILE="/root/unitstore-scan-${START_TS}.summary"
    LATEST_SUMMARY="/root/unitstore-scan-latest.summary"
else
    LOG_FILE="./unitstore-scan-${START_TS}.log"
    SUMMARY_FILE="./unitstore-scan-${START_TS}.summary"
    LATEST_SUMMARY="./unitstore-scan-latest.summary"
fi

{
    printf 'Unitstore forensic scan summary\n'
    printf 'Started: %s\n' "$(date -Is 2>/dev/null || date)"
    printf 'Host: %s\n' "$(hostname 2>/dev/null || echo unknown)"
    printf '\n'
} >"$SUMMARY_FILE"
ln -sfn "$SUMMARY_FILE" "$LATEST_SUMMARY" 2>/dev/null || true

if command -v tee >/dev/null 2>&1; then
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

ALERTS=0
OBSERVED=0
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/unitstore-scan.XXXXXX" 2>/dev/null || echo "")"

cleanup() {
    [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
}
trap cleanup EXIT

section() {
    printf '\n===== %s =====\n' "$1"
}

info() {
    printf '[INFO] %s\n' "$1"
}

found() {
    OBSERVED=$((OBSERVED + 1))
    printf '[FOUND] %s\n' "$1"
    printf '[FOUND] %s\n' "$1" >>"$SUMMARY_FILE"
}

alert() {
    ALERTS=$((ALERTS + 1))
    printf '[ALERT] %s\n' "$1"
    printf '[ALERT] %s\n' "$1" >>"$SUMMARY_FILE"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

is_scan_artifact() {
    local candidate="$1" artifact
    for artifact in "$SCRIPT_FILE" "$LOG_FILE" "$SUMMARY_FILE" "$LATEST_SUMMARY" "$WRAPPER_LOG"; do
        if [[ -n "$artifact" && "$candidate" -ef "$artifact" ]]; then
            return 0
        fi
    done
    return 1
}

run_timeout() {
    local seconds="$1"
    shift
    if has_cmd timeout; then
        timeout --signal=TERM "${seconds}s" "$@"
    else
        "$@"
    fi
}

print_file_details() {
    local path="$1"
    stat --printf='  mode=%A owner=%U:%G size=%s mtime=%y\n' "$path" 2>/dev/null || true
    file "$path" 2>/dev/null || true
    sha256sum "$path" 2>/dev/null || true
    readlink -f "$path" 2>/dev/null || true
}

section "Host"
printf 'Host: %s\n' "$(hostname 2>/dev/null || echo unknown)"
printf 'Date: %s\n' "$(date -Is 2>/dev/null || date)"
printf 'User: %s\n' "$(id -un 2>/dev/null || echo unknown)"
printf 'Kernel: %s\n' "$(uname -a 2>/dev/null || echo unknown)"
printf 'Uptime: '
uptime 2>/dev/null || true
printf 'Log: %s\n' "$LOG_FILE"

if [[ ${EUID:-9999} -ne 0 ]]; then
    info "Not running as root; some checks may be incomplete."
fi

section "Known unitstore files"

KNOWN_FILES=(
    "/usr/lib/libunitstore.so"
    "/usr/lib/unitstore"
    "/usr/lib/unitstore/supervisor"
    "/usr/lib/configured/security_spool/events.spool"
)

for path in "${KNOWN_FILES[@]}"; do
    if [[ -e "$path" || -L "$path" ]]; then
        alert "Known suspicious path exists: $path"
        print_file_details "$path"
    fi
done

section "Filesystem name search"

name_hits=0
while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    if is_scan_artifact "$path"; then
        info "Scanner artifact, not an infection indicator: $path"
        continue
    fi
    name_hits=$((name_hits + 1))
    found "Filename match only; requires review: $path"
    print_file_details "$path"
done < <(
    find / -xdev \
        \( -iname '*unitstore*' -o -iname '*unit*store*' \) \
        -print 2>/dev/null
)

if [[ $name_hits -eq 0 ]]; then
    info "No other unitstore filename matches found on the root filesystem."
fi

section "Dynamic linker preload"

if [[ -f /etc/ld.so.preload ]]; then
    found "/etc/ld.so.preload exists"
    sed -n '1,120p' /etc/ld.so.preload

    if grep -Eiq '(^|/)(lib)?unitstore([^[:alnum:]_]|$)' \
        /etc/ld.so.preload 2>/dev/null; then
        alert "/etc/ld.so.preload contains unitstore"
    fi
else
    info "/etc/ld.so.preload does not exist."
fi

section "Exact process names"

for process_name in unitstore unitstoreinit unitstored; do
    pids="$(pgrep -x "$process_name" 2>/dev/null || true)"

    if [[ -n "$pids" ]]; then
        while read -r pid; do
            [[ -z "$pid" ]] && continue
            alert "Exact process found: name=$process_name pid=$pid"

            printf '  exe: '
            readlink -f "/proc/$pid/exe" 2>/dev/null || true
            printf '  cwd: '
            readlink -f "/proc/$pid/cwd" 2>/dev/null || true
            printf '  cmdline: '
            tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true
            echo
            printf '  parent: '
            awk '/^PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true
            echo "  mappings:"
            grep -Ei 'unitstore|deleted|memfd|/tmp|/dev/shm' \
                "/proc/$pid/maps" 2>/dev/null || true
        done <<< "$pids"
    else
        info "No exact process named $process_name."
    fi
done

section "Processes using deleted executables"

deleted_count=0
for proc in /proc/[0-9]*; do
    [[ -r "$proc/exe" ]] || continue
    exe="$(readlink "$proc/exe" 2>/dev/null || true)"

    if [[ "$exe" == *"(deleted)"* ]]; then
        pid="${proc##*/}"
        deleted_count=$((deleted_count + 1))
        found "PID $pid is running a deleted executable: $exe"
        printf '  cmdline: '
        tr '\0' ' ' <"$proc/cmdline" 2>/dev/null || true
        echo
    fi
done

if [[ $deleted_count -eq 0 ]]; then
    info "No running deleted executables found."
fi

section "systemd units"

if has_cmd systemctl; then
    unit_hits="$(
        systemctl list-unit-files --all --no-legend 2>/dev/null |
        awk 'tolower($1) ~ /^unit(store|storeinit)(@.*)?\.(service|socket|path|timer|target)$/ {
            print $1
        }'
    )"

    if [[ -n "$unit_hits" ]]; then
        while read -r unit; do
            [[ -z "$unit" ]] && continue
            alert "Suspicious systemd unit: $unit"
            systemctl cat "$unit" 2>/dev/null || true
        done <<< "$unit_hits"
    else
        info "No unitstore systemd unit found."
    fi
else
    info "systemctl is unavailable."
fi

section "Custom startup files"

for dir in /etc/systemd/system /run/systemd/system /etc/init.d; do
    [[ -d "$dir" ]] || continue
    echo "--- $dir ---"
    find "$dir" -maxdepth 2 -type f -printf \
        '%TY-%Tm-%Td %TH:%TM:%TS %m %u:%g %s %p\n' \
        2>/dev/null | sort
done

for path in /etc/rc.local /etc/profile /etc/bash.bashrc /etc/profile.d/*; do
    [[ -f "$path" ]] || continue
    found "Startup or shell file exists: $path"
    grep -Ev '^[[:space:]]*(#|$)' "$path" 2>/dev/null || true
done

section "Cron persistence"

if [[ -n "$TMP_DIR" ]] && crontab -l >"$TMP_DIR/root.cron" 2>/dev/null; then
    found "root crontab exists"
    cat "$TMP_DIR/root.cron"
else
    info "No root crontab."
fi

for path in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* \
            /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    [[ -f "$path" ]] || continue
    echo "--- $path ---"
    grep -Ev '^[[:space:]]*(#|$)' "$path" 2>/dev/null || true
done

section "SSH persistence and settings"

for path in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [[ -f "$path" ]] || continue
    found "SSH authorized_keys exists: $path"
    stat "$path" 2>/dev/null || true
    ssh-keygen -lf "$path" 2>/dev/null || true
done

if [[ -f /etc/ssh/sshd_config ]] && has_cmd sshd; then
    sshd -T 2>/dev/null |
        grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeysfile|allowusers|allowgroups' ||
        true
fi

section "SSH authentication log"

if has_cmd journalctl; then
    journalctl -u ssh --no-pager -S '30 days ago' 2>/dev/null |
        grep -Ei 'Accepted|Failed|Invalid user|authentication failure|Disconnected' |
        tail -300 || true
fi

section "Kernel modules and taint"

if has_cmd lsmod; then
    lsmod
else
    cat /proc/modules 2>/dev/null || true
fi

if lsmod 2>/dev/null |
    awk '$1 == "unitstore" || $1 == "unitstoreinit" {hit=1} END {exit !hit}'; then
    alert "unitstore-related kernel module is loaded"
else
    info "No unitstore-related kernel module found."
fi

printf 'kernel.tainted: '
cat /proc/sys/kernel/tainted 2>/dev/null || echo unavailable

section "Kernel log indicators"

if has_cmd dmesg; then
    dmesg --color=never 2>/dev/null |
        grep -Ei 'unitstore|unitstored|bpf_probe_write_user|rootkit|taint' ||
        info "No matching kernel log indicators."
fi

section "Package integrity"

if has_cmd dpkg; then
    package_changes="$(dpkg -V 2>/dev/null || true)"
    if [[ -n "$package_changes" ]]; then
        found "dpkg reported changed package files:"
        printf '%s\n' "$package_changes"
    else
        info "dpkg reported no changed package files."
    fi
fi

if has_cmd debsums; then
    info "Running debsums on installed packages."
    debsums -e 2>&1 || true
else
    info "debsums is not installed."
fi

section "SUID and SGID files"

find / -xdev -type f \
    \( -perm -4000 -o -perm -2000 \) \
    -printf '%m %u:%g %s %p\n' \
    2>/dev/null | sort

section "Network sockets"

if has_cmd ss; then
    echo "--- listening ---"
    ss -lntup 2>/dev/null || true
    echo "--- active TCP/UDP ---"
    ss -ntup 2>/dev/null || true
    echo "--- UNIX sockets ---"
    ss -xap 2>/dev/null | head -300 || true
fi

if has_cmd lsof; then
    echo "--- lsof network ---"
    lsof -nP -i 2>/dev/null || true
fi

section "IOC: suspected C2"

C2_IP="85.137.60.246"
C2_PORT="8443"
C2_DOMAIN="ferp.telegram-cn.net"

printf 'C2 IP: %s\n' "$C2_IP"
printf 'C2 port: %s/UDP\n' "$C2_PORT"
printf 'C2 domain: %s\n' "$C2_DOMAIN"

if has_cmd ss; then
    c2_socket_hits="$(
        ss -Huapn 2>/dev/null |
        awk -v endpoint="$C2_IP:$C2_PORT" '$5 == endpoint'
    )"

    if [[ -n "$c2_socket_hits" ]]; then
        alert "UDP peer exactly matches the reported C2 endpoint:"
        printf '%s\n' "$c2_socket_hits" | tee -a "$SUMMARY_FILE"
    else
        info "No UDP socket peer exactly matched the reported C2 endpoint."
    fi
fi

if has_cmd lsof; then
    c2_lsof_hits="$(
        lsof -nP -iUDP@"$C2_IP":"$C2_PORT" 2>/dev/null || true
    )"

    if [[ -n "$c2_lsof_hits" ]]; then
        alert "lsof found a process using the suspected C2 endpoint:"
        printf '%s\n' "$c2_lsof_hits"
    else
        info "lsof found no process using the suspected C2 endpoint."
    fi
fi

if has_cmd conntrack; then
    conntrack_hits="$(
        conntrack -L 2>/dev/null |
        grep -F -e "$C2_IP" -e "dport=$C2_PORT" -e "sport=$C2_PORT" ||
        true
    )"

    if [[ -n "$conntrack_hits" ]]; then
        found "conntrack contains the suspected C2 endpoint:"
        printf '%s\n' "$conntrack_hits"
    else
        info "conntrack found no suspected C2 endpoint."
    fi
fi

section "IOC: local text and configuration search"

IOC_SEARCH_DIRS=(
    "/etc"
    "/usr/local"
    "/opt"
    "/root"
    "/tmp"
    "/var/tmp"
    "/dev/shm"
    "/var/spool"
    "/var/lib/docker/containers"
)

for search_dir in "${IOC_SEARCH_DIRS[@]}"; do
    [[ -d "$search_dir" ]] || continue

    while IFS= read -r -d '' hit; do
        is_scan_artifact "$hit" && continue
        if grep -IlF -e "$C2_IP" -e "$C2_DOMAIN" -- "$hit" >/dev/null 2>&1; then
            found "IOC text match; content requires review: $hit"
            grep -nIF -m 20 -e "$C2_IP" -e "$C2_DOMAIN" -- "$hit" 2>/dev/null |
                tee -a "$SUMMARY_FILE" || true
        fi
    done < <(
        find "$search_dir" -xdev -type f \
            ! -name '*.log.*' ! -name '*.gz' ! -name '*.zip' \
            ! -name '*.jpg' ! -name '*.png' ! -name '*.iso' \
            ! -name '*.jar' ! -name '*.so' ! -name '*.pyc' \
            -print0 2>/dev/null
    )
done

section "IOC: logs and journal"

if has_cmd journalctl; then
    journal_ioc_hits="$(
        journalctl --no-pager --since '30 days ago' 2>/dev/null |
        grep -F -e "$C2_IP" -e "$C2_DOMAIN" ||
        true
    )"

    if [[ -n "$journal_ioc_hits" ]]; then
        found "Journal contains the suspected IOC:"
        printf '%s\n' "$journal_ioc_hits" | tail -300
    else
        info "Journal contains no matching IOC."
    fi
fi

for log_file in /var/log/auth.log /var/log/syslog /var/log/messages \
                /var/log/kern.log /var/log/daemon.log; do
    [[ -f "$log_file" ]] || continue
    if grep -F -n -e "$C2_IP" -e "$C2_DOMAIN" "$log_file" 2>/dev/null; then
        found "Log contains the suspected IOC: $log_file"
    fi
done

section "IOC: firewall and packet filter rules"

if has_cmd nft; then
    nft list ruleset 2>/dev/null |
        grep -F -e "$C2_IP" -e "$C2_PORT" -e "$C2_DOMAIN" ||
        info "nftables rules contain no matching IOC."
fi

if has_cmd iptables; then
    iptables-save 2>/dev/null |
        grep -F -e "$C2_IP" -e "$C2_PORT" -e "$C2_DOMAIN" ||
        info "iptables rules contain no matching IOC."
fi

section "eBPF programs"

if has_cmd bpftool; then
    bpftool prog show 2>&1 || true
    bpftool link show 2>&1 || true
else
    info "bpftool is not installed."
fi

section "Recent files in sensitive paths"

find /tmp /var/tmp /dev/shm /usr/local/bin /usr/local/sbin \
     /etc/systemd/system /lib/systemd/system \
     -xdev -type f -mtime -30 \
     -printf '%TY-%Tm-%Td %TH:%TM:%TS %m %u:%g %s %p\n' \
     2>/dev/null | sort -r | head -300

section "Optional rootkit tools"

if has_cmd chkrootkit; then
    info "Running chkrootkit (read-only checks)."
    run_timeout 300 chkrootkit 2>&1 || true
else
    info "chkrootkit is not installed."
fi

if has_cmd rkhunter; then
    info "Running rkhunter (read-only checks)."
    run_timeout 300 rkhunter --check --skip-keypress --rwo 2>&1 || true
else
    info "rkhunter is not installed."
fi

if has_cmd unhide; then
    info "Running unhide proc."
    run_timeout 300 unhide proc 2>&1 || true
else
    info "unhide is not installed."
fi

section "Summary"

{
    printf '\nFinished: %s\n' "$(date -Is 2>/dev/null || date)"
    printf 'Observed items: %s\n' "$OBSERVED"
    printf 'High-signal alerts: %s\n' "$ALERTS"
    printf 'Full log: %s\n' "$LOG_FILE"
    printf 'Summary: %s\n' "$SUMMARY_FILE"
    printf 'Latest summary: %s\n' "$LATEST_SUMMARY"
} >>"$SUMMARY_FILE"

printf '\n----- FINAL SUMMARY -----\n'
cat "$SUMMARY_FILE"

printf 'Observed items: %s\n' "$OBSERVED"
printf 'High-signal alerts: %s\n' "$ALERTS"
printf 'Log file: %s\n' "$LOG_FILE"
printf 'Summary file: %s\n' "$SUMMARY_FILE"
printf 'Latest summary: %s\n' "$LATEST_SUMMARY"

if [[ $ALERTS -gt 0 ]]; then
    printf '[RESULT] Suspicious indicators were detected; preserve the log and continue with offline triage.\n'
    printf '[RESULT] Review the alert lines above first; the full log is only for evidence.\n'
    exit 1
else
    printf '[RESULT] No known unitstore indicators were confirmed.\n'
    printf '[RESULT] This does not prove the host is clean.\n'
    exit 0
fi
