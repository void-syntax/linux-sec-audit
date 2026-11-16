#!/usr/bin/env bash
set -uo pipefail

# ==========================================
# 1. CONSTANTS & SETTINGS
# ==========================================
VERSION="0.1.0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
WARN=0
FAIL=0

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
usage() {
    cat <<EOF
Linux Security Audit Tool v${VERSION}

Usage: $0 [OPTIONS]

Options:
  -h, --help       Show this help message and exit
  -v, --version    Show version information
      --no-color   Disable colored terminal output
EOF
}

log_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASS++)); }
log_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
log_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAIL++)); }
log_skip() { echo -e "  ${BLUE}[SKIP]${NC} $1"; }

# ==========================================
# 3. CLI ARGUMENT PARSER
# ==========================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                echo "sec-audit v${VERSION}"
                exit 0
                ;;
            --no-color)
                RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
                shift
                ;;
            *)
                echo "Error: Unknown option '$1'" >&2
                usage
                exit 1
                ;;
        esac
    done
}

# ==========================================
# 4. AUDIT MODULES
# ==========================================

# --- Module 1: Critical File Permissions ---
check_permissions() {
    echo -e "\n${CYAN}[*] Checking Critical File Permissions${NC}"

    if [[ -f /etc/passwd ]]; then
        local passwd_perm
        passwd_perm=$(stat -c "%a" /etc/passwd)
        if [[ "$passwd_perm" == "644" ]]; then
            log_pass "/etc/passwd has secure permissions (644)"
        else
            log_fail "/etc/passwd has insecure permissions: $passwd_perm (expected 644)"
        fi
    fi

    if [[ $EUID -ne 0 ]]; then
        log_skip "Checking /etc/shadow permissions requires root privileges"
    elif [[ -f /etc/shadow ]]; then
        local shadow_perm
        shadow_perm=$(stat -c "%a" /etc/shadow)
        if [[ "$shadow_perm" == "640" || "$shadow_perm" == "600" || "$shadow_perm" == "0" ]]; then
            log_pass "/etc/shadow has secure permissions ($shadow_perm)"
        else
            log_fail "/etc/shadow has insecure permissions: $shadow_perm (expected 600 or 640)"
        fi
    fi
}

# --- Module 2: User Accounts ---
check_users() {
    echo -e "\n${CYAN}[*] Checking User Accounts${NC}"

    local root_users
    root_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
    if [[ "$root_users" == "root" ]]; then
        log_pass "Only 'root' user has UID 0"
    else
        root_users=$(echo "$root_users" | tr '\n' ' ')
        log_fail "Multiple UID 0 accounts detected: $root_users"
    fi

    if [[ $EUID -ne 0 ]]; then
        log_skip "Checking for empty passwords in /etc/shadow requires root"
    else
        local empty_pass
        empty_pass=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
        if [[ -z "$empty_pass" ]]; then
            log_pass "No accounts with empty passwords found"
        else
            empty_pass=$(echo "$empty_pass" | tr '\n' ' ')
            log_fail "Accounts with EMPTY passwords detected: $empty_pass"
        fi
    fi
}

# --- Module 3: SSH Daemon Configuration ---
check_ssh() {
    echo -e "\n${CYAN}[*] Checking SSH Configuration${NC}"
    local ssh_conf="/etc/ssh/sshd_config"

    if [[ ! -f "$ssh_conf" ]]; then
        log_skip "File $ssh_conf not found (SSH server not installed)"
        return
    fi

    local root_login
    root_login=$(grep -Ei "^PermitRootLogin" "$ssh_conf" | awk '{print $2}' | tail -n 1)
    if [[ "$root_login" == "no" || "$root_login" == "prohibit-password" ]]; then
        log_pass "SSH: Direct root password login disabled ($root_login)"
    else
        log_fail "SSH: PermitRootLogin is not restricted (value: ${root_login:-default})"
    fi

    local pass_auth
    pass_auth=$(grep -Ei "^PasswordAuthentication" "$ssh_conf" | awk '{print $2}' | tail -n 1)
    if [[ "$pass_auth" == "no" ]]; then
        log_pass "SSH: Password authentication disabled (key-only)"
    else
        log_warn "SSH: Password authentication is enabled (value: ${pass_auth:-yes})"
    fi

    local empty_pw
    empty_pw=$(grep -Ei "^PermitEmptyPasswords" "$ssh_conf" | awk '{print $2}' | tail -n 1)
    if [[ "$empty_pw" == "no" || -z "$empty_pw" ]]; then
        log_pass "SSH: Empty passwords are prohibited"
    else
        log_fail "SSH: Empty passwords are allowed (PermitEmptyPasswords yes)"
    fi
}

# --- Module 4: Kernel Hardening (Sysctl) ---
check_kernel() {
    echo -e "\n${CYAN}[*] Checking Kernel Parameters (Sysctl)${NC}"

    local aslr
    aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "0")
    if [[ "$aslr" == "2" ]]; then
        log_pass "ASLR is fully enabled (randomize_va_space = 2)"
    else
        log_fail "ASLR is weakened or disabled (current value: $aslr)"
    fi

    local dmesg_restrict
    dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "0")
    if [[ "$dmesg_restrict" == "1" ]]; then
        log_pass "Unprivileged access to kernel logs (dmesg) is restricted"
    else
        log_warn "Regular users can read kernel logs (dmesg_restrict = 0)"
    fi

    local kptr_restrict
    kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "0")
    if [[ "$kptr_restrict" == "1" || "$kptr_restrict" == "2" ]]; then
        log_pass "Kernel pointers are hidden (kptr_restrict = $kptr_restrict)"
    else
        log_warn "Kernel symbols in /proc/kallsyms are exposed (kptr_restrict = 0)"
    fi
}

# --- Module 5: Network & Firewall ---
check_network() {
    echo -e "\n${CYAN}[*] Checking Network & Firewall${NC}"

    local syn_cookies
    syn_cookies=$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo "0")
    if [[ "$syn_cookies" == "1" ]]; then
        log_pass "SYN flood protection is active (tcp_syncookies = 1)"
    else
        log_fail "SYN flood protection is disabled (tcp_syncookies = 0)"
    fi

    local ip_fwd
    ip_fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    if [[ "$ip_fwd" == "0" ]]; then
        log_pass "IP Forwarding is disabled (ip_forward = 0)"
    else
        log_warn "IP Forwarding is enabled (1) — expected only for routers/VPNs"
    fi

    if command -v ufw &>/dev/null; then
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            log_pass "UFW firewall is active"
        else
            log_fail "UFW firewall is installed but inactive"
        fi
    elif systemctl is-active --quiet firewalld 2>/dev/null; then
        log_pass "firewalld service is active"
    elif systemctl is-active --quiet nftables 2>/dev/null; then
        log_pass "nftables service is active"
    else
        log_warn "No active firewall detected (ufw/firewalld/nftables)"
    fi

    if command -v ss &>/dev/null; then
        local open_ports
        open_ports=$(ss -tuln | awk 'NR>1 && ($5 ~ /^0\.0\.0\.0:/ || $5 ~ /^\[::\]:/ || $5 ~ /^\*:/) {print $5}' | sed 's/.*://' | sort -nu | tr '\n' ' ')
        if [[ -z "$open_ports" ]]; then
            log_pass "No ports listening on all network interfaces (0.0.0.0 / ::)"
        else
            log_warn "Exposed listening ports (0.0.0.0 / ::): $open_ports"
        fi
    fi
}

# ==========================================
# 5. ENTRY POINT
# ==========================================
main() {
    parse_args "$@"

    echo "================================================"
    echo " Linux Security Audit v${VERSION}"
    echo " Hostname: $(hostname) | Kernel: $(uname -r)"
    echo "================================================"

    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[!] Running without root. Some checks will be skipped.${NC}"
    fi

    check_permissions
    check_users
    check_ssh
    check_kernel
    check_network

    local total=$((PASS + WARN + FAIL))
    local score=0
    if [[ $total -gt 0 ]]; then
        score=$(( (PASS * 100) / total ))
    fi

    echo -e "\n================================================"
    echo -e " Summary: ${GREEN}PASS: $PASS${NC} | ${YELLOW}WARN: $WARN${NC} | ${RED}FAIL: $FAIL${NC}"
    echo -e " Hardening Score: ${CYAN}${score}%${NC}"
    echo "================================================"
}

main "$@"
