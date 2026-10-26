#!/usr/bin/env bash
# ==============================================================================
# OpenWrt ACME Client & Dnsmasq Dynamic Automation Configurator
# Script: run_openwrt_config.sh
#
# Automates the configuration of an OpenWrt router to issue and renew ACME
# certificates against a local ACME CA server using dynamic dnsmasq DNS-01 hooks.
# ==============================================================================

set -o pipefail

# ------------------------------------------------------------------------------
# ANSI Colors & UI Helpers
# ------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Resolve repository and workspace paths
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="${REPO_DIR}/.acme_workspace"
LOGS_DIR="${WORKSPACE_DIR}/logs"
CONFIG_FILE="${REPO_DIR}/.openwrt_config.env"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${LOGS_DIR}/openwrt_config_${TIMESTAMP}.log"

mkdir -p "${WORKSPACE_DIR}" "${LOGS_DIR}"

# (Logging redirection will be enabled after parsing CLI options)

log_header() {
    echo -e "\n${BOLD}${CYAN}======================================================================${NC}"
    echo -e "${BOLD}${WHITE}  $1${NC}"
    echo -e "${BOLD}${CYAN}======================================================================${NC}"
}

log_step() {
    echo -e "\n${BOLD}${BLUE}==>${NC} ${BOLD}${WHITE}$1${NC}"
}

log_info() {
    echo -e "  ${CYAN}[i]${NC} $1"
}

log_success() {
    echo -e "  ${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "  ${YELLOW}[!]${NC} ${YELLOW}$1${NC}"
}

log_error() {
    echo -e "  ${RED}[✗]${NC} ${RED}$1${NC}" >&2
}

# ------------------------------------------------------------------------------
# SSH ControlMaster & Cleanup Trap
# ------------------------------------------------------------------------------
SSH_CONTROL_DIR="/tmp/openwrt_ssh_${UID}"
SSH_CONTROL_PATH="${SSH_CONTROL_DIR}/ctl_%r@%h:%p"
mkdir -p "${SSH_CONTROL_DIR}" 2>/dev/null || true
chmod 700 "${SSH_CONTROL_DIR}" 2>/dev/null || true

cleanup() {
    local exit_code=$?
    if [[ -S "${SSH_CONTROL_PATH}" ]] 2>/dev/null; then
        ssh -O exit -o "ControlPath=${SSH_CONTROL_PATH}" "${ROUTER_USER}@${ROUTER_HOST}" >/dev/null 2>&1 || true
    fi
    rm -f "${SSH_CONTROL_DIR}"/ctl_* 2>/dev/null || true
    exit "${exit_code}"
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------------------
# Git Ignore Enforcement for Config File
# ------------------------------------------------------------------------------
ensure_gitignored() {
    local target_file="$1"
    if git -C "${REPO_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        local rel_path
        rel_path="$(realpath --relative-to="${REPO_DIR}" "${target_file}" 2>/dev/null || basename "${target_file}")"
        if ! git -C "${REPO_DIR}" check-ignore -q "${target_file}" 2>/dev/null; then
            echo "${rel_path}" >> "${REPO_DIR}/.gitignore"
            log_info "Added ${rel_path} to .gitignore"
        fi
    fi
}

# ------------------------------------------------------------------------------
# Load Cached State
# ------------------------------------------------------------------------------
ROUTER_HOST="192.168.1.1"
ROUTER_USER="root"
ROUTER_PORT="22"
CA_URL="https://your-local-ca.lan/acme/directory"
LAN_DOMAIN=""
ACCOUNT_EMAIL=""
CA_CERT_PATH=""
DRY_RUN=false
ASSUME_YES=false
RENEW_ONLY=false

if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${CONFIG_FILE}"
fi

save_config() {
    ensure_gitignored "${CONFIG_FILE}"
    cat << EOF > "${CONFIG_FILE}"
# OpenWrt ACME Client Automation Saved State
ROUTER_HOST="${ROUTER_HOST}"
ROUTER_USER="${ROUTER_USER}"
ROUTER_PORT="${ROUTER_PORT}"
CA_URL="${CA_URL}"
LAN_DOMAIN="${LAN_DOMAIN}"
ACCOUNT_EMAIL="${ACCOUNT_EMAIL}"
CA_CERT_PATH="${CA_CERT_PATH}"
EOF
}

# ------------------------------------------------------------------------------
# CLI Arguments & Help
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Configures ACME client and dynamic dnsmasq DNS-01 validation on OpenWrt routers.

Options:
  -d, --dry-run      Simulate all operations without modifying the OpenWrt router
  -y, --yes          Accept disclaimer and liability terms without interactive prompt
  -r, --renew-only   Only deploy/protect renewal check script, cron schedule, and sysupgrade backup
  -h, --help         Show this help message and exit
  --host <HOST>      OpenWrt router IP or hostname (default: ${ROUTER_HOST})
  --user <USER>      OpenWrt SSH username (default: ${ROUTER_USER})
  --port <PORT>      OpenWrt SSH port (default: ${ROUTER_PORT})
  --ca-url <URL>     ACME CA directory URL (default: ${CA_URL})
  --domain <DOMAIN>  LAN domain or wildcard (e.g. lan, *.home.arpa)
  --email <EMAIL>    ACME account email (default: ${ACCOUNT_EMAIL:-admin@lan})
  --ca-cert <PATH>   Path to local root CA certificate (default: ${CA_CERT_PATH:-./ca.pem})

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -y|--yes|--accept-terms)
            ASSUME_YES=true
            shift
            ;;
        -r|--renew-only)
            RENEW_ONLY=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        --host)
            ROUTER_HOST="$2"
            shift 2
            ;;
        --user)
            ROUTER_USER="$2"
            shift 2
            ;;
        --port)
            ROUTER_PORT="$2"
            shift 2
            ;;
        --ca-url)
            CA_URL="$2"
            shift 2
            ;;
        --domain)
            LAN_DOMAIN="$2"
            shift 2
            ;;
        --email)
            ACCOUNT_EMAIL="$2"
            shift 2
            ;;
        --ca-cert)
            CA_CERT_PATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

# ------------------------------------------------------------------------------
# Interactive Confirmation & Change Guard
# ------------------------------------------------------------------------------
confirm_action() {
    local description="$1"
    local command_preview="$2"

    echo -e "\n${BOLD}${YELLOW}[ACTION REQUIRED]${NC} ${BOLD}${WHITE}${description}${NC}"
    if [[ -n "${command_preview}" ]]; then
        echo -e "${DIM}Commands to execute on OpenWrt:${NC}"
        echo -e "${CYAN}${command_preview}${NC}"
    fi

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Skipping actual execution on router."
        return 0
    fi

    read -r -p "Proceed with this change? [Y/n]: " response
    case "${response:-y}" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            log_warn "Action cancelled by user."
            return 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# SSH Command Runner
# ------------------------------------------------------------------------------
SSH_PASS=""
SSH_AUTH_METHOD="key" # 'key' or 'password'

build_ssh_base_opts() {
    mkdir -p "${SSH_CONTROL_DIR}" 2>/dev/null || true
    chmod 700 "${SSH_CONTROL_DIR}" 2>/dev/null || true
    echo -n "-p ${ROUTER_PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=8"
}

ssh_exec() {
    local cmd="$1"
    local base_opts
    base_opts="$(build_ssh_base_opts)"

    if [[ "${DRY_RUN}" == "true" && "$2" == "mutating" ]]; then
        log_info "[DRY-RUN] Remote execution skipped: ${cmd}"
        return 0
    fi

    if [[ "${SSH_AUTH_METHOD}" == "password" && -n "${SSH_PASS}" ]] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "${SSH_PASS}" ssh ${base_opts} -o "ControlMaster=auto" -o "ControlPath=${SSH_CONTROL_PATH}" -o "ControlPersist=10m" "${ROUTER_USER}@${ROUTER_HOST}" "${cmd}"
    else
        ssh ${base_opts} -o "ControlMaster=auto" -o "ControlPath=${SSH_CONTROL_PATH}" -o "ControlPersist=10m" "${ROUTER_USER}@${ROUTER_HOST}" "${cmd}"
    fi
}

ssh_upload_string() {
    local content="$1"
    local remote_path="$2"
    local base_opts
    base_opts="$(build_ssh_base_opts)"

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Remote upload skipped: ${remote_path}"
        return 0
    fi

    if [[ "${SSH_AUTH_METHOD}" == "password" && -n "${SSH_PASS}" ]] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "${SSH_PASS}" ssh ${base_opts} -o "ControlMaster=auto" -o "ControlPath=${SSH_CONTROL_PATH}" "${ROUTER_USER}@${ROUTER_HOST}" "cat > '${remote_path}'" <<< "${content}"
    else
        ssh ${base_opts} -o "ControlMaster=auto" -o "ControlPath=${SSH_CONTROL_PATH}" "${ROUTER_USER}@${ROUTER_HOST}" "cat > '${remote_path}'" <<< "${content}"
    fi
}

remote_file_exists() {
    local remote_path="$1"
    local res
    res="$(ssh_exec "[ -f '${remote_path}' ] && echo 'yes' || echo 'no'" "read_only" | tr -d '\r\n')"
    [[ "${res}" == "yes" ]]
}

remote_content_matches() {
    local content_or_file="$1"
    local remote_path="$2"
    local remote_md5 local_md5 local_md5_nl

    remote_md5="$(ssh_exec "md5sum '${remote_path}' 2>/dev/null" "read_only" | awk '{print $1}' | tr -d '\r\n')"
    [[ -z "${remote_md5}" ]] && return 1

    if [[ -f "${content_or_file}" ]]; then
        local_md5="$(md5sum "${content_or_file}" 2>/dev/null | awk '{print $1}')"
        [[ "${local_md5}" == "${remote_md5}" ]] && return 0
    else
        local_md5="$(printf "%s" "${content_or_file}" | md5sum 2>/dev/null | awk '{print $1}')"
        local_md5_nl="$(printf "%s\n" "${content_or_file}" | md5sum 2>/dev/null | awk '{print $1}')"
        if [[ "${local_md5}" == "${remote_md5}" || "${local_md5_nl}" == "${remote_md5}" ]]; then
            return 0
        fi
    fi
    return 1
}

# Appends a line to a remote file if not already present.
# Guarantees that the new line begins on a clean newline without creating extra blank lines.
build_safe_append_cmd() {
    local target_file="$1"
    local line_to_add="$2"
    echo "touch '${target_file}' && if ! grep -Fxq '${line_to_add}' '${target_file}' 2>/dev/null; then [ -s '${target_file}' ] && [ -n \"\$(tail -c 1 '${target_file}' 2>/dev/null)\" ] && echo >> '${target_file}'; echo '${line_to_add}' >> '${target_file}'; fi"
}

remote_append_line_if_missing() {
    local target_file="$1"
    local line_to_add="$2"
    local cmd
    cmd="$(build_safe_append_cmd "${target_file}" "${line_to_add}")"
    ssh_exec "${cmd}" "mutating"
}

prompt_overwrite_or_skip() {
    local description="$1"
    local remote_path="$2"
    local is_identical="$3" # "true" or "false"

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] File check: ${remote_path} (identical: ${is_identical})"
        return 0
    fi

    if [[ "${ASSUME_YES}" == "true" ]]; then
        if [[ "${is_identical}" == "true" ]]; then
            log_info "${description} (${remote_path}) is already present with identical content. Skipping update (--yes)."
            return 1
        else
            log_info "${description} (${remote_path}) exists. Overwriting (--yes)."
            return 0
        fi
    fi

    if [[ "${is_identical}" == "true" ]]; then
        echo -e "\n${BOLD}${YELLOW}[NOTICE]${NC} ${BOLD}${WHITE}${description}${NC} (${CYAN}${remote_path}${NC}) already exists on OpenWrt with ${GREEN}identical content${NC}."
        read -r -p "Overwrite anyway or skip? [o=overwrite / S=skip]: " resp
        case "${resp}" in
            [oO]|[oO][vV][eE][rR][wW][rR][iI][tT][eE]|[yY]|[yY][eE][sS])
                return 0
                ;;
            *)
                log_info "Skipping overwrite of ${remote_path}."
                return 1
                ;;
        esac
    else
        echo -e "\n${BOLD}${YELLOW}[NOTICE]${NC} ${BOLD}${WHITE}${description}${NC} (${CYAN}${remote_path}${NC}) already exists on OpenWrt."
        read -r -p "Overwrite file or skip? [O=overwrite / s=skip]: " resp
        case "${resp}" in
            [sS]|[sS][kK][iI][pP]|[nN]|[nN][oO])
                log_info "Skipping overwrite of ${remote_path}."
                return 1
                ;;
            *)
                return 0
                ;;
        esac
    fi
}

prompt_reapply_or_skip() {
    local description="$1"

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Setting check: ${description}"
        return 1
    fi

    if [[ "${ASSUME_YES}" == "true" ]]; then
        log_info "${description} is already configured. Skipping re-apply (--yes)."
        return 1
    fi

    echo -e "\n${BOLD}${YELLOW}[NOTICE]${NC} ${BOLD}${WHITE}${description}${NC} is already configured on OpenWrt."
    read -r -p "Re-apply / overwrite configuration anyway? [y/N]: " resp
    case "${resp}" in
        [yY]|[yY][eE][sS])
            return 0
            ;;
        *)
            log_info "Skipping re-apply for ${description}."
            return 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Dedicated Renewal & Sysupgrade Protection Routine
# ------------------------------------------------------------------------------
deploy_and_protect_renewal_routine() {
    log_step "Daily Renewal Check Script, Sysupgrade Protection & Cron Scheduling"

    local renew_script_target="/usr/bin/acme-renew-check.sh"
    local do_deploy_renew=true

    # 1. Script Deployment Check
    log_info "Checking ${renew_script_target} on OpenWrt..."
    if remote_file_exists "${renew_script_target}"; then
        local renew_identical=false
        if remote_content_matches "${RENEW_SCRIPT_CONTENT}" "${renew_script_target}"; then
            renew_identical=true
            log_success "${renew_script_target} exists and its content is identical."
        else
            log_info "${renew_script_target} exists but differs from latest version."
        fi

        if ! prompt_overwrite_or_skip "Daily renewal script" "${renew_script_target}" "${renew_identical}"; then
            do_deploy_renew=false
            log_info "Renewal script upload bypassed by user."
        fi
    else
        log_info "${renew_script_target} does not exist on router."
    fi

    if [[ "${do_deploy_renew}" == "true" ]]; then
        local renew_preview="cat << 'EOF' > ${renew_script_target}
# (Script contents with self-healing symlinks & acme.sh invocation)
EOF
chmod +x ${renew_script_target}"

        if confirm_action "Deploy daily renewal script (${renew_script_target}) on OpenWrt" "${renew_preview}"; then
            ssh_upload_string "${RENEW_SCRIPT_CONTENT}" "${renew_script_target}"
            ssh_exec "chmod +x ${renew_script_target}" "mutating"
            log_success "Daily renewal script deployed to ${renew_script_target}."
        else
            log_warn "Renewal script deployment skipped by user."
        fi
    fi

    # 2. Sysupgrade Protection Check for acme-renew-check.sh
    log_info "Checking sysupgrade backup protection for ${renew_script_target}..."
    local sysupgrade_renew_exists
    sysupgrade_renew_exists="$(ssh_exec "grep -Fx '${renew_script_target}' /etc/sysupgrade.conf 2>/dev/null && echo yes || echo no" "read_only" | tr -d '\r\n')"

    if [[ "${sysupgrade_renew_exists}" == "yes" ]]; then
        log_success "${renew_script_target} is already protected in /etc/sysupgrade.conf (bypassing step)."
    else
        local sysupgrade_preview
        sysupgrade_preview="$(build_safe_append_cmd "/etc/sysupgrade.conf" "${renew_script_target}")"
        if confirm_action "Add ${renew_script_target} to /etc/sysupgrade.conf for firmware upgrade protection" "${sysupgrade_preview}"; then
            remote_append_line_if_missing "/etc/sysupgrade.conf" "${renew_script_target}"
            log_success "Added ${renew_script_target} to /etc/sysupgrade.conf."
        else
            log_warn "Protection in /etc/sysupgrade.conf skipped by user."
        fi
    fi

    # 3. Scheduled Task (Cron) Registration Check
    log_info "Checking scheduled task in /etc/crontabs/root..."
    local cron_job_exists
    cron_job_exists="$(ssh_exec "grep -q 'acme-renew-check.sh' /etc/crontabs/root 2>/dev/null && echo yes || echo no" "read_only" | tr -d '\r\n')"

    local do_config_cron=true
    if [[ "${cron_job_exists}" == "yes" ]]; then
        log_success "Daily cron schedule for acme-renew-check.sh already exists in /etc/crontabs/root."
        if ! prompt_reapply_or_skip "Cron schedule for acme-renew-check.sh in /etc/crontabs/root"; then
            do_config_cron=false
            log_info "Cron configuration bypassed."
        fi
    else
        log_info "Daily cron schedule for acme-renew-check.sh not found in /etc/crontabs/root."
    fi

    if [[ "${do_config_cron}" == "true" ]]; then
        local cron_line="15 3 * * * ${renew_script_target}"
        local cron_append_cmd
        cron_append_cmd="$(build_safe_append_cmd "/etc/crontabs/root" "${cron_line}")"
        local cron_preview="mkdir -p /etc/crontabs
${cron_append_cmd}
/etc/init.d/cron enable && /etc/init.d/cron restart"

        if confirm_action "Register daily cron schedule (03:15) in /etc/crontabs/root and enable cron service" "${cron_preview}"; then
            ssh_exec "mkdir -p /etc/crontabs" "mutating"
            remote_append_line_if_missing "/etc/crontabs/root" "${cron_line}"
            ssh_exec "/etc/init.d/cron enable && /etc/init.d/cron restart" "mutating"
            log_success "Cron schedule registered (03:15 daily) and cron service active."
        else
            log_warn "Cron schedule registration skipped by user."
        fi
    fi
}

print_summary_and_exit() {
    log_header "OpenWrt Configuration Summary"
    cat << EOF
  Router Host:        ${ROUTER_HOST}:${ROUTER_PORT} (${ROUTER_USER})
  Renewal Check:      /usr/bin/acme-renew-check.sh (Cron: 03:15 daily)
  Sysupgrade Backup:  /etc/sysupgrade.conf (/usr/bin/acme-renew-check.sh)
  Session Log File:   ${LOG_FILE}
EOF

    echo -e "\n${BOLD}${GREEN}[✓] OpenWrt renewal maintenance workflow complete!${NC}\n"

    read -r -p "View application session log now? [Y/n]: " view_log_resp
    if [[ ! "${view_log_resp}" =~ ^[nN] ]]; then
        if [[ -t 1 ]] && command -v less >/dev/null 2>&1; then
            less -R "${LOG_FILE}"
        else
            cat "${LOG_FILE}"
        fi
    fi
    exit 0
}

# ------------------------------------------------------------------------------
# Renewal Check Script Content
# ------------------------------------------------------------------------------
RENEW_SCRIPT_CONTENT='#!/bin/sh
# Daily ACME certificate renewal check script for OpenWrt
LOG_TAG="acme-renew"
logger -t "$LOG_TAG" "Starting daily ACME certificate renewal check..."

# Ensure dynamic ACME challenge directory exists in RAM
mkdir -p /tmp/acme 2>/dev/null || true

# Self-Healing: Verify & recreate DNS API plugin symlinks
DNS_PLUGIN="/etc/acme/dnsapi/dns_openwrt_dnsmasq.sh"
if [ -f "$DNS_PLUGIN" ]; then
    mkdir -p /usr/lib/acme/client/dnsapi /root/.acme.sh/dnsapi 2>/dev/null || true
    if [ ! -e /usr/lib/acme/client/dnsapi/dns_openwrt_dnsmasq.sh ]; then
        ln -sf "$DNS_PLUGIN" /usr/lib/acme/client/dnsapi/dns_openwrt_dnsmasq.sh 2>/dev/null || true
    fi
    if [ -d /usr/lib/acme/dnsapi ] && [ ! -e /usr/lib/acme/dnsapi/dns_openwrt_dnsmasq.sh ]; then
        ln -sf "$DNS_PLUGIN" /usr/lib/acme/dnsapi/dns_openwrt_dnsmasq.sh 2>/dev/null || true
    fi
    if [ ! -e /root/.acme.sh/dnsapi/dns_openwrt_dnsmasq.sh ]; then
        ln -sf "$DNS_PLUGIN" /root/.acme.sh/dnsapi/dns_openwrt_dnsmasq.sh 2>/dev/null || true
    fi
fi

# Locate acme.sh binary across known OpenWrt paths
ACME_BIN="/usr/lib/acme/client/acme.sh"
if [ ! -x "$ACME_BIN" ] && [ -x /usr/lib/acme/acme.sh ]; then
    ACME_BIN="/usr/lib/acme/acme.sh"
fi
if [ ! -x "$ACME_BIN" ]; then
    ACME_BIN=$(command -v acme.sh 2>/dev/null)
fi
if [ ! -x "$ACME_BIN" ] && [ -x /usr/share/acme.sh/acme.sh ]; then
    ACME_BIN="/usr/share/acme.sh/acme.sh"
fi

if [ -z "$ACME_BIN" ] || [ ! -x "$ACME_BIN" ]; then
    logger -t "$LOG_TAG" "Error: acme.sh binary not found on system!"
    exit 1
fi

# Self-Healing: Verify & recreate /usr/bin/acme.sh CLI wrapper symlink
if [ ! -e /usr/bin/acme.sh ]; then
    ln -s "$ACME_BIN" /usr/bin/acme.sh 2>/dev/null || true
fi

"$ACME_BIN" --cron --home /etc/acme >> /var/log/acme_renew.log 2>&1
STATUS=$?

if [ $STATUS -eq 0 ]; then
    logger -t "$LOG_TAG" "ACME renewal check completed successfully."
    if [ -x /etc/init.d/uhttpd ]; then
        /etc/init.d/uhttpd reload
    fi
else
    logger -t "$LOG_TAG" "Warning: ACME renewal check exited with code $STATUS"
fi
'

# ------------------------------------------------------------------------------
# Application Flow & Session Logging
# ------------------------------------------------------------------------------
exec > >(tee -a "${LOG_FILE}") 2>&1

log_header "OpenWrt ACME Client & Dynamic Dnsmasq Automation"
echo -e "Log file: ${CYAN}${LOG_FILE}${NC}"

# ------------------------------------------------------------------------------
# Disclaimer & Limitation of Liability (Industry Standard Terms)
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${YELLOW}======================================================================${NC}"
echo -e "${BOLD}${YELLOW}  DISCLAIMER & LIMITATION OF LIABILITY${NC}"
echo -e "${BOLD}${YELLOW}======================================================================${NC}"
echo -e "${WHITE}  This tool modifies core OpenWrt routing, DNS, DHCP, and security configs.${NC}"
echo -e ""
echo -e "${DIM}  THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS"
echo -e "  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,"
echo -e "  FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT."
echo -e ""
echo -e "  IN NO EVENT SHALL THE AUTHORS, CONTRIBUTORS, OR COPYRIGHT HOLDERS BE"
echo -e "  LIABLE FOR ANY CLAIM, DAMAGES, LOSS OF DATA, NETWORK DISRUPTION, SERVICE"
echo -e "  DOWNTIME, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT,"
echo -e "  OR OTHERWISE, ARISING FROM OR IN CONNECTION WITH THE SOFTWARE OR THE"
echo -e "  USE OR OTHER DEALINGS IN THE SOFTWARE."
echo -e ""
echo -e "  By proceeding, you acknowledge that you are responsible for maintaining"
echo -e "  proper router backups and accept all risk associated with executing this tool.${NC}"
echo -e "${BOLD}${YELLOW}======================================================================${NC}"

if [[ "${ASSUME_YES}" != "true" ]]; then
    read -r -p "Do you accept these terms and wish to proceed? [y/N]: " accept_disclaimer
    case "${accept_disclaimer}" in
        [yY][eE][sS]|[yY])
            log_success "Disclaimer and terms of use accepted."
            ;;
        *)
            echo ""
            log_warn "Disclaimer was not accepted. Exiting without making any changes."
            exit 0
            ;;
    esac
else
    log_info "Disclaimer automatically accepted via CLI flag (--yes)."
fi

if [[ "${DRY_RUN}" == "true" ]]; then
    echo -e "\n${BOLD}${YELLOW}*** RUNNING IN DRY-RUN MODE: No changes will be made to OpenWrt ***${NC}\n"
else
    read -r -p "Run in Dry-Run mode to preview changes without modifying OpenWrt? [y/N]: " dry_resp
    if [[ "${dry_resp}" =~ ^[yY] ]]; then
        DRY_RUN=true
        echo -e "${BOLD}${YELLOW}*** DRY-RUN MODE ENABLED ***${NC}\n"
    fi
fi

# Step 1: Prompt for Router Connection Details
log_step "1. Router Connection Details"
read -r -p "Enter OpenWrt Router Host / IP [${ROUTER_HOST}]: " input_host
ROUTER_HOST="${input_host:-$ROUTER_HOST}"

read -r -p "Enter OpenWrt SSH User [${ROUTER_USER}]: " input_user
ROUTER_USER="${input_user:-$ROUTER_USER}"

read -r -p "Enter OpenWrt SSH Port [${ROUTER_PORT}]: " input_port
ROUTER_PORT="${input_port:-$ROUTER_PORT}"

# Test SSH connection with public key first
log_info "Testing SSH public-key authentication to ${ROUTER_USER}@${ROUTER_HOST}:${ROUTER_PORT}..."
if ssh -n $(build_ssh_base_opts) -o BatchMode=yes "${ROUTER_USER}@${ROUTER_HOST}" "echo ok" >/dev/null 2>&1; then
    SSH_AUTH_METHOD="key"
    log_success "SSH key authentication succeeded!"
else
    log_warn "Public key authentication failed or not configured."
    SSH_AUTH_METHOD="password"
    read -r -s -p "Enter SSH password for ${ROUTER_USER}@${ROUTER_HOST}: " SSH_PASS
    echo ""
    if ! command -v sshpass >/dev/null 2>&1; then
        log_warn "'sshpass' is not installed. OpenSSH will prompt interactively on first connection."
    fi
fi

save_config

# Verify SSH connectivity and fetch OpenWrt release
log_info "Connecting to OpenWrt..."
OPENWRT_RELEASE="$(ssh_exec "cat /etc/openwrt_release 2>/dev/null || cat /etc/os-release 2>/dev/null || echo 'Unknown OpenWrt'" "read_only")"
if [[ -z "${OPENWRT_RELEASE}" ]]; then
    log_error "Could not establish SSH session with ${ROUTER_USER}@${ROUTER_HOST}. Please verify credentials, host, and port."
    exit 1
fi
ROUTER_DESC="$(echo "${OPENWRT_RELEASE}" | grep -E "DISTRIB_DESCRIPTION=" | cut -d= -f2 | tr -d '"')"
log_success "Connected successfully to: ${BOLD}${ROUTER_DESC:-OpenWrt}${NC}"

# Early Prompt: Offer dedicated renewal script & sysupgrade protection workflow
if [[ "${RENEW_ONLY}" != "true" ]]; then
    echo ""
    read -r -p "Deploy renewal script, protect against sysupgrade, and register scheduled task ONLY? [y/N]: " renew_only_resp
    if [[ "${renew_only_resp}" =~ ^[yY] ]]; then
        RENEW_ONLY=true
        log_info "Renewal-only maintenance mode selected."
    fi
fi

if [[ "${RENEW_ONLY}" == "true" ]]; then
    log_header "OpenWrt Renewal Maintenance Workflow"
    deploy_and_protect_renewal_routine
    print_summary_and_exit
fi

# Step 2: OpenWrt ACME Dependency Check
log_step "2. Checking OpenWrt ACME Packages"

# Detect package manager (apk on OpenWrt 25.12+, opkg on OpenWrt 24.10 and older)
ROUTER_PKG_MGR="$(ssh_exec "if command -v apk >/dev/null 2>&1; then echo apk; elif command -v opkg >/dev/null 2>&1; then echo opkg; else echo none; fi" "read_only" | tr -d '\r\n')"
log_info "Detected router package manager: ${BOLD}${ROUTER_PKG_MGR}${NC}"

INSTALLED_PKGS=""
if [[ "${ROUTER_PKG_MGR}" == "apk" ]]; then
    INSTALLED_PKGS="$(ssh_exec "apk info 2>/dev/null" "read_only")"
elif [[ "${ROUTER_PKG_MGR}" == "opkg" ]]; then
    INSTALLED_PKGS="$(ssh_exec "opkg list-installed 2>/dev/null" "read_only")"
fi

check_pkg_installed() {
    local pkg="$1"
    if [[ "${ROUTER_PKG_MGR}" == "apk" ]]; then
        if echo "${INSTALLED_PKGS}" | grep -Fxq "${pkg}"; then
            return 0
        fi
    elif [[ "${ROUTER_PKG_MGR}" == "opkg" ]]; then
        if echo "${INSTALLED_PKGS}" | grep -E -q "^${pkg}([[:space:]]|-)"; then
            return 0
        fi
    fi

    # Direct filesystem / binary fallback check (defense in depth)
    case "${pkg}" in
        curl)
            ssh_exec "command -v curl >/dev/null 2>&1" "read_only" && return 0
            ;;
        acme-acmesh|acme.sh)
            ssh_exec "[ -x /usr/lib/acme/client/acme.sh ] || [ -x /usr/lib/acme/acme.sh ] || command -v acme.sh >/dev/null 2>&1 || [ -x /usr/share/acme.sh/acme.sh ]" "read_only" && return 0
            ;;
        luci-app-acme)
            ssh_exec "[ -f /etc/init.d/acme ] || [ -f /usr/share/luci/menu.d/luci-app-acme.json ]" "read_only" && return 0
            ;;
        ca-certificates)
            ssh_exec "[ -f /etc/ssl/certs/ca-certificates.crt ] || [ -d /etc/ssl/certs ]" "read_only" && return 0
            ;;
    esac

    return 1
}

NEED_INSTALL=()
for pkg in luci-app-acme acme-acmesh curl ca-certificates; do
    if ! check_pkg_installed "${pkg}"; then
        NEED_INSTALL+=("${pkg}")
    fi
done

if [[ ${#NEED_INSTALL[@]} -gt 0 ]]; then
    log_warn "Missing required package(s) on router: ${NEED_INSTALL[*]}"

    INSTALL_CMD=""
    if [[ "${ROUTER_PKG_MGR}" == "apk" ]]; then
        INSTALL_CMD="apk update && apk add ${NEED_INSTALL[*]}"
    elif [[ "${ROUTER_PKG_MGR}" == "opkg" ]]; then
        INSTALL_CMD="opkg update && opkg install ${NEED_INSTALL[*]}"
    else
        INSTALL_CMD="echo 'No supported package manager found on router to install: ${NEED_INSTALL[*]}'"
    fi

    if confirm_action "Install missing package(s) on OpenWrt" "${INSTALL_CMD}"; then
        ssh_exec "${INSTALL_CMD}" "mutating"
        log_success "Packages installed successfully."
    else
        log_warn "Proceeding without installing packages. Note that ACME client operations may fail."
    fi
else
    log_success "All required ACME packages are installed on OpenWrt."
fi

# Step 3: Check Legacy Static TXT Records in /etc/config/dhcp
log_step "3. Inspecting /etc/config/dhcp for Legacy Static TXT Records"
LEGACY_ENTRIES="$(ssh_exec "grep -E \"extraconftext.*txt-record=\" /etc/config/dhcp 2>/dev/null || true" "read_only")"

if [[ -n "${LEGACY_ENTRIES}" ]]; then
    log_warn "Found legacy static extraconftext txt-record entry in /etc/config/dhcp:"
    echo -e "${YELLOW}${LEGACY_ENTRIES}${NC}"
    if confirm_action "Remove legacy static extraconftext txt-record to prevent DNS-01 challenge conflicts" \
"sed -i.bak '/extraconftext.*txt-record=/d' /etc/config/dhcp
/etc/init.d/dnsmasq reload"; then
        ssh_exec "sed -i.bak '/extraconftext.*txt-record=/d' /etc/config/dhcp && /etc/init.d/dnsmasq reload" "mutating"
        log_success "Legacy static TXT entries removed and dnsmasq reloaded."
    else
        log_warn "Kept existing static entries. Note: multiple conflicting TXT records can fail validation."
    fi
else
    log_success "No stale static extraconftext txt-record entries found in /etc/config/dhcp."
fi

# Step 4: LAN Domain Discovery
log_step "4. Detecting Local LAN Domain"

# Detect active dnsmasq section (dhcp.dnsmasq1, dhcp.dnsmasq, or dhcp.@dnsmasq[0])
DHCP_DNSMASQ_SECTION="$(ssh_exec "if uci get dhcp.dnsmasq1 >/dev/null 2>&1; then echo 'dnsmasq1'; elif uci get dhcp.dnsmasq >/dev/null 2>&1; then echo 'dnsmasq'; elif uci get dhcp.@dnsmasq[0] >/dev/null 2>&1; then echo '@dnsmasq[0]'; else uci show dhcp 2>/dev/null | grep -E '=dnsmasq$' | head -n 1 | cut -d. -f2 | cut -d= -f1; fi" "read_only" | tr -d '\r\n')"
DHCP_DNSMASQ_TARGET="${DHCP_DNSMASQ_SECTION:-@dnsmasq[0]}"

DETECTED_DOMAIN="$(ssh_exec "uci get dhcp.${DHCP_DNSMASQ_TARGET}.domain 2>/dev/null || uci get dhcp.@dnsmasq[0].domain 2>/dev/null || grep -E 'option[[:space:]]+domain' /etc/config/dhcp 2>/dev/null | head -n 1 | awk '{print \$3}' | tr -d \"'\\\"\" || true" "read_only")"
DEFAULT_DOMAIN="${LAN_DOMAIN:-${DETECTED_DOMAIN:-lan}}"

log_info "Detected router dnsmasq section: ${BOLD}dhcp.${DHCP_DNSMASQ_TARGET}${NC}"
log_info "Detected router local domain: ${BOLD}${DETECTED_DOMAIN:-unknown}${NC}"
read -r -p "Enter LAN domain for ACME certificate (e.g. 'lan', 'example.lan', or '*.lan') [${DEFAULT_DOMAIN}]: " input_domain
LAN_DOMAIN="${input_domain:-$DEFAULT_DOMAIN}"

# Normalize domain & determine if wildcard requested
if [[ "${LAN_DOMAIN}" =~ ^\*\. ]]; then
    BASE_DOMAIN="${LAN_DOMAIN#\*.}"
    WILDCARD_DOMAIN="${LAN_DOMAIN}"
else
    BASE_DOMAIN="${LAN_DOMAIN}"
    WILDCARD_DOMAIN="*.${LAN_DOMAIN}"
fi

# Confirm whether to include apex domain with wildcard
INCLUDE_APEX=true
if [[ "${LAN_DOMAIN}" =~ ^\*\. ]]; then
    log_info "Configuring wildcard certificate for ${BOLD}${WILDCARD_DOMAIN}${NC} and base domain ${BOLD}${BASE_DOMAIN}${NC}."
else
    read -r -p "Would you like to issue a wildcard certificate (*.${BASE_DOMAIN} and ${BASE_DOMAIN})? [Y/n]: " wc_resp
    if [[ ! "${wc_resp}" =~ ^[nN] ]]; then
        LAN_DOMAIN="*.${BASE_DOMAIN}"
        WILDCARD_DOMAIN="*.${BASE_DOMAIN}"
    fi
fi

DOMAIN_NORM="$(echo "${BASE_DOMAIN}" | tr '.' '_')"
CERT_SECTION="${DOMAIN_NORM}_wildcard"

save_config
log_success "Domain targets: Wildcard '${WILDCARD_DOMAIN}', Apex '${BASE_DOMAIN}', UCI section: '${CERT_SECTION}'"

# Step 5: Local ACME CA Server Verification
log_step "5. Verifying Local ACME CA Server"
while true; do
    read -r -p "Enter local ACME CA URL [${CA_URL}]: " input_ca
    CA_URL="${input_ca:-$CA_URL}"

    # Auto-append /directory if missing
    if [[ ! "${CA_URL}" =~ /directory$ ]]; then
        CA_URL="${CA_URL%/}/acme/directory"
    fi

    log_info "Testing CA directory endpoint from local machine: ${CA_URL} ..."
    CA_TEST_LOCAL="$(curl -fsSL -k --connect-timeout 5 "${CA_URL}" 2>&1 || true)"
    if echo "${CA_TEST_LOCAL}" | grep -q "newOrder"; then
        log_success "ACME CA directory endpoint is reachable and returned valid JSON."
        break
    else
        log_warn "Could not verify ACME CA directory at ${CA_URL}."
        echo -e "${DIM}Response: ${CA_TEST_LOCAL:0:200}${NC}"
        read -r -p "Would you like to re-enter CA URL, retry, or proceed anyway? [r=re-enter / t=retry / p=proceed]: " ca_choice
        case "${ca_choice}" in
            [pP]*)
                break
                ;;
            [tT]*)
                continue
                ;;
            *)
                continue
                ;;
        esac
    fi
done

save_config

# Test reachability from OpenWrt router
log_info "Testing CA reachability from OpenWrt router..."
ROUTER_CA_TEST="$(ssh_exec "curl -s -k --connect-timeout 5 '${CA_URL}' 2>&1 || true" "read_only")"
if echo "${ROUTER_CA_TEST}" | grep -q "newOrder"; then
    log_success "OpenWrt router can reach local ACME CA server."
else
    log_warn "Router failed to reach CA server at ${CA_URL}."
    echo -e "${DIM}Router output: ${ROUTER_CA_TEST:0:200}${NC}"
fi

# Check SSL verification from router
ROUTER_SSL_TEST="$(ssh_exec "curl -s --connect-timeout 5 '${CA_URL}' 2>&1 || true" "read_only")"
CA_BASE_URL="$(echo "${CA_URL}" | sed -E 's|^(https?://[^/]+).*|\1|')"
CA_BASE_HOST="$(echo "${CA_BASE_URL}" | sed -E 's|^https?://([^:/]+).*|\1|')"
PROBE_EP_RAW="$(ssh_exec "curl -s -k --connect-timeout 4 '${CA_BASE_URL}/ca-trust/api/probe-endpoints' 2>&1 || true" "read_only")"
PROBE_SSL_OK=true
PROBE_PORTS=""

if echo "${PROBE_EP_RAW}" | grep -q '"endpoints"'; then
    PROBE_PORTS="$(echo "${PROBE_EP_RAW}" | grep -o '"port": *[0-9]*' | grep -o '[0-9]*' | sort -u)"
    for p in ${PROBE_PORTS}; do
        P_CHECK="$(ssh_exec "curl -fsSL --connect-timeout 4 'https://${CA_BASE_HOST}:${p}/probe' 2>&1 || true" "read_only")"
        if echo "${P_CHECK}" | grep -q '"status": *"ok"'; then
            log_success "OpenWrt router successfully verified live TLS trust on probe port ${p}."
        else
            log_warn "OpenWrt router failed live TLS verification on probe port ${p}."
            PROBE_SSL_OK=false
        fi
    done
fi

if ! echo "${ROUTER_SSL_TEST}" | grep -q "newOrder" || [[ "${PROBE_SSL_OK}" == "false" ]]; then
    log_warn "OpenWrt router encountered an SSL certificate verification issue contacting ${CA_URL}."
    DEFAULT_CA_PEM="${CA_CERT_PATH:-${REPO_DIR}/ca.pem}"

    while true; do
        read -r -p "Enter path to local root CA certificate (.pem/.crt) [${DEFAULT_CA_PEM}]: " input_ca_pem
        TARGET_CA_PEM="${input_ca_pem:-$DEFAULT_CA_PEM}"
        # Expand leading tilde if specified
        TARGET_CA_PEM="${TARGET_CA_PEM/#\~/$HOME}"

        if [[ -f "${TARGET_CA_PEM}" ]]; then
            CA_CERT_PATH="${TARGET_CA_PEM}"
            save_config
            log_info "Selected root CA certificate: ${BOLD}${CA_CERT_PATH}${NC}"
            REMOTE_CA_TARGET="/etc/ssl/certs/local-ca.pem"
            DO_UPLOAD=true

            if remote_file_exists "${REMOTE_CA_TARGET}"; then
                CA_IDENTICAL=false
                if remote_content_matches "${CA_CERT_PATH}" "${REMOTE_CA_TARGET}"; then
                    CA_IDENTICAL=true
                fi
                if ! prompt_overwrite_or_skip "Root CA certificate" "${REMOTE_CA_TARGET}" "${CA_IDENTICAL}"; then
                    DO_UPLOAD=false
                fi
            fi

            if [[ "${DO_UPLOAD}" == "true" ]]; then
                local ca_bundle_append_cmd
                ca_bundle_append_cmd="([ -f /etc/ssl/certs/ca-certificates.crt ] && grep -qF \"\$(head -n 2 ${REMOTE_CA_TARGET} | tail -n 1)\" /etc/ssl/certs/ca-certificates.crt 2>/dev/null) || ([ -s /etc/ssl/certs/ca-certificates.crt ] && [ -n \"\$(tail -c 1 /etc/ssl/certs/ca-certificates.crt 2>/dev/null)\" ] && echo >> /etc/ssl/certs/ca-certificates.crt; cat '${REMOTE_CA_TARGET}' >> /etc/ssl/certs/ca-certificates.crt)"
                local ca_sysupgrade_cmd
                ca_sysupgrade_cmd="$(build_safe_append_cmd "/etc/sysupgrade.conf" "${REMOTE_CA_TARGET}")"

                if confirm_action "Upload CA certificate (${CA_CERT_PATH}) to OpenWrt trust store (${REMOTE_CA_TARGET})" \
"cat '${CA_CERT_PATH}' | ssh ... 'cat > ${REMOTE_CA_TARGET}'
chmod 644 ${REMOTE_CA_TARGET}
${ca_bundle_append_cmd}
openssl rehash /etc/ssl/certs/ || true
${ca_sysupgrade_cmd}"; then
                    CA_PEM_CONTENT="$(cat "${CA_CERT_PATH}")"
                    ssh_upload_string "${CA_PEM_CONTENT}" "${REMOTE_CA_TARGET}"
                    ssh_exec "chmod 644 ${REMOTE_CA_TARGET} && ${ca_bundle_append_cmd} && (openssl rehash /etc/ssl/certs 2>/dev/null || true)" "mutating"
                    remote_append_line_if_missing "/etc/sysupgrade.conf" "${REMOTE_CA_TARGET}"
                    log_success "Uploaded CA certificate, updated trust store, and registered in /etc/sysupgrade.conf."
                fi
            else
                # Ensure sysupgrade registration even if upload was skipped
                remote_append_line_if_missing "/etc/sysupgrade.conf" "${REMOTE_CA_TARGET}"
            fi

            # Retest reachability with strict SSL
            log_info "Retesting CA SSL verification from OpenWrt router..."
            RETEST_SSL="$(ssh_exec "curl -s --connect-timeout 5 '${CA_URL}' 2>&1 || true" "read_only")"
            if echo "${RETEST_SSL}" | grep -q "newOrder"; then
                log_success "OpenWrt router now successfully trusts and verifies the local ACME CA!"
            else
                log_warn "Router still encountered SSL verification issues contacting ${CA_URL}."
            fi
            if [[ -n "${PROBE_PORTS}" ]]; then
                for p in ${PROBE_PORTS}; do
                    RETEST_P="$(ssh_exec "curl -fsSL --connect-timeout 4 'https://${CA_BASE_HOST}:${p}/probe' 2>&1 || true" "read_only")"
                    if echo "${RETEST_P}" | grep -q '"status": *"ok"'; then
                        log_success "OpenWrt router verified live TLS handshake on probe port ${p}!"
                    else
                        log_warn "Probe port ${p} still failed TLS verification from router."
                    fi
                done
            fi
            break
        else
            log_warn "Certificate file not found at: ${TARGET_CA_PEM}"
            read -r -p "Would you like to re-enter path or skip CA upload? [r=retry / s=skip]: " retry_choice
            if [[ "${retry_choice}" =~ ^[sS] ]]; then
                log_warn "Skipping root CA certificate upload."
                break
            fi
        fi
    done
fi

# Step 6: Configuring ACME Global Settings (Account Email & Debug Logging)
log_step "6. Configuring ACME Global Settings (Account Email & Debug Logging)"

# Query existing global acme section (acme.acme1, acme.acme, or acme.@acme[0])
GLOBAL_ACME_SECTION="$(ssh_exec "if uci get acme.acme1 >/dev/null 2>&1; then echo 'acme1'; elif uci get acme.acme >/dev/null 2>&1; then echo 'acme'; elif uci get acme.@acme[0] >/dev/null 2>&1; then echo '@acme[0]'; else echo ''; fi" "read_only" | tr -d '\r\n')"
GLOBAL_TARGET="${GLOBAL_ACME_SECTION:-@acme[0]}"

# Query existing account_email and debug flag on OpenWrt
EXISTING_EMAIL="$(ssh_exec "uci get acme.${GLOBAL_TARGET}.account_email 2>/dev/null || uci get acme.acme1.account_email 2>/dev/null || uci get acme.@acme[0].account_email 2>/dev/null || uci get acme.acme.account_email 2>/dev/null || true" "read_only" | tr -d '\r\n')"
EXISTING_DEBUG="$(ssh_exec "uci get acme.${GLOBAL_TARGET}.debug 2>/dev/null || uci get acme.acme1.debug 2>/dev/null || uci get acme.@acme[0].debug 2>/dev/null || uci get acme.acme.debug 2>/dev/null || true" "read_only" | tr -d '\r\n')"

log_info "Detected global ACME configuration section: ${BOLD}acme.${GLOBAL_TARGET}${NC}"
if [[ -n "${EXISTING_EMAIL}" ]]; then
    log_info "Detected existing ACME account email on OpenWrt (${GLOBAL_TARGET}): ${BOLD}${EXISTING_EMAIL}${NC}"
    EMAIL_DEFAULT="${EXISTING_EMAIL}"
elif [[ -n "${ACCOUNT_EMAIL}" ]]; then
    EMAIL_DEFAULT="${ACCOUNT_EMAIL}"
else
    EMAIL_DEFAULT="admin@${BASE_DOMAIN}"
fi

read -r -p "Enter ACME account email to use or replace [${EMAIL_DEFAULT}]: " input_email
ACCOUNT_EMAIL="${input_email:-$EMAIL_DEFAULT}"
save_config
log_success "Using ACME account email: ${BOLD}${ACCOUNT_EMAIL}${NC}"

# Check if global ACME configuration already matches desired email and debug='1'
DO_CONFIG_GLOBAL=true
if [[ "${EXISTING_EMAIL}" == "${ACCOUNT_EMAIL}" && "${EXISTING_DEBUG}" == "1" ]]; then
    if ! prompt_reapply_or_skip "Global ACME configuration (acme.${GLOBAL_TARGET}: account_email='${ACCOUNT_EMAIL}', debug='1')"; then
        DO_CONFIG_GLOBAL=false
    fi
fi

if [[ "${DO_CONFIG_GLOBAL}" == "true" ]]; then
    # Configure global acme section with account_email and debug='1'
    if [[ "${GLOBAL_ACME_SECTION}" == "acme1" ]]; then
        UCI_GLOBAL_CMDS="uci set acme.acme1.account_email='${ACCOUNT_EMAIL}'
uci set acme.acme1.debug='1'
uci commit acme"
    elif [[ "${GLOBAL_ACME_SECTION}" == "acme" ]]; then
        UCI_GLOBAL_CMDS="uci set acme.acme.account_email='${ACCOUNT_EMAIL}'
uci set acme.acme.debug='1'
uci commit acme"
    else
        UCI_GLOBAL_CMDS="if ! uci get acme.@acme[0] >/dev/null 2>&1; then
    uci add acme acme
fi
uci set acme.@acme[0].account_email='${ACCOUNT_EMAIL}'
uci set acme.@acme[0].debug='1'
uci commit acme"
    fi

    log_info "OpenWrt ACME debug status currently: ${EXISTING_DEBUG:-not set (0)}"
    if confirm_action "Update global ACME configuration acme.${GLOBAL_TARGET} (Set account_email and enable debug logging)" "${UCI_GLOBAL_CMDS}"; then
        ssh_exec "${UCI_GLOBAL_CMDS}" "mutating"
        log_success "Global ACME configuration (acme.${GLOBAL_TARGET}) committed with account_email='${ACCOUNT_EMAIL}' and debug='1'."
    fi
fi

# Step 7: Setup Dynamic Config Directory for Dnsmasq
log_step "7. Setting Up Dynamic Config Directory for Dnsmasq"

if [[ -z "${DHCP_DNSMASQ_TARGET}" ]]; then
    DHCP_DNSMASQ_SECTION="$(ssh_exec "if uci get dhcp.dnsmasq1 >/dev/null 2>&1; then echo 'dnsmasq1'; elif uci get dhcp.dnsmasq >/dev/null 2>&1; then echo 'dnsmasq'; elif uci get dhcp.@dnsmasq[0] >/dev/null 2>&1; then echo '@dnsmasq[0]'; else uci show dhcp 2>/dev/null | grep -E '=dnsmasq$' | head -n 1 | cut -d. -f2 | cut -d= -f1; fi" "read_only" | tr -d '\r\n')"
    DHCP_DNSMASQ_TARGET="${DHCP_DNSMASQ_SECTION:-@dnsmasq[0]}"
fi

# Silently ensure /tmp/acme directory exists on router
ssh_exec "mkdir -p /tmp/acme 2>/dev/null || true" "read_only" >/dev/null 2>&1 || true

CONFDIRS="$(ssh_exec "uci get dhcp.${DHCP_DNSMASQ_TARGET}.confdir 2>/dev/null || uci get dhcp.@dnsmasq[0].confdir 2>/dev/null || true" "read_only")"
DO_CONFIG_CONFDIR=true
if echo "${CONFDIRS}" | grep -qw "/tmp/acme"; then
    if ! prompt_reapply_or_skip "Dnsmasq (dhcp.${DHCP_DNSMASQ_TARGET}) confdir='/tmp/acme'"; then
        DO_CONFIG_CONFDIR=false
    fi
else
    log_info "Dnsmasq (dhcp.${DHCP_DNSMASQ_TARGET}) confdir='/tmp/acme' is not yet present."
fi

if [[ "${DO_CONFIG_CONFDIR}" == "true" ]]; then
    UCI_CONFDIR_CMDS="mkdir -p /tmp/acme
uci add_list dhcp.${DHCP_DNSMASQ_TARGET}.confdir='/tmp/acme'
uci commit dhcp
/etc/init.d/dnsmasq restart"

    if confirm_action "Add '/tmp/acme' to dnsmasq confdir in /etc/config/dhcp (dhcp.${DHCP_DNSMASQ_TARGET})" "${UCI_CONFDIR_CMDS}"; then
        ssh_exec "mkdir -p /tmp/acme && uci add_list dhcp.${DHCP_DNSMASQ_TARGET}.confdir='/tmp/acme' && uci commit dhcp && /etc/init.d/dnsmasq restart" "mutating"
        log_success "Dnsmasq confdir updated to '/tmp/acme' and service restarted."
    fi
fi

# Step 8: Configure Boot Startup Script (/etc/rc.local)
log_step "8. Configuring Boot Startup Script (/etc/rc.local)"

RC_LOCAL_HAS_ACME="$(ssh_exec "grep -q '/tmp/acme' /etc/rc.local 2>/dev/null && echo yes || echo no" "read_only" | tr -d '\r\n')"
DO_CONFIG_RC_LOCAL=true
if [[ "${RC_LOCAL_HAS_ACME}" == "yes" ]]; then
    if ! prompt_reapply_or_skip "Boot startup initialization in /etc/rc.local (/tmp/acme & restart dnsmasq)"; then
        DO_CONFIG_RC_LOCAL=false
    fi
fi

if [[ "${DO_CONFIG_RC_LOCAL}" == "true" ]]; then
    local rc_sysupgrade_cmd
    rc_sysupgrade_cmd="$(build_safe_append_cmd "/etc/sysupgrade.conf" "/etc/rc.local")"
    RC_LOCAL_CMDS="# Ensure /tmp/acme initialization in /etc/rc.local before exit 0
if [ ! -f /etc/rc.local ]; then
    echo '#!/bin/sh' > /etc/rc.local
fi
sed -i '/# Ensure ACME challenge directory/,+2d' /etc/rc.local 2>/dev/null || true
if grep -q '^exit 0' /etc/rc.local 2>/dev/null; then
    sed -i '/^exit 0/i # Ensure ACME challenge directory exists and restart dnsmasq\\nmkdir -p /tmp/acme\\n/etc/init.d/dnsmasq restart\\n' /etc/rc.local
else
    echo -e '\\n# Ensure ACME challenge directory exists and restart dnsmasq\\nmkdir -p /tmp/acme\\n/etc/init.d/dnsmasq restart\\nexit 0' >> /etc/rc.local
fi
chmod +x /etc/rc.local
${rc_sysupgrade_cmd}"

    if confirm_action "Configure /tmp/acme initialization & dnsmasq restart in /etc/rc.local on boot" "${RC_LOCAL_CMDS}"; then
        ssh_exec "if [ ! -f /etc/rc.local ]; then echo '#!/bin/sh' > /etc/rc.local; fi && sed -i '/# Ensure ACME challenge directory/,+2d' /etc/rc.local 2>/dev/null || true && if grep -q '^exit 0' /etc/rc.local 2>/dev/null; then sed -i '/^exit 0/i # Ensure ACME challenge directory exists and restart dnsmasq\\nmkdir -p /tmp/acme\\n/etc/init.d/dnsmasq restart\\n' /etc/rc.local; else echo -e '\\n# Ensure ACME challenge directory exists and restart dnsmasq\\nmkdir -p /tmp/acme\\n/etc/init.d/dnsmasq restart\\nexit 0' >> /etc/rc.local; fi && chmod +x /etc/rc.local" "mutating"
        remote_append_line_if_missing "/etc/sysupgrade.conf" "/etc/rc.local"
        log_success "/etc/rc.local configured to create /tmp/acme and restart dnsmasq on boot."
    fi
fi

# Step 9: Deploy Native acme.sh DNS API Plugin on OpenWrt
log_step "9. Deploying Native acme.sh DNS API Plugin (dns_openwrt_dnsmasq)"

DNS_PLUGIN_CONTENT='#!/bin/sh
# ==============================================================================
# OpenWrt dnsmasq DNS-01 Challenge Plugin for acme.sh
# Supports single domain, multiple SANs, and wildcard + apex combinations.
# Deployed to: /etc/acme/dnsapi/dns_openwrt_dnsmasq.sh
# ==============================================================================

CONF_DIR="/tmp/acme"

dns_openwrt_dnsmasq_add() {
    fulldomain=$1
    txtvalue=$2

    [ -z "$fulldomain" ] || [ -z "$txtvalue" ] && return 1

    # Sanitize token for safe unique filename (allows apex + wildcard co-existence)
    _token_slug="$(echo "$txtvalue" | tr -c '\''a-zA-Z0-9_'\'' '\''_'\'')"
    _conf_file="${CONF_DIR}/acme_${fulldomain}_${_token_slug}.conf"

    mkdir -p "${CONF_DIR}" 2>/dev/null || true
    echo "txt-record=${fulldomain},${txtvalue}" > "${_conf_file}"

    # Full restart required because dnsmasq SIGHUP ignores confdir changes
    /etc/init.d/dnsmasq restart >/dev/null 2>&1

    sleep 1
    return 0
}

dns_openwrt_dnsmasq_rm() {
    fulldomain=$1
    txtvalue=$2

    [ -z "$fulldomain" ] || [ -z "$txtvalue" ] && return 1

    _token_slug="$(echo "$txtvalue" | tr -c '\''a-zA-Z0-9_'\'' '\''_'\'')"
    _conf_file="${CONF_DIR}/acme_${fulldomain}_${_token_slug}.conf"

    rm -f "${_conf_file}"
    /etc/init.d/dnsmasq restart >/dev/null 2>&1
    return 0
}

# Compatibility aliases
dns_add() {
    dns_openwrt_dnsmasq_add "$@"
}

dns_rm() {
    dns_openwrt_dnsmasq_rm "$@"
}
'

DNS_PLUGIN_TARGET="/etc/acme/dnsapi/dns_openwrt_dnsmasq.sh"
DO_DEPLOY_PLUGIN=true

if remote_file_exists "${DNS_PLUGIN_TARGET}"; then
    PLUGIN_IDENTICAL=false
    if remote_content_matches "${DNS_PLUGIN_CONTENT}" "${DNS_PLUGIN_TARGET}"; then
        PLUGIN_IDENTICAL=true
    fi
    if ! prompt_overwrite_or_skip "acme.sh DNS API plugin" "${DNS_PLUGIN_TARGET}" "${PLUGIN_IDENTICAL}"; then
        DO_DEPLOY_PLUGIN=false
    fi
fi

if [[ "${DO_DEPLOY_PLUGIN}" == "true" ]]; then
    local acme_sysupgrade_cmd
    acme_sysupgrade_cmd="$(build_safe_append_cmd "/etc/sysupgrade.conf" "/etc/acme")"
    DEPLOY_PLUGIN_CMDS="mkdir -p /etc/acme/dnsapi /usr/lib/acme/client/dnsapi /root/.acme.sh/dnsapi
cat << 'EOF' > ${DNS_PLUGIN_TARGET}
...
EOF
chmod +x ${DNS_PLUGIN_TARGET}
ln -sf ${DNS_PLUGIN_TARGET} /usr/lib/acme/client/dnsapi/dns_openwrt_dnsmasq.sh
[ -d /usr/lib/acme/dnsapi ] && ln -sf ${DNS_PLUGIN_TARGET} /usr/lib/acme/dnsapi/dns_openwrt_dnsmasq.sh
ln -sf ${DNS_PLUGIN_TARGET} /root/.acme.sh/dnsapi/dns_openwrt_dnsmasq.sh
${acme_sysupgrade_cmd}"

    if confirm_action "Deploy acme.sh DNS API plugin (${DNS_PLUGIN_TARGET}) and link into dnsapi directories" "${DEPLOY_PLUGIN_CMDS}"; then
        ssh_exec "mkdir -p /etc/acme/dnsapi /usr/lib/acme/client/dnsapi /root/.acme.sh/dnsapi 2>/dev/null || true" "mutating"
        ssh_upload_string "${DNS_PLUGIN_CONTENT}" "${DNS_PLUGIN_TARGET}"
        ssh_exec "chmod +x ${DNS_PLUGIN_TARGET}" "mutating"
        ssh_exec "ln -sf ${DNS_PLUGIN_TARGET} /usr/lib/acme/client/dnsapi/dns_openwrt_dnsmasq.sh 2>/dev/null || true" "mutating"
        ssh_exec "[ -d /usr/lib/acme/dnsapi ] && ln -sf ${DNS_PLUGIN_TARGET} /usr/lib/acme/dnsapi/dns_openwrt_dnsmasq.sh 2>/dev/null || true" "mutating"
        ssh_exec "ln -sf ${DNS_PLUGIN_TARGET} /root/.acme.sh/dnsapi/dns_openwrt_dnsmasq.sh 2>/dev/null || true" "mutating"
        remote_append_line_if_missing "/etc/sysupgrade.conf" "/etc/acme"
        log_success "acme.sh DNS API plugin deployed, symlinked to dnsapi paths, and /etc/acme registered in /etc/sysupgrade.conf."
    fi
else
    # Ensure symlinks and sysupgrade entry exist even if file upload was skipped
    ssh_exec "mkdir -p /usr/lib/acme/client/dnsapi /root/.acme.sh/dnsapi 2>/dev/null || true && ln -sf ${DNS_PLUGIN_TARGET} /usr/lib/acme/client/dnsapi/dns_openwrt_dnsmasq.sh 2>/dev/null || true && [ -d /usr/lib/acme/dnsapi ] && ln -sf ${DNS_PLUGIN_TARGET} /usr/lib/acme/dnsapi/dns_openwrt_dnsmasq.sh 2>/dev/null || true && ln -sf ${DNS_PLUGIN_TARGET} /root/.acme.sh/dnsapi/dns_openwrt_dnsmasq.sh 2>/dev/null || true" "mutating"
    remote_append_line_if_missing "/etc/sysupgrade.conf" "/etc/acme"
    log_info "Plugin upload skipped; verified symlinks and backup registration."
fi

# Step 10: Configure /etc/config/acme for Native DNS API
log_step "10. Configuring /etc/config/acme for Domain '${BASE_DOMAIN}'"

DOMAINS_TO_REGISTER=()
if [[ "${INCLUDE_APEX}" == "true" && -n "${WILDCARD_DOMAIN}" ]]; then
    DOMAINS_TO_REGISTER+=("${WILDCARD_DOMAIN}" "${BASE_DOMAIN}")
else
    DOMAINS_TO_REGISTER+=("${BASE_DOMAIN}")
fi

EXISTING_DOMAINS="$(ssh_exec "uci -q get acme.${CERT_SECTION}.domains || true" "read_only" | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g' -e 's/^ //' -e 's/ $//')"
TARGET_DOMAINS="$(echo "${DOMAINS_TO_REGISTER[*]}" | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g' -e 's/^ //' -e 's/ $//')"
EXISTING_ENABLED="$(ssh_exec "uci -q get acme.${CERT_SECTION}.enabled || true" "read_only" | tr -d '\r\n')"
EXISTING_UHTTPD="$(ssh_exec "uci -q get acme.${CERT_SECTION}.use_uhttpd || true" "read_only" | tr -d '\r\n')"
EXISTING_DNS="$(ssh_exec "uci -q get acme.${CERT_SECTION}.dns || true" "read_only" | tr -d '\r\n')"

DO_CONFIG_CERT=true
if [[ "${EXISTING_ENABLED}" == "1" && "${EXISTING_UHTTPD}" == "1" && "${EXISTING_DNS}" == "dns_openwrt_dnsmasq" && "${EXISTING_DOMAINS}" == "${TARGET_DOMAINS}" ]]; then
    if ! prompt_reapply_or_skip "Certificate entry acme.${CERT_SECTION} (domains: [${TARGET_DOMAINS}], dns: dns_openwrt_dnsmasq)"; then
        DO_CONFIG_CERT=false
    fi
fi

if [[ "${DO_CONFIG_CERT}" == "true" ]]; then
    UCI_ACME_CMDS="uci set acme.${CERT_SECTION}=cert
uci set acme.${CERT_SECTION}.enabled='1'
uci set acme.${CERT_SECTION}.use_uhttpd='1'
uci -q delete acme.${CERT_SECTION}.domains || true"

    for d in "${DOMAINS_TO_REGISTER[@]}"; do
        UCI_ACME_CMDS="${UCI_ACME_CMDS}
uci add_list acme.${CERT_SECTION}.domains='${d}'"
    done

    UCI_ACME_CMDS="${UCI_ACME_CMDS}
uci set acme.${CERT_SECTION}.dns='dns_openwrt_dnsmasq'
uci set acme.${CERT_SECTION}.d_ns_sleep='5'
uci commit acme"

    if confirm_action "Configure certificate entry in /etc/config/acme" "${UCI_ACME_CMDS}"; then
        ssh_exec "${UCI_ACME_CMDS}" "mutating"
        log_success "/etc/config/acme configured with cert section '${CERT_SECTION}' (dns='dns_openwrt_dnsmasq')."
    fi
fi

# Step 10b: Pre-Flight DNS-01 Resolution Verification
log_step "10b. Pre-Flight DNS-01 Resolution Verification"
log_info "Testing DNS-01 TXT record propagation via dnsmasq before issuing certificate..."

PROBE_SUB="_acme-challenge-test.${BASE_DOMAIN}"
PROBE_TOKEN="probe_$(date +%s)"
PROBE_CONF="/tmp/acme/probe_${PROBE_TOKEN}.conf"

log_info "Setting temporary probe record on router: ${PROBE_SUB} -> ${PROBE_TOKEN}"
ssh_exec "mkdir -p /tmp/acme 2>/dev/null && echo 'txt-record=${PROBE_SUB},${PROBE_TOKEN}' > ${PROBE_CONF} && /etc/init.d/dnsmasq restart" "mutating"

# Test local router resolution
sleep 2
ROUTER_RESOLV="$(ssh_exec "nslookup -type=txt ${PROBE_SUB} 127.0.0.1 2>/dev/null || true" "read_only")"
if echo "${ROUTER_RESOLV}" | grep -q "${PROBE_TOKEN}"; then
    log_success "Router dnsmasq successfully resolved local TXT probe."
else
    log_warn "Router local query for ${PROBE_SUB} did not return expected token. Output:"
    echo -e "${DIM}${ROUTER_RESOLV:0:200}${NC}"
fi

# Test resolution from local machine (where CA resides)
LOCAL_QUERY_SUCCESS=false
if command -v python3 >/dev/null 2>&1; then
    PY_QUERY="$(python3 -c "
import dns.resolver, sys
r = dns.resolver.Resolver()
r.nameservers = ['${ROUTER_HOST}']
r.lifetime = 3.0
try:
    ans = r.resolve('${PROBE_SUB}', 'TXT')
    for rec in ans:
        if '${PROBE_TOKEN}' in b''.join(rec.strings).decode('utf-8', errors='ignore'):
            print('MATCH')
            sys.exit(0)
except Exception as e:
    print(f'ERR: {e}')
" 2>/dev/null || true)"
    if [[ "${PY_QUERY}" == *"MATCH"* ]]; then
        LOCAL_QUERY_SUCCESS=true
    fi
fi

if [[ "${LOCAL_QUERY_SUCCESS}" != "true" ]] && command -v dig >/dev/null 2>&1; then
    DIG_QUERY="$(dig +short "@${ROUTER_HOST}" "${PROBE_SUB}" TXT 2>/dev/null || true)"
    if echo "${DIG_QUERY}" | grep -q "${PROBE_TOKEN}"; then
        LOCAL_QUERY_SUCCESS=true
    fi
fi

if [[ "${LOCAL_QUERY_SUCCESS}" == "true" ]]; then
    log_success "Local CA host successfully queried OpenWrt dnsmasq (${ROUTER_HOST}:53) and verified TXT record."
else
    log_warn "Host machine could not verify TXT query against OpenWrt router (${ROUTER_HOST}:53). Please ensure firewall permits UDP port 53."
fi

# Clean up probe record
ssh_exec "rm -f ${PROBE_CONF} && /etc/init.d/dnsmasq restart" "mutating"
log_info "Pre-flight probe record cleaned up and dnsmasq restarted."

# Step 11: Test Certificate Issuance via acme.sh
log_step "11. Issuing Certificate via acme.sh on OpenWrt"

ROUTER_ACME_BIN="$(ssh_exec "if [ -x /usr/lib/acme/client/acme.sh ]; then echo /usr/lib/acme/client/acme.sh; elif [ -x /usr/lib/acme/acme.sh ]; then echo /usr/lib/acme/acme.sh; elif command -v acme.sh >/dev/null 2>&1; then command -v acme.sh; elif [ -x /usr/share/acme.sh/acme.sh ]; then echo /usr/share/acme.sh/acme.sh; else echo /usr/lib/acme/client/acme.sh; fi" "read_only" | tr -d '\r\n')"
ROUTER_ACME_BIN="${ROUTER_ACME_BIN:-/usr/lib/acme/client/acme.sh}"

# Ensure CLI symlink /usr/bin/acme.sh exists if client is at /usr/lib/acme/client/acme.sh
ssh_exec "[ -x /usr/lib/acme/client/acme.sh ] && [ ! -e /usr/bin/acme.sh ] && ln -s /usr/lib/acme/client/acme.sh /usr/bin/acme.sh 2>/dev/null || true" "read_only" >/dev/null 2>&1 || true

# Ensure ACME state directory exists
ssh_exec "mkdir -p /etc/acme 2>/dev/null || true" "read_only" >/dev/null 2>&1 || true

EXISTING_CERT_FOUND="$(ssh_exec "if [ -f '/etc/acme/${BASE_DOMAIN}/fullchain.cer' ] || [ -f '/etc/acme/${BASE_DOMAIN}_ecc/fullchain.cer' ] || [ -f '/etc/acme/${CERT_SECTION}/fullchain.cer' ]; then echo yes; else echo no; fi" "read_only" | tr -d '\r\n')"

ACME_BASE_ARGS="--home /etc/acme --issue"
for d in "${DOMAINS_TO_REGISTER[@]}"; do
    ACME_BASE_ARGS="${ACME_BASE_ARGS} -d \"${d}\""
done
ACME_BASE_ARGS="${ACME_BASE_ARGS} --dns dns_openwrt_dnsmasq --dnssleep 5 --accountemail \"${ACCOUNT_EMAIL}\" --debug --server \"${CA_URL}\" --reloadcmd \"/etc/init.d/uhttpd reload 2>/dev/null || true\""

DO_ISSUE=true
FORCE_FLAG=""

if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Would prompt for certificate issuance."
    DO_ISSUE=false
elif [[ "${ASSUME_YES}" == "true" ]]; then
    log_info "Automatic certificate issuance requested (--yes)."
else
    echo -e "\n${BOLD}${YELLOW}[ACTION REQUIRED]${NC} ${BOLD}${WHITE}Certificate Issuance Request${NC}"
    echo -e "  Domains:  ${CYAN}${DOMAINS_TO_REGISTER[*]}${NC}"
    echo -e "  CA URL:   ${CYAN}${CA_URL}${NC}"
    if [[ "${EXISTING_CERT_FOUND}" == "yes" ]]; then
        echo -e "  ${YELLOW}Notice: Existing certificate files detected under /etc/acme/ for ${BASE_DOMAIN}.${NC}"
        read -r -p "Choose action: [i]ssue / [f]orce-renew / [s]kip certificate issuance? [i/f/S] (default: skip): " issue_choice
        case "${issue_choice}" in
            [iI]|[iI][sS][sS][uU][eE])
                DO_ISSUE=true
                ;;
            [fF]|[fF][oO][rR][cC][eE])
                DO_ISSUE=true
                FORCE_FLAG=" --force"
                ;;
            *)
                log_info "Skipping certificate issuance upon user request."
                DO_ISSUE=false
                ;;
        esac
    else
        read -r -p "Request certificate issuance from ACME CA now or skip? [I=issue / s=skip]: " issue_choice
        case "${issue_choice}" in
            [sS]|[sS][kK][iI][pP]|[nN]|[nN][oO])
                log_info "Skipping certificate issuance upon user request."
                DO_ISSUE=false
                ;;
            *)
                DO_ISSUE=true
                ;;
        esac
    fi
fi

if [[ "${DO_ISSUE}" == "true" ]]; then
    ACME_ISSUE_CMD="${ROUTER_ACME_BIN} ${ACME_BASE_ARGS}${FORCE_FLAG}"
    if confirm_action "Execute certificate issuance on OpenWrt" "${ACME_ISSUE_CMD}"; then
        log_info "Running acme.sh --issue on OpenWrt router..."
        ssh_exec "${ACME_ISSUE_CMD}" "mutating"
        ISSUE_STATUS=$?
        if [[ ${ISSUE_STATUS} -eq 0 ]]; then
            log_success "Certificate issued successfully by acme.sh on OpenWrt!"
        else
            log_warn "acme.sh exited with code ${ISSUE_STATUS}. Review output above for details."
        fi
    fi
else
    log_info "Certificate issuance skipped."
fi

# Step 12: Schedule Daily Renewal Check on OpenWrt
deploy_and_protect_renewal_routine

# ------------------------------------------------------------------------------
# Summary & Application Log Viewer
# ------------------------------------------------------------------------------
log_header "OpenWrt Configuration Summary"
cat << EOF
  Router Host:        ${ROUTER_HOST}:${ROUTER_PORT} (${ROUTER_USER})
  CA Directory URL:   ${CA_URL}
  Configured Domain:  ${BASE_DOMAIN} (Wildcard: ${WILDCARD_DOMAIN})
  Account Email:      ${ACCOUNT_EMAIL}
  Debug Logging:      Enabled (debug='1')
  ACME Client Binary: ${ROUTER_ACME_BIN}
  UCI Cert Section:   /etc/config/acme -> [${CERT_SECTION}]
  DNS API Plugin:     /etc/acme/dnsapi/dns_openwrt_dnsmasq.sh (--dns dns_openwrt_dnsmasq)
  Boot Startup:       /etc/rc.local (mkdir -p /tmp/acme & restart dnsmasq)
  Renewal Check:      /usr/bin/acme-renew-check.sh (Cron: 03:15 daily)
  Backup Protected:   /etc/sysupgrade.conf updated
  Session Log File:   ${LOG_FILE}
EOF

echo -e "\n${BOLD}${GREEN}[✓] OpenWrt ACME configuration workflow complete!${NC}\n"

# Screen View Application Log Prompt
read -r -p "View application session log now? [Y/n]: " view_log_resp
if [[ ! "${view_log_resp}" =~ ^[nN] ]]; then
    if [[ -t 1 ]] && command -v less >/dev/null 2>&1; then
        less -R "${LOG_FILE}"
    else
        cat "${LOG_FILE}"
    fi
fi
