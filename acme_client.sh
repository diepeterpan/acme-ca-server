#!/usr/bin/env bash
# ==============================================================================
# ACME RFC 8555 Interactive Test Harness & Client
# Features:
#   - New Certificate Issuance & Certificate Renewal workflows
#   - Standalone HTTP-01 challenge server on custom configurable port
#   - Individual ACME API primitive testing (Directory, Nonce, Account,
#     Key-Change rollover, New-Order with validity period, Authz, Challenges,
#     Finalize, Download, Revoke, ARI)
# ==============================================================================

set -o pipefail

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Workspace directories
WORKSPACE_DIR="$(pwd)/.acme_workspace"
CONFIG_FILE="${WORKSPACE_DIR}/config.env"
ACCOUNT_KEY="${WORKSPACE_DIR}/account.key"
ACCOUNT_URL_FILE="${WORKSPACE_DIR}/account_url.txt"
CERTS_DIR="${WORKSPACE_DIR}/certs"
WWW_DIR="${WORKSPACE_DIR}/www"
CHALLENGE_DIR="${WWW_DIR}/.well-known/acme-challenge"
HTTP_LOG="${WORKSPACE_DIR}/http_server.log"
HTTP_PID_FILE="${WORKSPACE_DIR}/http_server.pid"

mkdir -p "${WORKSPACE_DIR}" "${CERTS_DIR}" "${CHALLENGE_DIR}"

# ------------------------------------------------------------------------------
# Dependency Checks
# ------------------------------------------------------------------------------
for cmd in curl openssl jq python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}[ERROR] Missing required dependency: ${cmd}${NC}"
        echo "Please install ${cmd} and run this script again."
        exit 1
    fi
done

# ------------------------------------------------------------------------------
# Configuration & State Management
# ------------------------------------------------------------------------------
ACME_DIRECTORY_URL="http://localhost:8080/acme/directory"
HTTP_CHALLENGE_PORT="8080"
ACCOUNT_EMAIL="admin@example.com"

# Load saved configuration if available
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
fi

save_config() {
    cat <<EOF > "$CONFIG_FILE"
ACME_DIRECTORY_URL="${ACME_DIRECTORY_URL}"
HTTP_CHALLENGE_PORT="${HTTP_CHALLENGE_PORT}"
ACCOUNT_EMAIL="${ACCOUNT_EMAIL}"
EOF
}

# ------------------------------------------------------------------------------
# Cryptography & JWS Helpers (Pure Bash + OpenSSL + Python stdlib)
# ------------------------------------------------------------------------------
b64url() {
    # Accepts string via stdin or parameter and encodes to base64url (no padding, -, _)
    base64 | tr -d '\r\n' | tr '+/' '-_' | tr -d '='
}

b64url_str() {
    printf "%s" "$1" | b64url
}

# Ensure an active account RSA key exists
ensure_account_key() {
    if [[ ! -f "$ACCOUNT_KEY" ]]; then
        echo -e "${YELLOW}[*] No account key found. Generating 2048-bit RSA account key...${NC}"
        openssl genrsa -out "$ACCOUNT_KEY" 2048 2>/dev/null
        chmod 600 "$ACCOUNT_KEY"
        echo -e "${GREEN}[+] Account key created at ${ACCOUNT_KEY}${NC}"
        rm -f "$ACCOUNT_URL_FILE"
    fi
}

# Extracts JWK (e, kty, n) and calculates RFC 7638 SHA-256 thumbprint
get_jwk_and_thumbprint() {
    local key_file="$1"
    local mod_hex
    mod_hex=$(openssl rsa -in "$key_file" -modulus -noout 2>/dev/null | cut -d= -f2)
    python3 -c "
import sys, json, base64, hashlib
hex_mod = sys.argv[1]
n_bytes = bytes.fromhex(hex_mod)
n_b64 = base64.urlsafe_b64encode(n_bytes).decode().rstrip('=')
e_bytes = (65537).to_bytes(3, 'big')
e_b64 = base64.urlsafe_b64encode(e_bytes).decode().rstrip('=')
jwk = {'e': e_b64, 'kty': 'RSA', 'n': n_b64}
thumb_json = json.dumps(jwk, sort_keys=True, separators=(',', ':')).encode('utf-8')
thumb = base64.urlsafe_b64encode(hashlib.sha256(thumb_json).digest()).decode().rstrip('=')
print(json.dumps({'jwk': jwk, 'thumbprint': thumb}))
" "$mod_hex"
}

# ------------------------------------------------------------------------------
# ACME API Directory & Nonce Fetching
# ------------------------------------------------------------------------------
API_NEW_NONCE=""
API_NEW_ACCOUNT=""
API_NEW_ORDER=""
API_REVOKE_CERT=""
API_KEY_CHANGE=""
API_RENEWAL_INFO=""

fetch_directory() {
    echo -e "${BLUE}[*] Fetching ACME Directory from: ${ACME_DIRECTORY_URL}...${NC}"
    local resp
    resp=$(curl -s -S --connect-timeout 5 "$ACME_DIRECTORY_URL" 2>&1)
    if [[ $? -ne 0 ]] || ! echo "$resp" | jq -e . >/dev/null 2>&1; then
        echo -e "${RED}[ERROR] Failed to fetch or parse directory from ${ACME_DIRECTORY_URL}${NC}"
        echo -e "Response: $resp"
        return 1
    fi

    API_NEW_NONCE=$(echo "$resp" | jq -r '.newNonce // empty')
    API_NEW_ACCOUNT=$(echo "$resp" | jq -r '.newAccount // empty')
    API_NEW_ORDER=$(echo "$resp" | jq -r '.newOrder // empty')
    API_REVOKE_CERT=$(echo "$resp" | jq -r '.revokeCert // empty')
    API_KEY_CHANGE=$(echo "$resp" | jq -r '.keyChange // empty')
    API_RENEWAL_INFO=$(echo "$resp" | jq -r '.renewalInfo // empty')

    echo -e "${GREEN}[+] Directory fetched successfully!${NC}"
    echo -e "    - newNonce:     ${CYAN}${API_NEW_NONCE}${NC}"
    echo -e "    - newAccount:   ${CYAN}${API_NEW_ACCOUNT}${NC}"
    echo -e "    - newOrder:     ${CYAN}${API_NEW_ORDER}${NC}"
    echo -e "    - revokeCert:   ${CYAN}${API_REVOKE_CERT}${NC}"
    echo -e "    - keyChange:    ${CYAN}${API_KEY_CHANGE}${NC}"
    if [[ -n "$API_RENEWAL_INFO" ]]; then
        echo -e "    - renewalInfo:  ${CYAN}${API_RENEWAL_INFO}${NC}"
    fi
    return 0
}

get_new_nonce() {
    if [[ -z "$API_NEW_NONCE" ]]; then
        fetch_directory || return 1
    fi
    local headers
    headers=$(mktemp)
    curl -s -I -D "$headers" -o /dev/null "$API_NEW_NONCE"
    local nonce
    nonce=$(grep -i '^replay-nonce:' "$headers" | tr -d '\r' | awk '{print $2}' | tail -n 1)
    rm -f "$headers"
    if [[ -z "$nonce" ]]; then
        echo -e "${RED}[ERROR] Could not extract replay-nonce from ${API_NEW_NONCE}${NC}" >&2
        return 1
    fi
    echo "$nonce"
}

# ------------------------------------------------------------------------------
# Signed ACME JWS Request Execution
# ------------------------------------------------------------------------------
# Usage: acme_request <URL> <PAYLOAD_JSON_OR_EMPTY> [SIGNING_KEY_FILE] [CUSTOM_KID] [HEADER_OUT_FILE]
# If PAYLOAD_JSON is empty (""), performs a POST-as-GET request.
# Automatically handles replay-nonce retrieval and badNonce retries.
acme_request() {
    local target_url="$1"
    local payload="$2"
    local key_file="${3:-$ACCOUNT_KEY}"
    local custom_kid="${4:-}"
    local header_out_file="${5:-}"

    local account_url=""
    if [[ -n "$custom_kid" ]]; then
        account_url="$custom_kid"
    elif [[ -f "$ACCOUNT_URL_FILE" ]]; then
        account_url=$(cat "$ACCOUNT_URL_FILE")
    fi

    local max_retries=2
    local attempt=0
    local success=0

    while [[ $attempt -lt $max_retries ]]; do
        attempt=$((attempt + 1))
        local nonce
        nonce=$(get_new_nonce)
        if [[ -z "$nonce" ]]; then
            echo -e "${RED}[ERROR] Unable to obtain nonce for request.${NC}" >&2
            return 1
        fi

        # Determine protected header: use kid if known, otherwise use jwk
        local protected_json=""
        if [[ -n "$account_url" && "$target_url" != "$API_NEW_ACCOUNT" ]]; then
            protected_json=$(jq -n -c \
                --arg alg "RS256" \
                --arg kid "$account_url" \
                --arg nonce "$nonce" \
                --arg url "$target_url" \
                '{"alg": $alg, "kid": $kid, "nonce": $nonce, "url": $url}')
        else
            local key_info
            key_info=$(get_jwk_and_thumbprint "$key_file")
            local jwk_obj
            jwk_obj=$(echo "$key_info" | jq -c '.jwk')
            protected_json=$(jq -n -c \
                --arg alg "RS256" \
                --argjson jwk "$jwk_obj" \
                --arg nonce "$nonce" \
                --arg url "$target_url" \
                '{"alg": $alg, "jwk": $jwk, "nonce": $nonce, "url": $url}')
        fi

        local protected_b64
        protected_b64=$(b64url_str "$protected_json")

        local payload_b64=""
        if [[ -n "$payload" ]]; then
            payload_b64=$(b64url_str "$payload")
        fi

        local signing_input="${protected_b64}.${payload_b64}"
        local signature
        signature=$(printf "%s" "$signing_input" | openssl dgst -sha256 -sign "$key_file" | b64url)

        local body_json
        body_json=$(jq -n -c \
            --arg prot "$protected_b64" \
            --arg pay "$payload_b64" \
            --arg sig "$signature" \
            '{"protected": $prot, "payload": $pay, "signature": $sig}')

        local resp_headers
        resp_headers=$(mktemp)
        local resp_body
        resp_body=$(mktemp)

        curl -s -D "$resp_headers" -o "$resp_body" \
            -H "Content-Type: application/jose+json" \
            -H "Accept: application/json, application/problem+json, application/pem-certificate-chain" \
            -X POST \
            --data "$body_json" \
            "$target_url"

        local status_code
        status_code=$(head -n 1 "$resp_headers" | awk '{print $2}')
        local resp_content
        resp_content=$(cat "$resp_body")

        # Check for badNonce error to retry
        if echo "$resp_content" | grep -q "urn:ietf:params:acme:error:badNonce"; then
            echo -e "${YELLOW}[!] Server returned badNonce. Retrying with fresh nonce...${NC}" >&2
            rm -f "$resp_headers" "$resp_body"
            continue
        fi

        if [[ -n "$header_out_file" ]]; then
            cp "$resp_headers" "$header_out_file"
        fi

        rm -f "$resp_headers" "$resp_body"
        echo "$resp_content"
        return 0
    done

    echo -e "${RED}[ERROR] Request failed after retries.${NC}" >&2
    return 1
}

# ------------------------------------------------------------------------------
# Standalone HTTP-01 Challenge Server
# ------------------------------------------------------------------------------
start_standalone_http() {
    stop_standalone_http
    echo -e "${BLUE}[*] Starting standalone HTTP-01 challenge server on port ${HTTP_CHALLENGE_PORT}...${NC}"
    nohup python3 -m http.server "$HTTP_CHALLENGE_PORT" --directory "$WWW_DIR" > "$HTTP_LOG" 2>&1 &
    local pid=$!
    echo "$pid" > "$HTTP_PID_FILE"
    sleep 1

    if kill -0 "$pid" 2>/dev/null; then
        echo -e "${GREEN}[+] HTTP server listening on port ${HTTP_CHALLENGE_PORT} (PID: ${pid})${NC}"
        echo -e "    Serving root: ${WWW_DIR}"
        echo -e "    Challenge path: ${CHALLENGE_DIR}"
        return 0
    else
        echo -e "${RED}[ERROR] Failed to start HTTP challenge server. Check log:${NC}"
        cat "$HTTP_LOG"
        return 1
    fi
}

stop_standalone_http() {
    if [[ -f "$HTTP_PID_FILE" ]]; then
        local pid
        pid=$(cat "$HTTP_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${BLUE}[*] Stopping HTTP challenge server (PID: ${pid})...${NC}"
            kill "$pid" 2>/dev/null || true
            sleep 0.5
        fi
        rm -f "$HTTP_PID_FILE"
    fi
}

# ------------------------------------------------------------------------------
# Workflow 1: Request New Certificate (End-to-End)
# ------------------------------------------------------------------------------
workflow_new_cert() {
    echo -e "\n${BOLD}======================================================${NC}"
    echo -e "${BOLD}         REQUEST NEW CERTIFICATE (END-TO-END)         ${NC}"
    echo -e "${BOLD}======================================================${NC}"

    ensure_account_key
    fetch_directory || return 1

    # Check or create account
    if [[ ! -f "$ACCOUNT_URL_FILE" ]]; then
        echo -e "${YELLOW}[!] No registered account URL found. Registering new account first...${NC}"
        api_test_new_acct || return 1
    fi
    local account_url
    account_url=$(cat "$ACCOUNT_URL_FILE")
    echo -e "Using Account URL: ${CYAN}${account_url}${NC}"

    # Prompt for domain(s)
    echo -e "\n${BOLD}Step 1: Domain Identifier(s)${NC}"
    echo -e "Enter domains separated by space or comma (e.g. host1.example.org):"
    read -r -p "Domain(s): " raw_domains
    if [[ -z "$raw_domains" ]]; then
        echo -e "${RED}[ERROR] At least one domain is required.${NC}"
        return 1
    fi

    # Format domains into JSON array
    local identifiers_json="[]"
    local primary_domain=""
    for d in $(echo "$raw_domains" | tr ',' ' '); do
        d=$(echo "$d" | tr -d '[:space:]')
        if [[ -z "$primary_domain" ]]; then
            primary_domain="$d"
        fi
        identifiers_json=$(echo "$identifiers_json" | jq --arg dom "$d" '. += [{"type": "dns", "value": $dom}]')
    done

    # Prompt for Validity Period
    echo -e "\n${BOLD}Step 2: Certificate Validity Period (Optional)${NC}"
    echo -e "Leave empty for CA defaults, or enter RFC 3339 timestamps (e.g. $(date -u +"%Y-%m-%dT%H:%M:%SZ"))"
    read -r -p "notBefore [empty for default]: " not_before
    read -r -p "notAfter  [empty for default]: " not_after

    # Build newOrder payload
    local order_payload
    order_payload=$(jq -n -c --argjson idents "$identifiers_json" '{"identifiers": $idents}')
    if [[ -n "$not_before" ]]; then
        order_payload=$(echo "$order_payload" | jq --arg nb "$not_before" '. + {"notBefore": $nb}')
    fi
    if [[ -n "$not_after" ]]; then
        order_payload=$(echo "$order_payload" | jq --arg na "$not_after" '. + {"notAfter": $na}')
    fi

    echo -e "\nSubmitting newOrder request payload:"
    echo "$order_payload" | jq .

    local order_headers
    order_headers=$(mktemp)
    local order_resp
    order_resp=$(acme_request "$API_NEW_ORDER" "$order_payload" "$ACCOUNT_KEY" "" "$order_headers")

    local order_url
    order_url=$(grep -i '^location:' "$order_headers" | tr -d '\r' | awk '{print $2}' | tail -n 1)
    rm -f "$order_headers"

    if [[ -z "$order_url" ]]; then
        echo -e "${RED}[ERROR] Order creation failed. Response:${NC}"
        echo "$order_resp" | jq . 2>/dev/null || echo "$order_resp"
        return 1
    fi

    echo -e "${GREEN}[+] Order created!${NC}"
    echo -e "Order URL: ${CYAN}${order_url}${NC}"
    echo "$order_resp" | jq .

    local authz_urls
    authz_urls=$(echo "$order_resp" | jq -r '.authorizations[]?')
    local finalize_url
    finalize_url=$(echo "$order_resp" | jq -r '.finalize // empty')

    # Step 3: Handle HTTP-01 Challenges
    echo -e "\n${BOLD}Step 3: Solving HTTP-01 Challenges${NC}"
    local key_info
    key_info=$(get_jwk_and_thumbprint "$ACCOUNT_KEY")
    local thumbprint
    thumbprint=$(echo "$key_info" | jq -r '.thumbprint')

    start_standalone_http || return 1

    for authz_url in $authz_urls; do
        echo -e "\nFetching authorization: ${CYAN}${authz_url}${NC}..."
        local authz_resp
        authz_resp=$(acme_request "$authz_url" "")
        local authz_status
        authz_status=$(echo "$authz_resp" | jq -r '.status')
        local domain_val
        domain_val=$(echo "$authz_resp" | jq -r '.identifier.value')

        echo -e "Authorization for [${BOLD}${domain_val}${NC}] is currently: ${CYAN}${authz_status}${NC}"
        if [[ "$authz_status" == "valid" ]]; then
            echo -e "${GREEN}[+] Authorization already valid. Skipping challenge.${NC}"
            continue
        fi

        # Find http-01 challenge
        local challenge_obj
        challenge_obj=$(echo "$authz_resp" | jq -c '.challenges[] | select(.type == "http-01")')
        if [[ -z "$challenge_obj" ]]; then
            echo -e "${RED}[ERROR] No http-01 challenge found in authorization!${NC}"
            stop_standalone_http
            return 1
        fi

        local chal_url
        chal_url=$(echo "$challenge_obj" | jq -r '.url')
        local chal_token
        chal_token=$(echo "$challenge_obj" | jq -r '.token')
        local key_auth="${chal_token}.${thumbprint}"

        echo -e "Deploying HTTP challenge file:"
        echo -e "  Token: ${CYAN}${chal_token}${NC}"
        echo -e "  KeyAuthorization: ${CYAN}${key_auth}${NC}"
        echo -n "$key_auth" > "${CHALLENGE_DIR}/${chal_token}"

        echo -e "Triggering challenge validation at: ${CYAN}${chal_url}${NC}..."
        local chal_resp
        chal_resp=$(acme_request "$chal_url" "{}")
        echo "$chal_resp" | jq .

        # Poll authorization until valid
        echo -e "Waiting for authorization to become valid..."
        local tries=0
        while [[ $tries -lt 15 ]]; do
            sleep 2
            tries=$((tries + 1))
            authz_resp=$(acme_request "$authz_url" "")
            authz_status=$(echo "$authz_resp" | jq -r '.status')
            echo -e "  Status: ${CYAN}${authz_status}${NC} (check ${tries}/15)"
            if [[ "$authz_status" == "valid" ]]; then
                echo -e "${GREEN}[+] Domain ${domain_val} successfully validated!${NC}"
                break
            elif [[ "$authz_status" == "invalid" ]]; then
                echo -e "${RED}[ERROR] Authorization failed and became invalid!${NC}"
                echo "$authz_resp" | jq .
                stop_standalone_http
                return 1
            fi
        done
    done

    stop_standalone_http

    # Step 4: Finalize Order with CSR
    echo -e "\n${BOLD}Step 4: Generating Certificate Key & CSR${NC}"
    local cert_save_dir="${CERTS_DIR}/${primary_domain}"
    mkdir -p "$cert_save_dir"
    local cert_key="${cert_save_dir}/privkey.pem"
    local cert_csr_der="${cert_save_dir}/cert.csr.der"

    echo -e "Generating 2048-bit RSA certificate private key at: ${CYAN}${cert_key}${NC}..."
    openssl genrsa -out "$cert_key" 2048 2>/dev/null

    local san_list=""
    for d in $(echo "$raw_domains" | tr ',' ' '); do
        d=$(echo "$d" | tr -d '[:space:]')
        if [[ -z "$san_list" ]]; then
            san_list="DNS:${d}"
        else
            san_list="${san_list},DNS:${d}"
        fi
    done

    local openssl_cnf
    openssl_cnf=$(mktemp)
    cat <<EOF > "$openssl_cnf"
[ req ]
default_bits = 2048
distinguished_name = req_dn
req_extensions = req_ext
prompt = no

[ req_dn ]
CN = ${primary_domain}

[ req_ext ]
subjectAltName = ${san_list}
EOF

    openssl req -new -sha256 -key "$cert_key" -config "$openssl_cnf" -outform DER -out "$cert_csr_der" 2>/dev/null
    rm -f "$openssl_cnf"

    local csr_b64url
    csr_b64url=$(b64url < "$cert_csr_der")

    echo -e "Submitting CSR to finalize URL: ${CYAN}${finalize_url}${NC}..."
    local finalize_resp
    finalize_resp=$(acme_request "$finalize_url" "{\"csr\": \"${csr_b64url}\"}")
    echo "$finalize_resp" | jq .

    # Step 5: Poll Order for Certificate URL
    echo -e "\n${BOLD}Step 5: Polling Order Status for Certificate${NC}"
    local order_status=""
    local cert_url=""
    local tries=0
    while [[ $tries -lt 15 ]]; do
        sleep 2
        tries=$((tries + 1))
        local current_order
        current_order=$(acme_request "$order_url" "")
        order_status=$(echo "$current_order" | jq -r '.status')
        cert_url=$(echo "$current_order" | jq -r '.certificate // empty')
        echo -e "  Order status: ${CYAN}${order_status}${NC} (check ${tries}/15)"
        if [[ "$order_status" == "valid" && -n "$cert_url" ]]; then
            break
        elif [[ "$order_status" == "invalid" ]]; then
            echo -e "${RED}[ERROR] Order became invalid!${NC}"
            echo "$current_order" | jq .
            return 1
        fi
    done

    if [[ -z "$cert_url" ]]; then
        echo -e "${RED}[ERROR] Timed out waiting for certificate URL.${NC}"
        return 1
    fi

    # Step 6: Download Certificate
    echo -e "\n${BOLD}Step 6: Downloading Certificate Chain${NC}"
    local fullchain_pem="${cert_save_dir}/fullchain.pem"
    acme_request "$cert_url" "" > "$fullchain_pem"

    echo -e "${GREEN}[+] Certificate downloaded successfully!${NC}"
    echo -e "Saved to: ${CYAN}${fullchain_pem}${NC}"

    echo -e "\n${BOLD}Certificate Details:${NC}"
    openssl x509 -in "$fullchain_pem" -noout -subject -issuer -dates
    echo -e "SANs:"
    openssl x509 -in "$fullchain_pem" -noout -text | grep -A 1 "Subject Alternative Name" | tr -d ' '
}

# ------------------------------------------------------------------------------
# Workflow 2: Renew Existing Certificate
# ------------------------------------------------------------------------------
workflow_renew_cert() {
    echo -e "\n${BOLD}======================================================${NC}"
    echo -e "${BOLD}             RENEW EXISTING CERTIFICATE               ${NC}"
    echo -e "${BOLD}======================================================${NC}"

    # Search for certificates in workspace
    local cert_files=()
    while IFS= read -r -d $'\0' f; do
        cert_files+=("$f")
    done < <(find "$CERTS_DIR" -name "fullchain.pem" -print0 2>/dev/null)

    local target_cert=""
    if [[ ${#cert_files[@]} -gt 0 ]]; then
        echo "Found existing certificates:"
        for i in "${!cert_files[@]}"; do
            local cn
            cn=$(openssl x509 -in "${cert_files[$i]}" -noout -subject 2>/dev/null | sed 's/subject=CN = //')
            local exp
            exp=$(openssl x509 -in "${cert_files[$i]}" -noout -enddate 2>/dev/null)
            echo -e "  [${CYAN}$((i+1))${NC}] ${cert_files[$i]} (${cn}, ${exp})"
        done
        read -r -p "Select certificate number or enter custom file path: " sel
        if [[ "$sel" =~ ^[0-9]+$ ]] && [[ "$sel" -ge 1 && "$sel" -le "${#cert_files[@]}" ]]; then
            target_cert="${cert_files[$((sel-1))]}"
        else
            target_cert="$sel"
        fi
    else
        read -r -p "Enter path to existing fullchain.pem: " target_cert
    fi

    if [[ ! -f "$target_cert" ]]; then
        echo -e "${RED}[ERROR] Certificate file not found: ${target_cert}${NC}"
        return 1
    fi

    echo -e "\n${BOLD}Current Certificate Information:${NC}"
    openssl x509 -in "$target_cert" -noout -subject -issuer -dates

    # Check ARI (RFC 9444) if renewalInfo is available
    if [[ -n "$API_RENEWAL_INFO" ]]; then
        echo -e "\n${BLUE}[*] Checking ACME Renewal Information (ARI) from CA...${NC}"
        local cert_serial
        cert_serial=$(openssl x509 -in "$target_cert" -noout -serial | cut -d= -f2)
        local ari_url="${API_RENEWAL_INFO}/${cert_serial}"
        local ari_resp
        ari_resp=$(curl -s "$ari_url" 2>/dev/null)
        if echo "$ari_resp" | jq -e . >/dev/null 2>&1; then
            echo -e "ARI response for serial ${cert_serial}:"
            echo "$ari_resp" | jq .
        else
            echo -e "${YELLOW}[!] ARI endpoint did not return JSON or certificate not known to ARI.${NC}"
        fi
    fi

    # Extract existing SAN domains
    local existing_sans
    existing_sans=$(openssl x509 -in "$target_cert" -noout -text 2>/dev/null | grep -A 1 "Subject Alternative Name" | tail -n 1 | sed 's/DNS://g' | tr -d ' ')
    echo -e "\nDetected domains: ${CYAN}${existing_sans}${NC}"
    read -r -p "Use these domains for renewal? [Y/n]: " yn_dom
    local renewal_domains="${existing_sans}"
    if [[ "$yn_dom" =~ ^[Nn] ]]; then
        read -r -p "Enter domains for renewal: " renewal_domains
    fi

    read -r -p "Reuse existing private key? [y/N]: " reuse_key
    read -r -p "New notBefore [empty for default]: " ren_nb
    read -r -p "New notAfter  [empty for default]: " ren_na

    # Execute issuance flow with prompt overrides
    # Formulate domain array
    local identifiers_json="[]"
    local primary_domain=""
    for d in $(echo "$renewal_domains" | tr ',' ' '); do
        d=$(echo "$d" | tr -d '[:space:]')
        if [[ -z "$primary_domain" ]]; then primary_domain="$d"; fi
        identifiers_json=$(echo "$identifiers_json" | jq --arg dom "$d" '. += [{"type": "dns", "value": $dom}]')
    done

    local order_payload
    order_payload=$(jq -n -c --argjson idents "$identifiers_json" '{"identifiers": $idents}')
    if [[ -n "$ren_nb" ]]; then order_payload=$(echo "$order_payload" | jq --arg nb "$ren_nb" '. + {"notBefore": $nb}'); fi
    if [[ -n "$ren_na" ]]; then order_payload=$(echo "$order_payload" | jq --arg na "$ren_na" '. + {"notAfter": $na}'); fi

    local order_headers
    order_headers=$(mktemp)
    local order_resp
    order_resp=$(acme_request "$API_NEW_ORDER" "$order_payload" "$ACCOUNT_KEY" "" "$order_headers")
    local order_url
    order_url=$(grep -i '^location:' "$order_headers" | tr -d '\r' | awk '{print $2}' | tail -n 1)
    rm -f "$order_headers"

    if [[ -z "$order_url" ]]; then
        echo -e "${RED}[ERROR] Renewal order failed:${NC}"
        echo "$order_resp" | jq . 2>/dev/null || echo "$order_resp"
        return 1
    fi

    echo -e "${GREEN}[+] Renewal Order created:${NC} ${CYAN}${order_url}${NC}"
    local authz_urls
    authz_urls=$(echo "$order_resp" | jq -r '.authorizations[]?')
    local finalize_url
    finalize_url=$(echo "$order_resp" | jq -r '.finalize // empty')

    # Challenge validation
    local key_info
    key_info=$(get_jwk_and_thumbprint "$ACCOUNT_KEY")
    local thumbprint
    thumbprint=$(echo "$key_info" | jq -r '.thumbprint')

    start_standalone_http || return 1
    for authz_url in $authz_urls; do
        local authz_resp
        authz_resp=$(acme_request "$authz_url" "")
        local authz_status
        authz_status=$(echo "$authz_resp" | jq -r '.status')
        if [[ "$authz_status" == "valid" ]]; then continue; fi

        local challenge_obj
        challenge_obj=$(echo "$authz_resp" | jq -c '.challenges[] | select(.type == "http-01")')
        local chal_url
        chal_url=$(echo "$challenge_obj" | jq -r '.url')
        local chal_token
        chal_token=$(echo "$challenge_obj" | jq -r '.token')
        local key_auth="${chal_token}.${thumbprint}"

        echo -n "$key_auth" > "${CHALLENGE_DIR}/${chal_token}"
        acme_request "$chal_url" "{}" > /dev/null

        local tries=0
        while [[ $tries -lt 15 ]]; do
            sleep 2
            tries=$((tries + 1))
            authz_resp=$(acme_request "$authz_url" "")
            if [[ $(echo "$authz_resp" | jq -r '.status') == "valid" ]]; then break; fi
        done
    done
    stop_standalone_http

    # CSR & Finalize
    local cert_save_dir="${CERTS_DIR}/${primary_domain}"
    mkdir -p "$cert_save_dir"
    local cert_key="${cert_save_dir}/privkey.pem"
    if [[ ! "$reuse_key" =~ ^[Yy] ]] || [[ ! -f "$cert_key" ]]; then
        echo -e "[*] Generating fresh 2048-bit RSA private key..."
        openssl genrsa -out "$cert_key" 2048 2>/dev/null
    fi

    local cert_csr_der="${cert_save_dir}/cert_renewal.csr.der"
    local san_list=""
    for d in $(echo "$renewal_domains" | tr ',' ' '); do
        d=$(echo "$d" | tr -d '[:space:]')
        if [[ -z "$san_list" ]]; then san_list="DNS:${d}"; else san_list="${san_list},DNS:${d}"; fi
    done

    local openssl_cnf
    openssl_cnf=$(mktemp)
    cat <<EOF > "$openssl_cnf"
[ req ]
default_bits = 2048
distinguished_name = req_dn
req_extensions = req_ext
prompt = no

[ req_dn ]
CN = ${primary_domain}

[ req_ext ]
subjectAltName = ${san_list}
EOF
    openssl req -new -sha256 -key "$cert_key" -config "$openssl_cnf" -outform DER -out "$cert_csr_der" 2>/dev/null
    rm -f "$openssl_cnf"

    local csr_b64url
    csr_b64url=$(b64url < "$cert_csr_der")
    acme_request "$finalize_url" "{\"csr\": \"${csr_b64url}\"}" > /dev/null

    # Poll and Download
    local cert_url=""
    local tries=0
    while [[ $tries -lt 15 ]]; do
        sleep 2
        tries=$((tries + 1))
        local current_order
        current_order=$(acme_request "$order_url" "")
        if [[ $(echo "$current_order" | jq -r '.status') == "valid" ]]; then
            cert_url=$(echo "$current_order" | jq -r '.certificate // empty')
            break
        fi
    done

    local fullchain_pem="${cert_save_dir}/fullchain.pem"
    acme_request "$cert_url" "" > "$fullchain_pem"
    echo -e "${GREEN}[+] Certificate successfully renewed!${NC}"
    echo -e "Saved to: ${CYAN}${fullchain_pem}${NC}"
    openssl x509 -in "$fullchain_pem" -noout -subject -issuer -dates
}

# ------------------------------------------------------------------------------
# ACME API Primitives Test Menu Handlers
# ------------------------------------------------------------------------------

api_test_new_nonce() {
    echo -e "\n${BOLD}--- [API TEST] HEAD/GET New-Nonce ---${NC}"
    fetch_directory || return 1
    local nonce
    nonce=$(get_new_nonce)
    echo -e "Received fresh Nonce: ${CYAN}${nonce}${NC}"
}

api_test_new_acct() {
    echo -e "\n${BOLD}--- [API TEST] POST New-Account (Registration) ---${NC}"
    ensure_account_key
    fetch_directory || return 1

    read -r -p "Enter contact email [${ACCOUNT_EMAIL}]: " input_email
    if [[ -n "$input_email" ]]; then ACCOUNT_EMAIL="$input_email"; save_config; fi

    local payload
    payload=$(jq -n -c \
        --arg email "mailto:${ACCOUNT_EMAIL}" \
        '{"termsOfServiceAgreed": true, "contact": [$email]}')

    echo -e "Sending newAccount payload:"
    echo "$payload" | jq .

    local headers
    headers=$(mktemp)
    local resp
    resp=$(acme_request "$API_NEW_ACCOUNT" "$payload" "$ACCOUNT_KEY" "" "$headers")

    local acct_url
    acct_url=$(grep -i '^location:' "$headers" | tr -d '\r' | awk '{print $2}' | tail -n 1)
    rm -f "$headers"

    if [[ -n "$acct_url" ]]; then
        echo "$acct_url" > "$ACCOUNT_URL_FILE"
        echo -e "${GREEN}[+] Account registered/retrieved!${NC}"
        echo -e "Account URL (kid): ${CYAN}${acct_url}${NC}"
    fi
    echo "$resp" | jq . 2>/dev/null || echo "$resp"
}

api_test_query_existing_acct() {
    echo -e "\n${BOLD}--- [API TEST] POST New-Account (onlyReturnExisting) ---${NC}"
    ensure_account_key
    fetch_directory || return 1

    local payload='{"onlyReturnExisting": true}'
    local headers
    headers=$(mktemp)
    local resp
    resp=$(acme_request "$API_NEW_ACCOUNT" "$payload" "$ACCOUNT_KEY" "" "$headers")
    local acct_url
    acct_url=$(grep -i '^location:' "$headers" | tr -d '\r' | awk '{print $2}' | tail -n 1)
    rm -f "$headers"

    if [[ -n "$acct_url" ]]; then
        echo "$acct_url" > "$ACCOUNT_URL_FILE"
        echo -e "${GREEN}[+] Existing Account found!${NC}"
        echo -e "Account URL (kid): ${CYAN}${acct_url}${NC}"
    else
        echo -e "${YELLOW}[!] Account lookup returned without Location header.${NC}"
    fi
    echo "$resp" | jq . 2>/dev/null || echo "$resp"
}

api_test_account_mgmt() {
    echo -e "\n${BOLD}--- [API TEST] Account Management (Update / Deactivate) ---${NC}"
    if [[ ! -f "$ACCOUNT_URL_FILE" ]]; then
        echo -e "${RED}[ERROR] No account URL found. Register or query an account first.${NC}"
        return 1
    fi
    local acct_url
    acct_url=$(cat "$ACCOUNT_URL_FILE")
    echo -e "Target Account URL: ${CYAN}${acct_url}${NC}"

    echo "1) Update Contact Email"
    echo "2) Deactivate Account (status: deactivated)"
    echo "3) Back"
    read -r -p "Choose option: " opt
    case "$opt" in
        1)
            read -r -p "Enter new contact email: " new_mail
            local payload
            payload=$(jq -n -c --arg m "mailto:${new_mail}" '{"contact": [$m]}')
            local resp
            resp=$(acme_request "$acct_url" "$payload")
            echo "$resp" | jq . 2>/dev/null || echo "$resp"
            ;;
        2)
            read -r -p "Are you sure you want to DEACTIVATE this account? (yes/no): " confirm
            if [[ "$confirm" == "yes" ]]; then
                local resp
                resp=$(acme_request "$acct_url" '{"status": "deactivated"}')
                echo "$resp" | jq . 2>/dev/null || echo "$resp"
                rm -f "$ACCOUNT_URL_FILE"
                echo -e "${YELLOW}[!] Account marked deactivated.${NC}"
            fi
            ;;
        *)
            ;;
    esac
}

api_test_key_change() {
    echo -e "\n${BOLD}--- [API TEST] POST Key-Change (RFC 8555 §7.3.5 Account Key Rollover) ---${NC}"
    ensure_account_key
    fetch_directory || return 1
    if [[ ! -f "$ACCOUNT_URL_FILE" ]]; then
        echo -e "${RED}[ERROR] Account URL required for key-change. Register account first.${NC}"
        return 1
    fi
    local acct_url
    acct_url=$(cat "$ACCOUNT_URL_FILE")

    # Generate new RSA key for rollover
    local new_key="${WORKSPACE_DIR}/new_account.key"
    echo -e "[*] Generating replacement 2048-bit RSA key at: ${new_key}..."
    openssl genrsa -out "$new_key" 2048 2>/dev/null

    local old_info
    old_info=$(get_jwk_and_thumbprint "$ACCOUNT_KEY")
    local old_jwk
    old_jwk=$(echo "$old_info" | jq -c '.jwk')

    local new_info
    new_info=$(get_jwk_and_thumbprint "$new_key")
    local new_jwk
    new_jwk=$(echo "$new_info" | jq -c '.jwk')

    # Step 1: Inner JWS signed with NEW key
    local inner_payload
    inner_payload=$(jq -n -c \
        --arg acct "$acct_url" \
        --argjson oldKey "$old_jwk" \
        '{"account": $acct, "oldKey": $oldKey}')

    local inner_protected
    inner_protected=$(jq -n -c \
        --arg alg "RS256" \
        --argjson jwk "$new_jwk" \
        --arg url "$API_KEY_CHANGE" \
        '{"alg": $alg, "jwk": $jwk, "url": $url}')

    local inner_prot_b64
    inner_prot_b64=$(b64url_str "$inner_protected")
    local inner_pay_b64
    inner_pay_b64=$(b64url_str "$inner_payload")
    local inner_sig
    inner_sig=$(printf "%s" "${inner_prot_b64}.${inner_pay_b64}" | openssl dgst -sha256 -sign "$new_key" | b64url)

    local inner_jws
    inner_jws=$(jq -n -c \
        --arg prot "$inner_prot_b64" \
        --arg pay "$inner_pay_b64" \
        --arg sig "$inner_sig" \
        '{"protected": $prot, "payload": $pay, "signature": $sig}')

    echo -e "Constructed Inner JWS (signed by NEW key):"
    echo "$inner_jws" | jq .

    # Step 2: Outer JWS signed with OLD key, containing inner JWS as payload
    echo -e "\nSending KeyChange request to: ${CYAN}${API_KEY_CHANGE}${NC}..."
    local resp
    resp=$(acme_request "$API_KEY_CHANGE" "$inner_jws" "$ACCOUNT_KEY" "$acct_url")

    echo "Response:"
    echo "$resp" | jq . 2>/dev/null || echo "$resp"

    read -r -p "Replace old account key with new key in workspace? [Y/n]: " yn_swap
    if [[ ! "$yn_swap" =~ ^[Nn] ]]; then
        mv "$new_key" "$ACCOUNT_KEY"
        echo -e "${GREEN}[+] Account key updated!${NC}"
    else
        rm -f "$new_key"
    fi
}

api_test_new_order() {
    echo -e "\n${BOLD}--- [API TEST] POST New-Order ---${NC}"
    ensure_account_key
    fetch_directory || return 1

    read -r -p "Enter domains (space or comma separated): " raw_domains
    if [[ -z "$raw_domains" ]]; then echo -e "${RED}Domains required.${NC}"; return 1; fi

    local identifiers_json="[]"
    for d in $(echo "$raw_domains" | tr ',' ' '); do
        d=$(echo "$d" | tr -d '[:space:]')
        identifiers_json=$(echo "$identifiers_json" | jq --arg dom "$d" '. += [{"type": "dns", "value": $dom}]')
    done

    read -r -p "notBefore (RFC 3339 or empty): " not_before
    read -r -p "notAfter  (RFC 3339 or empty): " not_after

    local payload
    payload=$(jq -n -c --argjson idents "$identifiers_json" '{"identifiers": $idents}')
    if [[ -n "$not_before" ]]; then payload=$(echo "$payload" | jq --arg nb "$not_before" '. + {"notBefore": $nb}'); fi
    if [[ -n "$not_after" ]]; then payload=$(echo "$payload" | jq --arg na "$not_after" '. + {"notAfter": $na}'); fi

    local headers
    headers=$(mktemp)
    local resp
    resp=$(acme_request "$API_NEW_ORDER" "$payload" "$ACCOUNT_KEY" "" "$headers")
    local order_url
    order_url=$(grep -i '^location:' "$headers" | tr -d '\r' | awk '{print $2}' | tail -n 1)
    rm -f "$headers"

    if [[ -n "$order_url" ]]; then
        echo -e "${GREEN}[+] Order Location:${NC} ${CYAN}${order_url}${NC}"
        echo "$order_url" > "${WORKSPACE_DIR}/last_order_url.txt"
    fi
    echo "$resp" | jq . 2>/dev/null || echo "$resp"
}

api_test_query_order() {
    echo -e "\n${BOLD}--- [API TEST] Query Order (POST-as-GET) ---${NC}"
    local def_url=""
    if [[ -f "${WORKSPACE_DIR}/last_order_url.txt" ]]; then
        def_url=$(cat "${WORKSPACE_DIR}/last_order_url.txt")
    fi
    read -r -p "Enter Order URL [${def_url}]: " input_url
    local target="${input_url:-$def_url}"
    if [[ -z "$target" ]]; then echo -e "${RED}Order URL required.${NC}"; return 1; fi

    local resp
    resp=$(acme_request "$target" "")
    echo "$resp" | jq . 2>/dev/null || echo "$resp"
}

api_test_query_authz() {
    echo -e "\n${BOLD}--- [API TEST] Query Authorization & Challenges (POST-as-GET) ---${NC}"
    read -r -p "Enter Authorization URL: " authz_url
    if [[ -z "$authz_url" ]]; then echo -e "${RED}Authz URL required.${NC}"; return 1; fi

    local resp
    resp=$(acme_request "$authz_url" "")
    echo "$resp" | jq . 2>/dev/null || echo "$resp"
}

api_test_respond_challenge() {
    echo -e "\n${BOLD}--- [API TEST] Trigger Challenge Validation (POST) ---${NC}"
    read -r -p "Enter Challenge URL: " chal_url
    read -r -p "Enter Token: " token
    if [[ -z "$chal_url" || -z "$token" ]]; then
        echo -e "${RED}Challenge URL and Token required.${NC}"
        return 1
    fi

    local key_info
    key_info=$(get_jwk_and_thumbprint "$ACCOUNT_KEY")
    local thumbprint
    thumbprint=$(echo "$key_info" | jq -r '.thumbprint')
    local key_auth="${token}.${thumbprint}"

    echo -e "Writing challenge response: ${CYAN}${key_auth}${NC} to ${CHALLENGE_DIR}/${token}"
    echo -n "$key_auth" > "${CHALLENGE_DIR}/${token}"

    read -r -p "Ensure HTTP challenge server is running? [Y/n]: " yn_http
    if [[ ! "$yn_http" =~ ^[Nn] ]]; then
        start_standalone_http
    fi

    echo -e "Posting empty challenge response to: ${CYAN}${chal_url}${NC}..."
    local resp
    resp=$(acme_request "$chal_url" "{}")
    echo "$resp" | jq . 2>/dev/null || echo "$resp"
}

api_test_finalize_order() {
    echo -e "\n${BOLD}--- [API TEST] Finalize Order (POST CSR) ---${NC}"
    read -r -p "Enter Finalize URL: " finalize_url
    read -r -p "Enter path to CSR (DER format) or press Enter to generate one: " csr_path

    local temp_csr=""
    if [[ -z "$csr_path" || ! -f "$csr_path" ]]; then
        read -r -p "Enter domain for CSR: " csr_dom
        local temp_key
        temp_key=$(mktemp)
        temp_csr=$(mktemp)
        openssl genrsa -out "$temp_key" 2048 2>/dev/null
        openssl req -new -sha256 -key "$temp_key" -subj "/CN=${csr_dom}" -outform DER -out "$temp_csr" 2>/dev/null
        csr_path="$temp_csr"
        rm -f "$temp_key"
    fi

    local csr_b64
    csr_b64=$(b64url < "$csr_path")
    if [[ -n "$temp_csr" ]]; then rm -f "$temp_csr"; fi

    local resp
    resp=$(acme_request "$finalize_url" "{\"csr\": \"${csr_b64}\"}")
    echo "$resp" | jq . 2>/dev/null || echo "$resp"
}

api_test_download_cert() {
    echo -e "\n${BOLD}--- [API TEST] Download Certificate (POST-as-GET) ---${NC}"
    read -r -p "Enter Certificate URL: " cert_url
    if [[ -z "$cert_url" ]]; then echo -e "${RED}Certificate URL required.${NC}"; return 1; fi

    local out_file="${WORKSPACE_DIR}/downloaded_cert.pem"
    acme_request "$cert_url" "" > "$out_file"
    echo -e "${GREEN}[+] Saved to: ${CYAN}${out_file}${NC}"
    openssl x509 -in "$out_file" -noout -subject -issuer -dates 2>/dev/null || cat "$out_file"
}

api_test_revoke_cert() {
    echo -e "\n${BOLD}--- [API TEST] POST Revoke-Cert ---${NC}"
    fetch_directory || return 1

    read -r -p "Enter path to certificate PEM file to revoke: " cert_file
    if [[ ! -f "$cert_file" ]]; then echo -e "${RED}File not found.${NC}"; return 1; fi

    echo "RFC 5280 Revocation Reason Codes:"
    echo "  0: unspecified"
    echo "  1: keyCompromise"
    echo "  3: affiliationChanged"
    echo "  4: superseded"
    echo "  5: cessationOfOperation"
    read -r -p "Enter reason code [0]: " reason_code
    reason_code="${reason_code:-0}"

    local cert_der_b64
    cert_der_b64=$(openssl x509 -in "$cert_file" -outform DER | b64url)

    local payload
    payload=$(jq -n -c \
        --arg cert "$cert_der_b64" \
        --argjson reason "$reason_code" \
        '{"certificate": $cert, "reason": $reason}')

    echo -e "Sending revocation request to: ${CYAN}${API_REVOKE_CERT}${NC}..."
    local resp
    resp=$(acme_request "$API_REVOKE_CERT" "$payload")
    if [[ -z "$resp" ]]; then
        echo -e "${GREEN}[+] Certificate successfully revoked (200 OK empty response).${NC}"
    else
        echo "$resp" | jq . 2>/dev/null || echo "$resp"
    fi
}

api_test_ari() {
    echo -e "\n${BOLD}--- [API TEST] Renewal Information (ARI - RFC 9444) ---${NC}"
    fetch_directory || return 1
    if [[ -z "$API_RENEWAL_INFO" ]]; then
        echo -e "${YELLOW}[!] This ACME CA does not advertise renewalInfo in directory.${NC}"
        return 0
    fi
    read -r -p "Enter Certificate Serial (hex) or path to cert PEM: " input_val
    local cert_serial="$input_val"
    if [[ -f "$input_val" ]]; then
        cert_serial=$(openssl x509 -in "$input_val" -noout -serial | cut -d= -f2)
    fi
    local url="${API_RENEWAL_INFO}/${cert_serial}"
    echo -e "Fetching ARI from: ${CYAN}${url}${NC}..."
    curl -s "$url" | jq .
}

# ------------------------------------------------------------------------------
# Submenu: Individual API Tests
# ------------------------------------------------------------------------------
menu_api_tests() {
    while true; do
        echo -e "\n${BOLD}======================================================${NC}"
        echo -e "${BOLD}            ACME API PRIMITIVE TEST MENU              ${NC}"
        echo -e "${BOLD}======================================================${NC}"
        echo -e "  [${CYAN}1${NC}] GET Directory (${ACME_DIRECTORY_URL})"
        echo -e "  [${CYAN}2${NC}] GET/HEAD New-Nonce"
        echo -e "  [${CYAN}3${NC}] POST New-Account (Register)"
        echo -e "  [${CYAN}4${NC}] POST New-Account (Query Existing)"
        echo -e "  [${CYAN}5${NC}] Account Management (Update Contact / Deactivate)"
        echo -e "  [${CYAN}6${NC}] POST Key-Change (Account Key Rollover §7.3.5)"
        echo -e "  [${CYAN}7${NC}] POST New-Order (Custom domains & validity period)"
        echo -e "  [${CYAN}8${NC}] POST-as-GET Query Order"
        echo -e "  [${CYAN}9${NC}] POST-as-GET Query Authorization & Challenges"
        echo -e "  [${CYAN}10${NC}] POST Trigger Challenge (HTTP-01)"
        echo -e "  [${CYAN}11${NC}] POST Finalize Order (CSR)"
        echo -e "  [${CYAN}12${NC}] POST-as-GET Download Certificate"
        echo -e "  [${CYAN}13${NC}] POST Revoke-Cert"
        echo -e "  [${CYAN}14${NC}] GET ARI Renewal Information (RFC 9444)"
        echo -e "  [${CYAN}B${NC}] Back to Main Menu"
        read -r -p "Select option: " subopt
        case "$subopt" in
            1) api_test_new_nonce ;; # calls directory & new-nonce
            2) api_test_new_nonce ;;
            3) api_test_new_acct ;;
            4) api_test_query_existing_acct ;;
            5) api_test_account_mgmt ;;
            6) api_test_key_change ;;
            7) api_test_new_order ;;
            8) api_test_query_order ;;
            9) api_test_query_authz ;;
            10) api_test_respond_challenge ;;
            11) api_test_finalize_order ;;
            12) api_test_download_cert ;;
            13) api_test_revoke_cert ;;
            14) api_test_ari ;;
            [Bb]|"") break ;;
            *) echo -e "${RED}Invalid option.${NC}" ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Settings Configuration
# ------------------------------------------------------------------------------
configure_settings() {
    echo -e "\n${BOLD}--- SETTINGS CONFIGURATION ---${NC}"
    echo -e "Current ACME Server:     ${CYAN}${ACME_DIRECTORY_URL}${NC}"
    echo -e "Current Challenge Port:  ${CYAN}${HTTP_CHALLENGE_PORT}${NC}"
    echo -e "Current Account Email:   ${CYAN}${ACCOUNT_EMAIL}${NC}"

    read -r -p "Change ACME Server URL [Enter to keep]: " new_srv
    if [[ -n "$new_srv" ]]; then ACME_DIRECTORY_URL="$new_srv"; fi

    read -r -p "Change HTTP Challenge Port [Enter to keep]: " new_port
    if [[ -n "$new_port" ]]; then HTTP_CHALLENGE_PORT="$new_port"; fi

    read -r -p "Change Account Email [Enter to keep]: " new_mail
    if [[ -n "$new_mail" ]]; then ACCOUNT_EMAIL="$new_mail"; fi

    save_config
    echo -e "${GREEN}[+] Settings updated.${NC}"
    fetch_directory
}

# ------------------------------------------------------------------------------
# Startup Prompt: Server and HTTP Challenge Port
# ------------------------------------------------------------------------------
startup_initialization() {
    echo -e "${BOLD}${CYAN}"
    echo "=========================================================="
    echo "           ACME RFC 8555 TEST HARNESS & CLIENT            "
    echo "=========================================================="
    echo -e "${NC}"

    # Prompt for destination ACME server URL
    read -r -p "Enter destination ACME Server Directory URL [${ACME_DIRECTORY_URL}]: " input_server
    if [[ -n "$input_server" ]]; then
        ACME_DIRECTORY_URL="$input_server"
    fi

    # Prompt for custom HTTP challenge server port
    read -r -p "Enter standalone HTTP Challenge Server Port [${HTTP_CHALLENGE_PORT}]: " input_port
    if [[ -n "$input_port" ]]; then
        HTTP_CHALLENGE_PORT="$input_port"
    fi

    save_config
    ensure_account_key
    fetch_directory || true
}

# ------------------------------------------------------------------------------
# Main Menu Loop
# ------------------------------------------------------------------------------
main_menu() {
    startup_initialization

    while true; do
        local acct_status="None (Not registered)"
        if [[ -f "$ACCOUNT_URL_FILE" ]]; then
            acct_status=$(cat "$ACCOUNT_URL_FILE")
        fi

        echo -e "\n${BOLD}======================================================${NC}"
        echo -e "${BOLD}                    MAIN MENU                         ${NC}"
        echo -e "${BOLD}======================================================${NC}"
        echo -e " ACME Server:     ${CYAN}${ACME_DIRECTORY_URL}${NC}"
        echo -e " HTTP Port:       ${CYAN}${HTTP_CHALLENGE_PORT}${NC}"
        echo -e " Account Key:     ${CYAN}${ACCOUNT_KEY}${NC}"
        echo -e " Account URL:     ${CYAN}${acct_status}${NC}"
        echo -e "------------------------------------------------------"
        echo -e "  [${GREEN}1${NC}] Request New Certificate (End-to-End Workflow)"
        echo -e "  [${GREEN}2${NC}] Renew Existing Certificate (Workflow)"
        echo -e "  [${CYAN}3${NC}] ACME API Test Suite (Individual Primitives)"
        echo -e "  [${YELLOW}4${NC}] Standalone HTTP Challenge Server Controls"
        echo -e "  [${MAGENTA}5${NC}] Change Settings (Server / Port / Email / Keys)"
        echo -e "  [${RED}6${NC}] Exit"
        echo -e "------------------------------------------------------"
        read -r -p "Select option [1-6]: " choice

        case "$choice" in
            1) workflow_new_cert ;;
            2) workflow_renew_cert ;;
            3) menu_api_tests ;;
            4)
                echo -e "\n[1] Start Server  [2] Stop Server  [3] Test Challenge Path  [4] View Log"
                read -r -p "Choice: " h_opt
                case "$h_opt" in
                    1) start_standalone_http ;;
                    2) stop_standalone_http ;;
                    3)
                        echo -n "test_token_content" > "${CHALLENGE_DIR}/test"
                        echo -e "Testing fetch from: http://localhost:${HTTP_CHALLENGE_PORT}/.well-known/acme-challenge/test"
                        curl -i "http://localhost:${HTTP_CHALLENGE_PORT}/.well-known/acme-challenge/test"
                        rm -f "${CHALLENGE_DIR}/test"
                        ;;
                    4)
                        if [[ -f "$HTTP_LOG" ]]; then cat "$HTTP_LOG"; else echo "No log file found."; fi
                        ;;
                esac
                ;;
            5) configure_settings ;;
            6)
                stop_standalone_http
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice. Please select 1-6.${NC}"
                ;;
        esac
    done
}

# Trap exit to cleanup background HTTP server
trap stop_standalone_http EXIT

# Run
main_menu
