#!/usr/bin/env bash
#
# analyze_email_links.sh - Forensic Analysis Tool for Email Links (Phishing Detection)
#
# Purpose: Passive and controlled evidence collection from URLs found in emails
# Usage: ./analyze_email_links.sh urls.txt [output_dir] [options]
#
# Security: NO exploitation, NO brute force, NO JavaScript execution
# Focus: Safe forensic collection with curl, DNS, TLS inspection
#

set -euo pipefail

# ============================================================================
# CONFIGURATION & DEFAULTS
# ============================================================================

VERSION="2.0.0"
SCRIPT_NAME="$(basename "$0")"

# Defaults
FOLLOW_REDIRECTS=1
MAX_REDIRECTS=5
TIMEOUT=20
MAX_BYTES=200  # KB
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
ENABLE_DNS=1
ENABLE_TLS=1
RATE_LIMIT=0  # milliseconds between requests
VERBOSE=0

# Known legitimate domains (whitelist)
declare -A LEGITIMATE_DOMAINS=(
    ["microsoft.com"]=1 ["google.com"]=1 ["apple.com"]=1 ["amazon.com"]=1
    ["facebook.com"]=1 ["linkedin.com"]=1 ["twitter.com"]=1 ["github.com"]=1
    ["paypal.com"]=1 ["netflix.com"]=1 ["dropbox.com"]=1 ["adobe.com"]=1
    ["salesforce.com"]=1 ["office.com"]=1 ["outlook.com"]=1 ["live.com"]=1
    ["microsoftonline.com"]=1 ["office365.com"]=1 ["onmicrosoft.com"]=1
)

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS="xyz|top|work|click|link|online|site|info|club|icu|buzz|tk|ml|ga|cf|gq|pw"

# Free SSL providers (often used by phishers)
FREE_SSL_ISSUERS="Let's Encrypt|ZeroSSL|Cloudflare|cPanel|SSL.com Free"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

log() {
    echo -e "${CYAN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" >&2
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

usage() {
    cat <<EOF
${SCRIPT_NAME} v${VERSION} - Advanced Forensic Email Link Analysis Tool

USAGE:
    ${SCRIPT_NAME} <urls_file> [output_dir] [options]

ARGUMENTS:
    urls_file       Text file with one URL per line
    output_dir      Output directory (default: ./report_TIMESTAMP)

OPTIONS:
    --follow            Follow redirects (default)
    --no-follow         Do not follow redirects
    --max-redirs N      Maximum redirects to follow (default: 5)
    --timeout S         Connection timeout in seconds (default: 20)
    --max-bytes KB      Maximum response body size in KB (default: 200)
    --user-agent "..."  Custom User-Agent string
    --no-dns            Skip DNS resolution
    --no-tls            Skip TLS certificate inspection
    --rate-limit MS     Sleep MS milliseconds between URLs (default: 0)
    --verbose           Enable verbose output
    -h, --help          Show this help message

ANALYSIS FEATURES:
    • Risk scoring (0-100) with CRITICAL/HIGH/MEDIUM/LOW/MINIMAL levels
    • Typosquatting detection against 15+ major brands
    • Brand impersonation detection (Microsoft, Google, PayPal, etc.)
    • Urgency/fear language analysis
    • Credential harvesting detection (password, CC, SSN fields)
    • Obfuscation detection (Base64, eval, hex encoding)
    • URL structure analysis (suspicious TLDs, subdomains, encoding)
    • TLS certificate risk analysis (self-signed, expired, free CAs)
    • Security header audit (HSTS, CSP, X-Frame-Options)

EXAMPLES:
    ${SCRIPT_NAME} suspicious_links.txt
    ${SCRIPT_NAME} urls.txt ./evidence --max-redirs 3 --timeout 10
    ${SCRIPT_NAME} urls.txt --no-follow --rate-limit 500

SECURITY:
    - Passive collection only (no exploitation)
    - No JavaScript execution
    - No browser automation
    - Controlled timeouts and size limits
    - Redacts sensitive parameters in reports

EOF
    exit 0
}

# Sanitize string for use in filenames
sanitize_filename() {
    local input="$1"
    echo "$input" | sed 's/[^a-zA-Z0-9._-]/_/g' | cut -c1-200
}

# Normalize URL: add scheme if missing, trim spaces
normalize_url() {
    local url="$1"
    # Trim whitespace
    url="$(echo "$url" | tr -d '[:space:]')"

    # Skip empty lines
    [[ -z "$url" ]] && return

    # Add https:// if no scheme
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="https://$url"
    fi

    echo "$url"
}

# Extract domain from URL
extract_domain() {
    local url="$1"
    echo "$url" | awk -F/ '{print $3}' | cut -d: -f1
}

# Redact sensitive parameters from URL for reporting
redact_url() {
    local url="$1"
    # Redact common sensitive parameters
    echo "$url" | sed -E 's/(token|password|pass|pwd|secret|key|session|sid|auth|api_key|apikey)=[^&]*/<REDACTED>/gi'
}

# Check required dependencies
check_dependencies() {
    local missing=()

    command -v curl >/dev/null 2>&1 || missing+=("curl")
    command -v openssl >/dev/null 2>&1 || missing+=("openssl")
    command -v sha256sum >/dev/null 2>&1 || missing+=("sha256sum")

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        log_error "Please install them and try again."
        exit 1
    fi

    # Optional dependencies
    if ! command -v dig >/dev/null 2>&1 && ! command -v host >/dev/null 2>&1; then
        log_warn "Neither 'dig' nor 'host' found. DNS resolution will be limited."
    fi
}

# ============================================================================
# ADVANCED PHISHING DETECTION FUNCTIONS
# ============================================================================

# Calculate Levenshtein distance (for typosquatting detection)
levenshtein_distance() {
    local s1="$1"
    local s2="$2"
    local len1=${#s1}
    local len2=${#s2}
    
    # Use awk for calculation (bash arrays are slow for this)
    awk -v s1="$s1" -v s2="$s2" 'BEGIN {
        len1 = length(s1)
        len2 = length(s2)
        
        for (i = 0; i <= len1; i++) d[i,0] = i
        for (j = 0; j <= len2; j++) d[0,j] = j
        
        for (i = 1; i <= len1; i++) {
            for (j = 1; j <= len2; j++) {
                cost = (substr(s1,i,1) != substr(s2,j,1)) ? 1 : 0
                d[i,j] = d[i-1,j] + 1
                if (d[i,j-1] + 1 < d[i,j]) d[i,j] = d[i,j-1] + 1
                if (d[i-1,j-1] + cost < d[i,j]) d[i,j] = d[i-1,j-1] + cost
            }
        }
        print d[len1,len2]
    }'
}

# Check for typosquatting against known brands
check_typosquatting() {
    local domain="$1"
    local output_file="$2"
    
    # Extract the main domain without TLD
    local base_domain=$(echo "$domain" | sed -E 's/\.[a-z]{2,}$//' | sed -E 's/.*\.//')
    
    # Known brands to check against
    local brands=("microsoft" "google" "apple" "amazon" "facebook" "paypal" "netflix" "linkedin" "dropbox" "adobe" "outlook" "office" "onedrive" "sharepoint" "teams")
    
    {
        echo "## Typosquatting Analysis"
        echo ""
        
        local found_suspicious=0
        for brand in "${brands[@]}"; do
            # Skip if exact match
            [[ "$base_domain" == "$brand" ]] && continue
            
            # Check if domain contains the brand name
            if [[ "$domain" =~ $brand ]]; then
                echo "⚠️  Contains brand name '$brand' in domain: $domain"
                found_suspicious=1
            fi
            
            # Check Levenshtein distance (typos)
            local distance=$(levenshtein_distance "$base_domain" "$brand")
            if [[ $distance -le 2 && $distance -gt 0 ]]; then
                echo "⚠️  Similar to '$brand' (distance: $distance): $base_domain"
                found_suspicious=1
            fi
        done
        
        # Check for homograph attacks (mixed scripts, lookalikes)
        if echo "$domain" | grep -qE '[0oO]|[1lI]|[5sS]|rn'; then
            # Check specific patterns
            if [[ "$domain" =~ micro[s5]oft|g[o0][o0]gle|pay[p]a[l1]|amaz[o0]n|faceb[o0][o0]k ]]; then
                echo "⚠️  Possible homograph attack detected"
                found_suspicious=1
            fi
        fi
        
        [[ $found_suspicious -eq 0 ]] && echo "✓ No typosquatting patterns detected"
        
    } >> "$output_file"
}

# Analyze URL structure for suspicious patterns
analyze_url_structure() {
    local url="$1"
    local domain="$2"
    local output_file="$3"
    
    {
        echo "## URL Structure Analysis"
        echo ""
        
        local risk_factors=0
        
        # Check TLD
        local tld=$(echo "$domain" | grep -oE '\.[a-z]+$' | tr -d '.')
        if echo "$tld" | grep -qiE "^($SUSPICIOUS_TLDS)$"; then
            echo "⚠️  Suspicious TLD: .$tld"
            ((risk_factors++))
        fi
        
        # Check for IP address in URL
        if echo "$url" | grep -qE 'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'; then
            echo "🚨 URL uses IP address instead of domain name"
            ((risk_factors+=2))
        fi
        
        # Check subdomain depth
        local subdomain_count=$(echo "$domain" | tr '.' '\n' | wc -l)
        if [[ $subdomain_count -gt 4 ]]; then
            echo "⚠️  Excessive subdomains ($subdomain_count levels): $domain"
            ((risk_factors++))
        fi
        
        # Check for long random-looking subdomains
        local first_subdomain=$(echo "$domain" | cut -d. -f1)
        if [[ ${#first_subdomain} -gt 20 ]]; then
            echo "⚠️  Unusually long subdomain (${#first_subdomain} chars): ${first_subdomain:0:30}..."
            ((risk_factors++))
        fi
        
        # Check for suspicious URL patterns
        if echo "$url" | grep -qiE '(login|signin|verify|secure|account|update|confirm|suspend).*\?'; then
            echo "⚠️  Suspicious keywords with query parameters"
            ((risk_factors++))
        fi
        
        # Check for data URIs or javascript
        if echo "$url" | grep -qiE '^(data:|javascript:)'; then
            echo "🚨 Malicious URI scheme detected!"
            ((risk_factors+=3))
        fi
        
        # Check URL length (very long URLs are suspicious)
        if [[ ${#url} -gt 200 ]]; then
            echo "⚠️  Unusually long URL (${#url} characters)"
            ((risk_factors++))
        fi
        
        # Check for @ symbol (URL credential injection)
        if echo "$url" | grep -qE '@'; then
            echo "🚨 URL contains @ symbol (possible credential injection attack)"
            ((risk_factors+=2))
        fi
        
        # Check for URL encoding abuse
        local encoded_count=$(echo "$url" | grep -o '%' | wc -l)
        if [[ $encoded_count -gt 10 ]]; then
            echo "⚠️  Heavy URL encoding ($encoded_count encoded chars)"
            ((risk_factors++))
        fi
        
        # Check for double extensions
        if echo "$url" | grep -qiE '\.(php|asp|jsp|html?)\.[a-z]+'; then
            echo "⚠️  Double extension detected (possible spoofing)"
            ((risk_factors++))
        fi
        
        echo ""
        echo "URL Structure Risk Factors: $risk_factors"
        echo "URL_STRUCTURE_RISK=$risk_factors"
        
    } >> "$output_file"
}

# Analyze security headers
analyze_security_headers() {
    local headers_file="$1"
    local output_file="$2"
    
    [[ ! -f "$headers_file" ]] && return
    
    {
        echo "## Security Headers Analysis"
        echo ""
        
        local missing_headers=0
        local security_score=0
        
        # Check for important security headers
        if grep -qi "Strict-Transport-Security" "$headers_file" 2>/dev/null; then
            echo "✓ HSTS header present"
            ((security_score++))
        else
            echo "⚠️  Missing: Strict-Transport-Security (HSTS)"
            ((missing_headers++))
        fi
        
        if grep -qi "Content-Security-Policy" "$headers_file" 2>/dev/null; then
            echo "✓ CSP header present"
            ((security_score++))
        else
            echo "⚠️  Missing: Content-Security-Policy"
            ((missing_headers++))
        fi
        
        if grep -qi "X-Frame-Options" "$headers_file" 2>/dev/null; then
            echo "✓ X-Frame-Options present"
            ((security_score++))
        else
            echo "⚠️  Missing: X-Frame-Options"
            ((missing_headers++))
        fi
        
        if grep -qi "X-Content-Type-Options" "$headers_file" 2>/dev/null; then
            echo "✓ X-Content-Type-Options present"
            ((security_score++))
        else
            echo "⚠️  Missing: X-Content-Type-Options"
            ((missing_headers++))
        fi
        
        if grep -qi "X-XSS-Protection" "$headers_file" 2>/dev/null; then
            echo "✓ X-XSS-Protection present"
            ((security_score++))
        fi
        
        # Check server disclosure
        local server_header=$(grep -i "^server:" "$headers_file" 2>/dev/null | head -1)
        if [[ -n "$server_header" ]]; then
            if echo "$server_header" | grep -qiE 'apache|nginx|iis|cloudflare|litespeed'; then
                echo "ℹ️  Server: $server_header"
            fi
        fi
        
        # Check for suspicious headers
        if grep -qi "X-Powered-By" "$headers_file" 2>/dev/null; then
            local powered_by=$(grep -i "X-Powered-By" "$headers_file" | head -1)
            echo "ℹ️  $powered_by"
        fi
        
        echo ""
        echo "Security Headers Score: $security_score/5"
        echo "Missing Security Headers: $missing_headers"
        echo "SECURITY_HEADERS_SCORE=$security_score"
        echo "MISSING_HEADERS=$missing_headers"
        
    } >> "$output_file"
}

# Analyze TLS certificate for suspicious patterns
analyze_certificate_risk() {
    local cert_file="$1"
    local output_file="$2"
    
    [[ ! -f "$cert_file" ]] && return
    
    {
        echo "## Certificate Risk Analysis"
        echo ""
        
        local cert_risk=0
        
        # Check for free SSL (commonly used by phishers)
        if grep -qiE "$FREE_SSL_ISSUERS" "$cert_file" 2>/dev/null; then
            local issuer=$(grep -iE "$FREE_SSL_ISSUERS" "$cert_file" | head -1)
            echo "ℹ️  Free SSL Certificate detected: $issuer"
            # Not necessarily bad, but worth noting
        fi
        
        # Check for self-signed certificate
        if grep -q "self signed" "$cert_file" 2>/dev/null || \
           grep -q "verify error:num=18" "$cert_file" 2>/dev/null; then
            echo "🚨 Self-signed certificate detected!"
            ((cert_risk+=3))
        fi
        
        # Check certificate validity
        local not_before=$(grep -i "notBefore" "$cert_file" 2>/dev/null | head -1 | cut -d= -f2)
        local not_after=$(grep -i "notAfter" "$cert_file" 2>/dev/null | head -1 | cut -d= -f2)
        
        if [[ -n "$not_before" ]]; then
            echo "Certificate Valid From: $not_before"
            
            # Check if certificate is very new (< 30 days)
            local cert_start=$(date -d "$not_before" +%s 2>/dev/null || echo "0")
            local now=$(date +%s)
            local age_days=$(( (now - cert_start) / 86400 ))
            
            if [[ $cert_start -gt 0 && $age_days -lt 30 ]]; then
                echo "⚠️  Certificate is very new ($age_days days old)"
                ((cert_risk++))
            fi
        fi
        
        if [[ -n "$not_after" ]]; then
            echo "Certificate Valid Until: $not_after"
            
            # Check if certificate is expired
            local cert_end=$(date -d "$not_after" +%s 2>/dev/null || echo "0")
            local now=$(date +%s)
            
            if [[ $cert_end -gt 0 && $cert_end -lt $now ]]; then
                echo "🚨 Certificate is EXPIRED!"
                ((cert_risk+=3))
            fi
        fi
        
        # Check for wildcard certificate
        if grep -qE 'CN\s*=\s*\*\.' "$cert_file" 2>/dev/null; then
            echo "ℹ️  Wildcard certificate detected"
        fi
        
        # Check certificate verification status
        if grep -q "Verify return code: 0" "$cert_file" 2>/dev/null; then
            echo "✓ Certificate verification: OK"
        else
            local verify_code=$(grep "Verify return code:" "$cert_file" 2>/dev/null | head -1)
            if [[ -n "$verify_code" ]]; then
                echo "⚠️  $verify_code"
                ((cert_risk++))
            fi
        fi
        
        echo ""
        echo "Certificate Risk Score: $cert_risk"
        echo "CERT_RISK=$cert_risk"
        
    } >> "$output_file"
}

# ============================================================================
# EVIDENCE COLLECTION FUNCTIONS
# ============================================================================

# Perform DNS resolution
collect_dns() {
    local domain="$1"
    local output_file="$2"

    [[ $ENABLE_DNS -eq 0 ]] && return

    {
        echo "# DNS Resolution for: $domain"
        echo "# Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""

        # Try dig first (more detailed)
        if command -v dig >/dev/null 2>&1; then
            echo "## A Records (IPv4):"
            dig +short +time=3 +tries=2 A "$domain" 2>&1 || echo "(query failed)"
            echo ""

            echo "## AAAA Records (IPv6):"
            dig +short +time=3 +tries=2 AAAA "$domain" 2>&1 || echo "(query failed)"
            echo ""

            echo "## CNAME Records:"
            dig +short +time=3 +tries=2 CNAME "$domain" 2>&1 || echo "(query failed)"
            echo ""

            echo "## Full A Record Query:"
            dig +time=3 +tries=2 A "$domain" 2>&1 || echo "(query failed)"
        elif command -v host >/dev/null 2>&1; then
            echo "## Host lookup (fallback):"
            host -W 3 "$domain" 2>&1 || echo "(query failed)"
        else
            echo "No DNS tools available (dig/host not found)"
        fi
    } > "$output_file"
}

# Collect TLS certificate information
collect_tls() {
    local domain="$1"
    local output_file="$2"
    local cert_file="${output_file%.txt}_chain.pem"

    [[ $ENABLE_TLS -eq 0 ]] && return

    # Only for HTTPS
    local url="$3"
    [[ ! "$url" =~ ^https:// ]] && return

    # Extract port if specified, default 443
    local port=443
    if [[ "$domain" =~ :([0-9]+)$ ]]; then
        port="${BASH_REMATCH[1]}"
        domain="${domain%:*}"
    fi

    {
        echo "# TLS Certificate Information for: $domain:$port"
        echo "# Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""

        # Get certificate chain
        echo "## Certificate Chain:"
        timeout 10 openssl s_client -connect "$domain:$port" -servername "$domain" \
            -showcerts </dev/null 2>&1 | tee "$cert_file" | grep -E "^(subject|issuer|notBefore|notAfter|Verify return code)" || echo "(failed to retrieve)"

        echo ""
        echo "## Certificate Details:"
        if [[ -s "$cert_file" ]]; then
            # Extract first certificate
            openssl x509 -in "$cert_file" -noout -text 2>&1 || echo "(failed to parse)"

            echo ""
            echo "## SHA256 Fingerprint:"
            openssl x509 -in "$cert_file" -noout -fingerprint -sha256 2>&1 || echo "(failed to compute)"
        fi
    } > "$output_file"
}

# Collect HTTP headers (HEAD request)
collect_headers() {
    local url="$1"
    local output_file="$2"
    local stderr_file="${output_file}.stderr"

    local redirect_opt=""
    [[ $FOLLOW_REDIRECTS -eq 1 ]] && redirect_opt="--location --max-redirs $MAX_REDIRECTS"

    timeout "$TIMEOUT" curl -I \
        --user-agent "$USER_AGENT" \
        --connect-timeout "$TIMEOUT" \
        --max-time "$TIMEOUT" \
        $redirect_opt \
        --silent \
        --show-error \
        --write-out "\n\n# CURL INFO:\nhttp_code: %{http_code}\neffective_url: %{url_effective}\nredirect_count: %{num_redirects}\nsize_download: %{size_download}\ntime_total: %{time_total}\n" \
        "$url" > "$output_file" 2> "$stderr_file" || true
}

# Collect HTTP body (GET request)
collect_body() {
    local url="$1"
    local output_file="$2"
    local stderr_file="${output_file}.stderr"
    local headers_file="${output_file}.headers"

    local redirect_opt=""
    [[ $FOLLOW_REDIRECTS -eq 1 ]] && redirect_opt="--location --max-redirs $MAX_REDIRECTS"

    local max_bytes_bytes=$((MAX_BYTES * 1024))

    timeout "$TIMEOUT" curl \
        --user-agent "$USER_AGENT" \
        --connect-timeout "$TIMEOUT" \
        --max-time "$TIMEOUT" \
        --max-filesize "$max_bytes_bytes" \
        $redirect_opt \
        --silent \
        --show-error \
        --dump-header "$headers_file" \
        --output "$output_file" \
        "$url" 2> "$stderr_file" || true

    # Add curl info to headers file
    {
        echo ""
        echo "# CURL INFO:"
        timeout "$TIMEOUT" curl \
            --user-agent "$USER_AGENT" \
            --connect-timeout "$TIMEOUT" \
            --max-time "$TIMEOUT" \
            --max-filesize "$max_bytes_bytes" \
            $redirect_opt \
            --silent \
            --head \
            --write-out "http_code: %{http_code}\neffective_url: %{url_effective}\nredirect_count: %{num_redirects}\nsize_download: %{size_download}\ntime_total: %{time_total}\nspeed_download: %{speed_download}\n" \
            --output /dev/null \
            "$url" 2>/dev/null || true
    } >> "$headers_file"
}

# Extract redirect chain from headers
extract_redirects() {
    local headers_file="$1"
    grep -i "^location:" "$headers_file" 2>/dev/null | awk '{print $2}' | tr -d '\r' || true
}

# Extract effective URL from curl output
extract_effective_url() {
    local headers_file="$1"
    grep "effective_url:" "$headers_file" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\r' || true
}

# Extract HTTP status code
extract_status_code() {
    local headers_file="$1"
    grep "http_code:" "$headers_file" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\r' || true
}

# Extract Server header
extract_server() {
    local headers_file="$1"
    grep -i "^server:" "$headers_file" 2>/dev/null | head -1 | cut -d: -f2- | sed 's/^[[:space:]]*//' | tr -d '\r' || echo "N/A"
}

# Analyze content for suspicious indicators
analyze_content() {
    local body_file="$1"
    local output_file="$2"

    [[ ! -f "$body_file" ]] && return

    {
        echo "# Content Analysis"
        echo "# Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""

        local content_risk=0
        local suspicious_count=0

        # =====================================================================
        # BRAND IMPERSONATION DETECTION
        # =====================================================================
        echo "## Brand Impersonation Detection"
        echo ""
        
        local brand_patterns=(
            "microsoft:Microsoft"
            "office 365:Office 365"
            "outlook:Outlook"
            "onedrive:OneDrive"
            "sharepoint:SharePoint"
            "teams:Teams"
            "google:Google"
            "gmail:Gmail"
            "apple:Apple"
            "icloud:iCloud"
            "amazon:Amazon"
            "paypal:PayPal"
            "netflix:Netflix"
            "facebook:Facebook"
            "instagram:Instagram"
            "linkedin:LinkedIn"
            "bank of america:Bank of America"
            "wells fargo:Wells Fargo"
            "chase:Chase Bank"
            "dhl:DHL"
            "fedex:FedEx"
            "usps:USPS"
            "docusign:DocuSign"
        )
        
        local brands_found=0
        for brand_entry in "${brand_patterns[@]}"; do
            local pattern="${brand_entry%%:*}"
            local brand_name="${brand_entry##*:}"
            local count
            count=$(grep -ciE "$pattern" "$body_file" 2>/dev/null) || count=0
            if [[ $count -gt 0 ]]; then
                echo "  🏢 $brand_name mentioned: $count times"
                brands_found=$((brands_found + 1))
                content_risk=$((content_risk + 1))
            fi
        done
        
        [[ $brands_found -eq 0 ]] && echo "  ✓ No major brand mentions detected"
        
        # =====================================================================
        # URGENCY/FEAR LANGUAGE
        # =====================================================================
        echo ""
        echo "## Urgency & Fear Language"
        echo ""
        
        local urgency_patterns=(
            "urgent"
            "immediate"
            "expire"
            "suspended"
            "locked"
            "unusual activity"
            "unauthorized"
            "verify your"
            "confirm your"
            "update your"
            "within 24 hours"
            "within 48 hours"
            "action required"
            "account will be"
            "failure to"
            "last warning"
            "final notice"
        )
        
        local urgency_found=0
        for pattern in "${urgency_patterns[@]}"; do
            local count
            count=$(grep -ciE "$pattern" "$body_file" 2>/dev/null) || count=0
            if [[ $count -gt 0 ]]; then
                echo "  ⚠️  '$pattern': $count"
                urgency_found=$((urgency_found + 1))
                content_risk=$((content_risk + 2))
            fi
        done
        
        [[ $urgency_found -eq 0 ]] && echo "  ✓ No urgency language detected"
        echo "URGENCY_SCORE=$urgency_found"

        # =====================================================================
        # CREDENTIAL HARVESTING INDICATORS
        # =====================================================================
        echo ""
        echo "## Credential Harvesting Indicators"
        echo ""
        
        # Check forms
        local form_count
        form_count=$(grep -ciE "<form" "$body_file" 2>/dev/null) || form_count=0
        echo "Forms found: $form_count"
        
        # Check password fields
        local password_fields
        password_fields=$(grep -ciE 'type=["\x27]password' "$body_file" 2>/dev/null) || password_fields=0
        if [[ $password_fields -gt 0 ]]; then
            echo "🚨 Password input fields: $password_fields"
            content_risk=$((content_risk + 3))
        fi
        
        # Check email/username fields
        local email_fields
        email_fields=$(grep -ciE 'type=["\x27](email|text)["\x27].*name=["\x27].*(email|user|login)' "$body_file" 2>/dev/null) || email_fields=0
        local email_fields2
        email_fields2=$(grep -ciE 'name=["\x27].*(email|user|login).*type=["\x27](email|text)' "$body_file" 2>/dev/null) || email_fields2=0
        email_fields=$((email_fields + email_fields2))
        [[ $email_fields -gt 0 ]] && echo "⚠️  Email/Username fields: $email_fields"
        
        # Check for credit card patterns
        local cc_fields
        cc_fields=$(grep -ciE '(credit.?card|card.?number|cvv|cvc|expir)' "$body_file" 2>/dev/null) || cc_fields=0
        if [[ $cc_fields -gt 0 ]]; then
            echo "🚨 Credit card related fields: $cc_fields"
            content_risk=$((content_risk + 5))
        fi
        
        # Check for SSN patterns
        local ssn_fields
        ssn_fields=$(grep -ciE '(social.?security|ssn|tax.?id)' "$body_file" 2>/dev/null) || ssn_fields=0
        if [[ $ssn_fields -gt 0 ]]; then
            echo "🚨 SSN/Tax ID related fields: $ssn_fields"
            content_risk=$((content_risk + 5))
        fi
        
        # Form actions to external/suspicious URLs
        local ext_form_actions
        ext_form_actions=$(grep -oiE 'action=["\x27][^"\x27]+["\x27]' "$body_file" 2>/dev/null | grep -viE '(^#|^$|javascript:)' | head -5)
        if [[ -n "$ext_form_actions" ]]; then
            echo "Form actions found:"
            echo "$ext_form_actions" | while read -r action; do
                echo "  → $action"
            done
        fi
        
        echo "CREDENTIAL_FIELDS=$((password_fields + email_fields))"

        # =====================================================================
        # OBFUSCATION DETECTION
        # =====================================================================
        echo ""
        echo "## Obfuscation Detection"
        echo ""
        
        local obfuscation_score=0
        
        # Base64 encoded content
        local base64_count
        base64_count=$(grep -coE 'atob\(|btoa\(|base64' "$body_file" 2>/dev/null) || base64_count=0
        if [[ $base64_count -gt 0 ]]; then
            echo "⚠️  Base64 operations: $base64_count"
            obfuscation_score=$((obfuscation_score + 1))
        fi
        
        # Hex encoding
        local hex_count
        hex_count=$(grep -coE '\\x[0-9a-fA-F]{2}' "$body_file" 2>/dev/null) || hex_count=0
        if [[ $hex_count -gt 10 ]]; then
            echo "⚠️  Heavy hex encoding: $hex_count occurrences"
            obfuscation_score=$((obfuscation_score + 1))
        fi
        
        # Unicode escapes
        local unicode_count
        unicode_count=$(grep -coE '\\u[0-9a-fA-F]{4}' "$body_file" 2>/dev/null) || unicode_count=0
        if [[ $unicode_count -gt 10 ]]; then
            echo "⚠️  Heavy unicode escapes: $unicode_count"
            obfuscation_score=$((obfuscation_score + 1))
        fi
        
        # eval() usage
        local eval_count
        eval_count=$(grep -ciE '\beval\s*\(' "$body_file" 2>/dev/null) || eval_count=0
        if [[ $eval_count -gt 0 ]]; then
            echo "🚨 eval() usage detected: $eval_count"
            obfuscation_score=$((obfuscation_score + 2))
            content_risk=$((content_risk + 3))
        fi
        
        # document.write
        local docwrite_count
        docwrite_count=$(grep -ciE 'document\.write' "$body_file" 2>/dev/null) || docwrite_count=0
        if [[ $docwrite_count -gt 0 ]]; then
            echo "⚠️  document.write usage: $docwrite_count"
            obfuscation_score=$((obfuscation_score + 1))
        fi
        
        # String concatenation obfuscation
        local concat_obfusc
        concat_obfusc=$(grep -coE '\+\s*["\x27][a-zA-Z]{1,3}["\x27]\s*\+' "$body_file" 2>/dev/null) || concat_obfusc=0
        if [[ $concat_obfusc -gt 5 ]]; then
            echo "⚠️  String concatenation obfuscation detected"
            obfuscation_score=$((obfuscation_score + 1))
        fi
        
        # Minified/packed JavaScript (long lines without whitespace)
        local long_lines
        long_lines=$(awk 'length > 1000' "$body_file" 2>/dev/null | wc -l) || long_lines=0
        if [[ $long_lines -gt 0 ]]; then
            echo "ℹ️  Minified/packed content detected ($long_lines long lines)"
        fi
        
        [[ $obfuscation_score -eq 0 ]] && echo "✓ No significant obfuscation detected"
        echo "OBFUSCATION_SCORE=$obfuscation_score"
        content_risk=$((content_risk + obfuscation_score))

        # =====================================================================
        # REDIRECT & TRACKING
        # =====================================================================
        echo ""
        echo "## Redirect & Tracking Analysis"
        echo ""
        
        # Meta refresh
        local meta_refresh
        meta_refresh=$(grep -ciE 'http-equiv=["\x27]refresh' "$body_file" 2>/dev/null) || meta_refresh=0
        if [[ $meta_refresh -gt 0 ]]; then
            echo "⚠️  Meta refresh redirects: $meta_refresh"
            content_risk=$((content_risk + 1))
        fi
        
        # JavaScript redirects
        local js_redirect
        js_redirect=$(grep -ciE '(window\.location|location\.href|location\.replace)' "$body_file" 2>/dev/null) || js_redirect=0
        if [[ $js_redirect -gt 0 ]]; then
            echo "⚠️  JavaScript redirects: $js_redirect"
            content_risk=$((content_risk + 1))
        fi
        
        # Tracking pixels
        local tracking_pixels
        tracking_pixels=$(grep -ciE '(1x1|\.gif\?|\.png\?|pixel|beacon|track)' "$body_file" 2>/dev/null) || tracking_pixels=0
        if [[ $tracking_pixels -gt 0 ]]; then
            echo "ℹ️  Possible tracking pixels: $tracking_pixels"
        fi
        
        # Data exfiltration patterns
        local exfil_patterns
        exfil_patterns=$(grep -ciE '(XMLHttpRequest|fetch\(|\.ajax|sendBeacon)' "$body_file" 2>/dev/null) || exfil_patterns=0
        if [[ $exfil_patterns -gt 0 ]]; then
            echo "⚠️  Data transmission methods: $exfil_patterns"
        fi

        # =====================================================================
        # SCRIPT ANALYSIS
        # =====================================================================
        echo ""
        echo "## Script Analysis"
        echo ""
        
        local script_count
        script_count=$(grep -ciE "<script" "$body_file" 2>/dev/null) || script_count=0
        echo "Script tags: $script_count"
        
        # External scripts
        local ext_scripts
        ext_scripts=$(grep -oiE '<script[^>]+src=["\x27][^"\x27]+["\x27]' "$body_file" 2>/dev/null | head -10)
        if [[ -n "$ext_scripts" ]]; then
            echo "External scripts:"
            echo "$ext_scripts" | while read -r script; do
                local src=$(echo "$script" | grep -oE 'src=["\x27][^"\x27]+' | cut -d'"' -f2 | cut -d"'" -f2)
                echo "  → $src"
            done
        fi
        
        # Inline event handlers (often used in phishing)
        local inline_handlers
        inline_handlers=$(grep -coE '\bon(click|error|load|submit|focus|blur|mouseover)=' "$body_file" 2>/dev/null) || inline_handlers=0
        if [[ $inline_handlers -gt 5 ]]; then
            echo "⚠️  Inline event handlers: $inline_handlers"
            content_risk=$((content_risk + 1))
        fi

        # =====================================================================
        # EXTERNAL RESOURCES
        # =====================================================================
        echo ""
        echo "## External Resources (top 15)"
        echo ""
        grep -oiE '(src|href)=["\x27][^"\x27]+["\x27]' "$body_file" 2>/dev/null | \
            grep -viE '(^#|javascript:|data:)' | \
            sort -u | head -15 || echo "(none found)"

        # =====================================================================
        # SUMMARY
        # =====================================================================
        echo ""
        echo "## Content Risk Summary"
        echo ""
        echo "Total Content Risk Score: $content_risk"
        echo "Brands Mentioned: $brands_found"
        echo "Urgency Indicators: $urgency_found"
        echo "Password Fields: $password_fields"
        echo "CONTENT_RISK_SCORE=$content_risk"

    } > "$output_file"
}

# Calculate overall risk score (0-100)
calculate_risk_score() {
    local url_dir="$1"
    local output_file="$2"
    
    local total_score=0
    local max_score=100
    
    {
        echo "# Risk Score Calculation"
        echo "# Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""
        
        # Read various risk factors from analysis files
        local content_risk=0
        local url_risk=0
        local cert_risk=0
        local header_score=0
        
        # Content risk
        if [[ -f "$url_dir/analysis/content_analysis.txt" ]]; then
            content_risk=$(grep "CONTENT_RISK_SCORE=" "$url_dir/analysis/content_analysis.txt" 2>/dev/null | cut -d= -f2 | head -1)
            content_risk=${content_risk:-0}
        fi
        
        # URL structure risk
        if [[ -f "$url_dir/analysis/url_analysis.txt" ]]; then
            url_risk=$(grep "URL_STRUCTURE_RISK=" "$url_dir/analysis/url_analysis.txt" 2>/dev/null | cut -d= -f2 | head -1)
            url_risk=${url_risk:-0}
        fi
        
        # Certificate risk
        if [[ -f "$url_dir/analysis/url_analysis.txt" ]]; then
            cert_risk=$(grep "CERT_RISK=" "$url_dir/analysis/url_analysis.txt" 2>/dev/null | cut -d= -f2 | head -1)
            cert_risk=${cert_risk:-0}
        fi
        
        # Security headers (inverse - more missing = higher risk)
        if [[ -f "$url_dir/analysis/url_analysis.txt" ]]; then
            local missing_headers=$(grep "MISSING_HEADERS=" "$url_dir/analysis/url_analysis.txt" 2>/dev/null | cut -d= -f2 | head -1)
            missing_headers=${missing_headers:-0}
            header_score=$((missing_headers * 2))
        fi
        
        # Check for redirects
        local redirect_count=0
        if [[ -f "$url_dir/metadata.env" ]]; then
            source "$url_dir/metadata.env"
            redirect_count=${REDIRECT_COUNT:-0}
            redirect_count=$(echo "$redirect_count" | tr -d '"')
        fi
        
        # Calculate weighted score
        local content_weight=40   # Content analysis is heavily weighted
        local url_weight=20       # URL structure
        local cert_weight=15      # Certificate issues
        local header_weight=10    # Security headers
        local redirect_weight=15  # Redirects
        
        # Normalize and weight scores
        local content_normalized=$(( content_risk > 20 ? 20 : content_risk ))
        local content_score=$(( (content_normalized * content_weight) / 20 ))
        
        local url_normalized=$(( url_risk > 10 ? 10 : url_risk ))
        local url_score=$(( (url_normalized * url_weight) / 10 ))
        
        local cert_normalized=$(( cert_risk > 5 ? 5 : cert_risk ))
        local cert_score=$(( (cert_normalized * cert_weight) / 5 ))
        
        local header_normalized=$(( header_score > 10 ? 10 : header_score ))
        local header_final=$(( (header_normalized * header_weight) / 10 ))
        
        local redirect_normalized=$(( redirect_count > 3 ? 3 : redirect_count ))
        local redirect_score=$(( (redirect_normalized * redirect_weight) / 3 ))
        
        total_score=$((content_score + url_score + cert_score + header_final + redirect_score))
        
        # Ensure score is between 0 and 100
        [[ $total_score -gt 100 ]] && total_score=100
        [[ $total_score -lt 0 ]] && total_score=0
        
        echo "## Score Breakdown"
        echo ""
        echo "| Category | Raw Score | Weighted |"
        echo "|----------|-----------|----------|"
        echo "| Content Analysis | $content_risk | $content_score/$content_weight |"
        echo "| URL Structure | $url_risk | $url_score/$url_weight |"
        echo "| Certificate | $cert_risk | $cert_score/$cert_weight |"
        echo "| Security Headers | $header_score | $header_final/$header_weight |"
        echo "| Redirects | $redirect_count | $redirect_score/$redirect_weight |"
        echo ""
        echo "## Final Risk Score: $total_score/100"
        echo ""
        
        # Risk level classification
        local risk_level=""
        local risk_emoji=""
        if [[ $total_score -ge 70 ]]; then
            risk_level="CRITICAL"
            risk_emoji="🚨"
        elif [[ $total_score -ge 50 ]]; then
            risk_level="HIGH"
            risk_emoji="🔴"
        elif [[ $total_score -ge 30 ]]; then
            risk_level="MEDIUM"
            risk_emoji="🟠"
        elif [[ $total_score -ge 15 ]]; then
            risk_level="LOW"
            risk_emoji="🟡"
        else
            risk_level="MINIMAL"
            risk_emoji="🟢"
        fi
        
        echo "Risk Level: $risk_emoji $risk_level"
        echo ""
        echo "RISK_SCORE=$total_score"
        echo "RISK_LEVEL=$risk_level"
        
    } > "$output_file"
    
    # Return the score for use in metadata
    echo "$total_score"
}

# Compute SHA256 hash of a file
compute_hash() {
    local file="$1"
    [[ ! -f "$file" ]] && return
    sha256sum "$file" 2>/dev/null | awk '{print $1}' || echo "N/A"
}

# ============================================================================
# MAIN ANALYSIS FUNCTION
# ============================================================================

analyze_url() {
    local original_url="$1"
    local url_dir="$2"
    local index="$3"

    log_info "[$index] Analyzing: $(redact_url "$original_url")"

    # Create URL-specific directory
    mkdir -p "$url_dir"/{raw,dns,tls,analysis}

    local domain=$(extract_domain "$original_url")
    local url_safe=$(sanitize_filename "$original_url")

    # Collect evidence
    log "  → Collecting headers..."
    collect_headers "$original_url" "$url_dir/raw/headers.txt"

    log "  → Collecting body..."
    collect_body "$original_url" "$url_dir/raw/body.html"

    log "  → Resolving DNS..."
    collect_dns "$domain" "$url_dir/dns/resolution.txt"

    log "  → Inspecting TLS..."
    collect_tls "$domain" "$url_dir/tls/certificate.txt" "$original_url"

    log "  → Analyzing content..."
    analyze_content "$url_dir/raw/body.html" "$url_dir/analysis/content_analysis.txt"

    # Extract metadata
    local effective_url=$(extract_effective_url "$url_dir/raw/body.html.headers")
    local status_code=$(extract_status_code "$url_dir/raw/body.html.headers")
    local server=$(extract_server "$url_dir/raw/body.html.headers")

    # Get redirect count
    local redirect_count=$(grep "redirect_count:" "$url_dir/raw/body.html.headers" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\r' || echo "0")

    # Get IPs from DNS
    local ips=$(grep -E "^[0-9]+\." "$url_dir/dns/resolution.txt" 2>/dev/null | head -3 | tr '\n' ' ' || echo "N/A")

    # Advanced analysis
    log "  → Running advanced analysis..."
    local adv_analysis_file="$url_dir/analysis/url_analysis.txt"
    {
        echo "# Advanced URL Analysis"
        echo "# URL: $(redact_url "$original_url")"
        echo "# Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""
    } > "$adv_analysis_file"
    
    # URL structure analysis
    analyze_url_structure "$original_url" "$domain" "$adv_analysis_file"
    
    # Typosquatting check
    echo "" >> "$adv_analysis_file"
    check_typosquatting "$domain" "$adv_analysis_file"
    
    # Security headers analysis
    echo "" >> "$adv_analysis_file"
    analyze_security_headers "$url_dir/raw/body.html.headers" "$adv_analysis_file"
    
    # Certificate risk analysis
    echo "" >> "$adv_analysis_file"
    analyze_certificate_risk "$url_dir/tls/certificate.txt" "$adv_analysis_file"

    # Calculate risk score
    log "  → Calculating risk score..."
    local risk_score=$(calculate_risk_score "$url_dir" "$url_dir/analysis/risk_score.txt")

    # Compute hashes
    log "  → Computing hashes..."
    {
        echo "# SHA256 Hashes - URL: $(redact_url "$original_url")"
        echo "# Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""
        find "$url_dir" -type f | while read -r file; do
            local hash=$(compute_hash "$file")
            local relpath="${file#$url_dir/}"
            echo "$hash  $relpath"
        done
    } > "$url_dir/hashes.txt"

    # Store metadata for report generation
    {
        echo "ORIGINAL_URL=\"$original_url\""
        echo "EFFECTIVE_URL=\"$effective_url\""
        echo "STATUS_CODE=\"$status_code\""
        echo "SERVER=\"$server\""
        echo "REDIRECT_COUNT=\"$redirect_count\""
        echo "IPS=\"$ips\""
        echo "DOMAIN=\"$domain\""
        echo "RISK_SCORE=\"$risk_score\""
    } > "$url_dir/metadata.env"

    log_success "[$index] Complete: $(redact_url "$original_url") [Risk: $risk_score/100]"

    # Rate limiting
    [[ $RATE_LIMIT -gt 0 ]] && sleep "$(echo "scale=3; $RATE_LIMIT/1000" | bc 2>/dev/null || echo "0.1")"
    
    return 0
}

# ============================================================================
# REPORT GENERATION
# ============================================================================

generate_report() {
    local report_dir="$1"
    local report_file="$report_dir/REPORT.md"
    local total_urls="$2"

    log_info "Generating final report..."

    # Calculate statistics first
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    local minimal_count=0
    local total_risk_score=0
    
    for url_dir in "$report_dir"/per_url/*/; do
        [[ ! -d "$url_dir" ]] && continue
        [[ ! -f "$url_dir/metadata.env" ]] && continue
        
        # Source metadata safely
        source "$url_dir/metadata.env" 2>/dev/null || true
        local score=$(echo "$RISK_SCORE" | tr -d '"')
        score=${score:-0}
        # Ensure score is numeric
        [[ ! "$score" =~ ^[0-9]+$ ]] && score=0
        total_risk_score=$((total_risk_score + score))
        
        if [[ $score -ge 70 ]]; then critical_count=$((critical_count + 1))
        elif [[ $score -ge 50 ]]; then high_count=$((high_count + 1))
        elif [[ $score -ge 30 ]]; then medium_count=$((medium_count + 1))
        elif [[ $score -ge 15 ]]; then low_count=$((low_count + 1))
        else minimal_count=$((minimal_count + 1))
        fi
    done
    
    local avg_risk=$((total_urls > 0 ? total_risk_score / total_urls : 0))

    {
        cat <<'EOF'
# 🔍 Email Link Forensic Analysis Report

<div align="center">

**Automated Phishing Detection & Forensic Evidence Collection**

</div>

---

EOF
        echo "📅 **Report Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""
        echo "🛠️ **Tool:** analyze_email_links.sh v${VERSION}"
        echo ""
        echo "---"
        echo ""

        # =====================================================================
        # EXECUTIVE SUMMARY WITH STATISTICS
        # =====================================================================
        cat <<EOF
## 📊 Executive Summary

This report contains forensic evidence collected from **$total_urls** URLs extracted from email messages.

### Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| 🚨 **CRITICAL** (70-100) | $critical_count | $((total_urls > 0 ? critical_count * 100 / total_urls : 0))% |
| 🔴 **HIGH** (50-69) | $high_count | $((total_urls > 0 ? high_count * 100 / total_urls : 0))% |
| 🟠 **MEDIUM** (30-49) | $medium_count | $((total_urls > 0 ? medium_count * 100 / total_urls : 0))% |
| 🟡 **LOW** (15-29) | $low_count | $((total_urls > 0 ? low_count * 100 / total_urls : 0))% |
| 🟢 **MINIMAL** (0-14) | $minimal_count | $((total_urls > 0 ? minimal_count * 100 / total_urls : 0))% |

**Average Risk Score:** $avg_risk/100

EOF

        # Threat level assessment
        if [[ $critical_count -gt 0 ]]; then
            echo "> ⚠️ **ALERT:** $critical_count URL(s) flagged as CRITICAL risk. Immediate investigation recommended."
            echo ""
        fi
        if [[ $high_count -gt 0 ]]; then
            echo "> ⚡ **WARNING:** $high_count URL(s) flagged as HIGH risk. Review before any user interaction."
            echo ""
        fi

        cat <<EOF

### Analysis Scope

| Feature | Status |
|---------|--------|
| HTTP/HTTPS Collection | ✅ Enabled |
| DNS Resolution | $([ $ENABLE_DNS -eq 1 ] && echo "✅ Enabled" || echo "❌ Disabled") |
| TLS Inspection | $([ $ENABLE_TLS -eq 1 ] && echo "✅ Enabled" || echo "❌ Disabled") |
| Content Analysis | ✅ Enabled |
| Typosquatting Detection | ✅ Enabled |
| Brand Impersonation | ✅ Enabled |
| Obfuscation Detection | ✅ Enabled |
| Risk Scoring | ✅ Enabled |

### Security Configuration

- **Max Response Size:** ${MAX_BYTES}KB
- **Connection Timeout:** ${TIMEOUT}s
- **Max Redirects:** ${MAX_REDIRECTS}
- **JavaScript Execution:** ❌ Disabled (Safe)
- **Form Submission:** ❌ Disabled (Safe)

---

## 🎯 URL Analysis Results

### Summary Table

| # | Risk | URL | Status | Server | Redirects | Key Findings |
|---|------|-----|--------|--------|-----------|--------------|
EOF

        # Populate summary table
        local idx=1
        for url_dir in "$report_dir"/per_url/*/; do
            [[ ! -d "$url_dir" ]] && continue
            [[ ! -f "$url_dir/metadata.env" ]] && continue

            source "$url_dir/metadata.env"
            
            local score=$(echo "$RISK_SCORE" | tr -d '"')
            score=${score:-0}
            
            # Determine risk emoji
            local risk_emoji="🟢"
            if [[ $score -ge 70 ]]; then risk_emoji="🚨"
            elif [[ $score -ge 50 ]]; then risk_emoji="🔴"
            elif [[ $score -ge 30 ]]; then risk_emoji="🟠"
            elif [[ $score -ge 15 ]]; then risk_emoji="🟡"
            fi
            
            # Extract key findings
            local findings=""
            local analysis_file="$url_dir/analysis/content_analysis.txt"
            local url_analysis="$url_dir/analysis/url_analysis.txt"
            
            if [[ -f "$analysis_file" ]]; then
                # Check for password fields
                if grep -q "Password input fields:" "$analysis_file" 2>/dev/null; then
                    findings+="🔑 "
                fi
                # Check for brand mentions
                if grep -q "🏢" "$analysis_file" 2>/dev/null; then
                    findings+="🏢 "
                fi
                # Check for urgency
                local urgency=$(grep "URGENCY_SCORE=" "$analysis_file" 2>/dev/null | cut -d= -f2)
                if [[ -n "$urgency" && "$urgency" -gt 0 ]]; then
                    findings+="⏰ "
                fi
            fi
            
            if [[ -f "$url_analysis" ]]; then
                # Check for typosquatting
                if grep -q "Similar to\|Contains brand" "$url_analysis" 2>/dev/null; then
                    findings+="🎭 "
                fi
                # Check for suspicious TLD
                if grep -q "Suspicious TLD" "$url_analysis" 2>/dev/null; then
                    findings+="🌐 "
                fi
            fi
            
            [[ -z "$findings" ]] && findings="-"

            # Redact and truncate URL
            local display_url=$(redact_url "$ORIGINAL_URL" | cut -c1-40)
            [[ ${#ORIGINAL_URL} -gt 40 ]] && display_url="${display_url}..."
            
            local status=$(echo "$STATUS_CODE" | tr -d '"')
            local server_clean=$(echo "$SERVER" | tr -d '"' | cut -c1-15)
            local redirects=$(echo "$REDIRECT_COUNT" | tr -d '"')

            echo "| $idx | $risk_emoji $score | \`$display_url\` | $status | $server_clean | $redirects | $findings |"

            idx=$((idx + 1))
        done

        echo ""
        echo "**Legend:** 🔑=Password Field 🏢=Brand Mention ⏰=Urgency Language 🎭=Typosquatting 🌐=Suspicious TLD"
        echo ""
        echo "---"
        echo ""

        # =====================================================================
        # DETAILED PER-URL ANALYSIS
        # =====================================================================
        echo "## 📋 Detailed URL Analysis"
        echo ""
        
        idx=1
        for url_dir in "$report_dir"/per_url/*/; do
            [[ ! -d "$url_dir" ]] && continue
            [[ ! -f "$url_dir/metadata.env" ]] && continue

            source "$url_dir/metadata.env"
            
            local score=$(echo "$RISK_SCORE" | tr -d '"')
            score=${score:-0}
            
            # Risk level
            local risk_level="MINIMAL"
            local risk_emoji="🟢"
            if [[ $score -ge 70 ]]; then risk_level="CRITICAL"; risk_emoji="🚨"
            elif [[ $score -ge 50 ]]; then risk_level="HIGH"; risk_emoji="🔴"
            elif [[ $score -ge 30 ]]; then risk_level="MEDIUM"; risk_emoji="🟠"
            elif [[ $score -ge 15 ]]; then risk_level="LOW"; risk_emoji="🟡"
            fi

            echo "### [$idx] $risk_emoji $risk_level - Risk Score: $score/100"
            echo ""
            echo "**Original URL:** \`$(redact_url "$ORIGINAL_URL")\`"
            echo ""
            local eff_url=$(echo "$EFFECTIVE_URL" | tr -d '"')
            if [[ -n "$eff_url" && "$eff_url" != "$ORIGINAL_URL" ]]; then
                echo "**Final URL (after redirects):** \`$(redact_url "$eff_url")\`"
                echo ""
            fi
            
            echo "| Property | Value |"
            echo "|----------|-------|"
            echo "| Domain | \`$(echo "$DOMAIN" | tr -d '"')\` |"
            echo "| Status Code | $(echo "$STATUS_CODE" | tr -d '"') |"
            echo "| Server | $(echo "$SERVER" | tr -d '"') |"
            echo "| IP Addresses | $(echo "$IPS" | tr -d '"') |"
            echo "| Redirects | $(echo "$REDIRECT_COUNT" | tr -d '"') |"
            echo ""
            
            # Include key findings from analysis
            local analysis_file="$url_dir/analysis/content_analysis.txt"
            local url_analysis="$url_dir/analysis/url_analysis.txt"
            local risk_file="$url_dir/analysis/risk_score.txt"
            
            if [[ -f "$url_analysis" ]]; then
                echo "<details>"
                echo "<summary>🔎 URL & Security Analysis</summary>"
                echo ""
                echo '```'
                grep -E "(⚠️|🚨|✓|ℹ️|Missing:|Score:|Risk)" "$url_analysis" 2>/dev/null | head -30 || echo "No significant findings"
                echo '```'
                echo "</details>"
                echo ""
            fi
            
            if [[ -f "$analysis_file" ]]; then
                echo "<details>"
                echo "<summary>📄 Content Analysis</summary>"
                echo ""
                echo '```'
                grep -E "(⚠️|🚨|✓|🏢|Password|Forms|Script|URGENCY|CONTENT_RISK)" "$analysis_file" 2>/dev/null | head -40 || echo "No significant findings"
                echo '```'
                echo "</details>"
                echo ""
            fi
            
            if [[ -f "$risk_file" ]]; then
                echo "<details>"
                echo "<summary>📊 Risk Score Breakdown</summary>"
                echo ""
                cat "$risk_file" 2>/dev/null | grep -v "^#" | head -20
                echo "</details>"
                echo ""
            fi
            
            echo "---"
            echo ""
            idx=$((idx + 1))
        done

        # =====================================================================
        # IOCs SECTION
        # =====================================================================
        cat <<'EOF'
## 🎯 Indicators of Compromise (IOCs)

> Copy these IOCs for threat intelligence feeds, SIEM rules, or blocklists.

### Domains

EOF
        echo '```'
        find "$report_dir/per_url" -name "metadata.env" -exec grep "DOMAIN=" {} \; 2>/dev/null | \
            cut -d= -f2 | tr -d '"' | sort -u || echo "(none)"
        echo '```'

        echo ""
        echo "### IP Addresses"
        echo ""
        echo '```'
        find "$report_dir/per_url" -type f -name "resolution.txt" -exec grep -hE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" {} \; 2>/dev/null | sort -u || echo "(none)"
        echo '```'

        echo ""
        echo "### Final URLs (Post-Redirect)"
        echo ""
        echo '```'
        find "$report_dir/per_url" -name "metadata.env" -exec grep "EFFECTIVE_URL=" {} \; 2>/dev/null | \
            cut -d= -f2- | tr -d '"' | grep -v "^$" | sort -u || echo "(none)"
        echo '```'

        echo ""
        echo "### TLS Certificate SHA256 Fingerprints"
        echo ""
        echo '```'
        find "$report_dir/per_url" -type f -name "certificate.txt" -exec grep -h "SHA256 Fingerprint" {} \; 2>/dev/null | \
            awk -F= '{print $2}' | tr -d ' ' | sort -u || echo "(none collected)"
        echo '```'

        echo ""
        echo "### High-Risk URLs (Score ≥ 50)"
        echo ""
        echo '```'
        for url_dir in "$report_dir"/per_url/*/; do
            [[ ! -f "$url_dir/metadata.env" ]] && continue
            source "$url_dir/metadata.env"
            local score=$(echo "$RISK_SCORE" | tr -d '"')
            if [[ ${score:-0} -ge 50 ]]; then
                echo "$(echo "$ORIGINAL_URL" | tr -d '"')"
            fi
        done || echo "(none)"
        echo '```'

        echo ""
        echo "---"
        echo ""

        # =====================================================================
        # EVIDENCE FILES
        # =====================================================================
        cat <<EOF
## 📁 Evidence Files Structure

\`\`\`
$report_dir/
├── 📄 REPORT.md (this file)
├── 📄 urls_normalized.txt (deduplicated input)
├── 📁 per_url/
│   └── <url_directory>/
│       ├── 📁 raw/
│       │   ├── headers.txt (HTTP headers)
│       │   ├── body.html (response body)
│       │   └── *.stderr (error logs)
│       ├── 📁 dns/
│       │   └── resolution.txt (A, AAAA, CNAME)
│       ├── 📁 tls/
│       │   ├── certificate.txt (cert details)
│       │   └── certificate_chain.pem
│       ├── 📁 analysis/
│       │   ├── content_analysis.txt
│       │   ├── url_analysis.txt
│       │   └── risk_score.txt
│       ├── metadata.env
│       └── hashes.txt
├── 📁 logs/
└── 📄 sha256sum_all.txt (chain of custody)
\`\`\`

---

## 📖 Methodology

### Collection Techniques

| Method | Tool | Purpose |
|--------|------|---------|
| HTTP(S) | \`curl\` | Header & body collection |
| DNS | \`dig\`/\`host\` | A, AAAA, CNAME resolution |
| TLS | \`openssl\` | Certificate inspection |
| Hashing | \`sha256sum\` | Evidence integrity |

### Analysis Techniques

| Analysis | Description |
|----------|-------------|
| **Typosquatting** | Levenshtein distance against known brands |
| **Brand Impersonation** | Keyword matching for 20+ major brands |
| **Urgency Language** | Detection of fear/urgency tactics |
| **Credential Harvesting** | Password/CC/SSN field detection |
| **Obfuscation** | Base64, eval(), hex encoding detection |
| **URL Structure** | TLD, subdomain, encoding analysis |
| **Certificate Risk** | Self-signed, expired, free CA detection |
| **Security Headers** | HSTS, CSP, X-Frame-Options audit |

### Limitations

- ❌ No JavaScript execution (dynamic content not captured)
- ❌ No form submissions or POST requests
- ❌ No browser fingerprinting simulation
- ⚠️ DNS/TLS may fail due to network restrictions
- ⚠️ Sophisticated phishing may evade static analysis

---

## 🛡️ Recommendations

### Immediate Actions

1. **Block** all CRITICAL and HIGH risk URLs at the firewall/proxy
2. **Alert** users who may have received emails containing these URLs
3. **Report** confirmed phishing to the impersonated brand
4. **Submit** malicious URLs to threat intelligence feeds

### Investigation Steps

1. Review detailed analysis for each flagged URL
2. Cross-reference IOCs with your SIEM/threat intel
3. Check if any users clicked on the URLs (proxy logs)
4. Consider sandboxed browser analysis for suspicious pages

### Prevention

1. Implement email URL rewriting/sandboxing
2. Deploy browser isolation for untrusted links
3. Enable DMARC, SPF, DKIM for your domains
4. Conduct user awareness training on phishing

---

**Report End**

*Generated by analyze_email_links.sh v${VERSION}*
EOF
    } > "$report_file"

    log_success "Report generated: $report_file"
}

# Generate master hash file for chain of custody
generate_master_hashes() {
    local report_dir="$1"
    local hash_file="$report_dir/sha256sum_all.txt"

    log_info "Generating master hash file for chain of custody..."

    {
        echo "# SHA256 Hashes - Complete Evidence Package"
        echo "# Report Directory: $report_dir"
        echo "# Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo "# Tool: analyze_email_links.sh v${VERSION}"
        echo ""

        find "$report_dir" -type f ! -name "sha256sum_all.txt" | sort | while read -r file; do
            local hash=$(compute_hash "$file")
            local relpath="${file#$report_dir/}"
            echo "$hash  $relpath"
        done
    } > "$hash_file"

    log_success "Master hash file: $hash_file"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    log "analyze_email_links.sh v${VERSION}"
    log "Forensic Email Link Analysis Tool"
    echo ""

    # Check dependencies first
    check_dependencies

    # Parse arguments
    [[ $# -lt 1 ]] && usage

    local urls_file=""
    local output_dir=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            --follow)
                FOLLOW_REDIRECTS=1
                shift
                ;;
            --no-follow)
                FOLLOW_REDIRECTS=0
                shift
                ;;
            --max-redirs)
                MAX_REDIRECTS="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --max-bytes)
                MAX_BYTES="$2"
                shift 2
                ;;
            --user-agent)
                USER_AGENT="$2"
                shift 2
                ;;
            --no-dns)
                ENABLE_DNS=0
                shift
                ;;
            --no-tls)
                ENABLE_TLS=0
                shift
                ;;
            --rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=1
                shift
                ;;
            *)
                if [[ -z "$urls_file" ]]; then
                    urls_file="$1"
                elif [[ -z "$output_dir" ]]; then
                    output_dir="$1"
                else
                    log_error "Unknown argument: $1"
                    usage
                fi
                shift
                ;;
        esac
    done

    # Validate input file
    [[ -z "$urls_file" ]] && { log_error "URLs file not specified"; usage; }
    [[ ! -f "$urls_file" ]] && { log_error "URLs file not found: $urls_file"; exit 1; }

    # Set output directory
    [[ -z "$output_dir" ]] && output_dir="./report_$(date +%Y%m%d_%H%M%S)"

    log_info "Configuration:"
    log "  URLs file: $urls_file"
    log "  Output directory: $output_dir"
    log "  Follow redirects: $FOLLOW_REDIRECTS (max: $MAX_REDIRECTS)"
    log "  Timeout: ${TIMEOUT}s"
    log "  Max body size: ${MAX_BYTES}KB"
    log "  DNS resolution: $ENABLE_DNS"
    log "  TLS inspection: $ENABLE_TLS"
    log "  Rate limit: ${RATE_LIMIT}ms"
    echo ""

    # Create output structure
    mkdir -p "$output_dir"/{per_url,logs}

    # Normalize and deduplicate URLs
    log_info "Normalizing and deduplicating URLs..."
    local normalized_file="$output_dir/urls_normalized.txt"

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        local normalized=$(normalize_url "$line")
        [[ -n "$normalized" ]] && echo "$normalized"
    done < "$urls_file" | sort -u > "$normalized_file"

    local total_urls=$(wc -l < "$normalized_file")
    log_success "Found $total_urls unique URLs"
    echo ""

    [[ $total_urls -eq 0 ]] && { log_error "No valid URLs found"; exit 1; }

    # Process each URL
    local idx=1
    while IFS= read -r url; do
        local url_safe=$(sanitize_filename "${url}_${idx}")
        local url_dir="$output_dir/per_url/$url_safe"

        # Analyze URL (continue on error)
        analyze_url "$url" "$url_dir" "$idx" || log_warn "Failed to fully analyze: $url"

        idx=$((idx + 1))
    done < "$normalized_file"

    echo ""

    # Generate reports
    generate_report "$output_dir" "$total_urls"
    generate_master_hashes "$output_dir"

    echo ""
    log_success "Analysis complete!"
    log "Results: $output_dir"
    log "Report: $output_dir/REPORT.md"
    log "Master hashes: $output_dir/sha256sum_all.txt"
    echo ""
    log "⚠️  Review the report for IOCs and high-risk indicators"
}

# Run main function
main "$@"
