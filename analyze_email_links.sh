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

VERSION="1.0.0"
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
${SCRIPT_NAME} v${VERSION} - Forensic Email Link Analysis Tool

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

        # Define suspicious patterns
        local patterns=(
            "microsoft"
            "office"
            "login"
            "password"
            "verify"
            "update"
            "atob\("
            "localStorage"
            "\$.ajax"
            "fetch\("
            "next\.php"
            "post\.php"
            "send\.php"
            "eval\("
            "base64_decode"
            "document\.write"
            "window\.location"
            "onclick="
            "onerror="
            "credentials"
            "account"
            "suspend"
            "confirm"
            "security"
            "billing"
        )

        echo "## Suspicious Keywords Found:"
        local found=0
        for pattern in "${patterns[@]}"; do
            local count=$(grep -ciE "$pattern" "$body_file" 2>/dev/null || echo "0")
            if [[ $count -gt 0 ]]; then
                echo "  - '$pattern': $count occurrences"
                found=1
            fi
        done

        [[ $found -eq 0 ]] && echo "  (none detected)"

        echo ""
        echo "## Forms Found:"
        grep -ciE "<form" "$body_file" 2>/dev/null || echo "0"

        echo ""
        echo "## Input Fields:"
        grep -ciE "<input" "$body_file" 2>/dev/null || echo "0"

        echo ""
        echo "## Script Tags:"
        grep -ciE "<script" "$body_file" 2>/dev/null || echo "0"

        echo ""
        echo "## External Resources (sample):"
        grep -oiE "(src|href)=[\"'][^\"']+[\"']" "$body_file" 2>/dev/null | head -20 || echo "(none found)"

    } > "$output_file"
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
        echo "ORIGINAL_URL=$original_url"
        echo "EFFECTIVE_URL=$effective_url"
        echo "STATUS_CODE=$status_code"
        echo "SERVER=$server"
        echo "REDIRECT_COUNT=$redirect_count"
        echo "IPS=$ips"
        echo "DOMAIN=$domain"
    } > "$url_dir/metadata.env"

    log_success "[$index] Complete: $(redact_url "$original_url")"

    # Rate limiting
    [[ $RATE_LIMIT -gt 0 ]] && sleep "$(echo "scale=3; $RATE_LIMIT/1000" | bc 2>/dev/null || echo "0.1")"
}

# ============================================================================
# REPORT GENERATION
# ============================================================================

generate_report() {
    local report_dir="$1"
    local report_file="$report_dir/REPORT.md"
    local total_urls="$2"

    log_info "Generating final report..."

    {
        cat <<'EOF'
# Email Link Forensic Analysis Report

**Generated by:** analyze_email_links.sh
**Timestamp:**
EOF
        echo "$(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""
        echo "---"
        echo ""

        cat <<EOF
## Executive Summary

This report contains forensic evidence collected from **$total_urls** URLs extracted from email messages.
The analysis was conducted using passive, controlled methods with no active exploitation.

**Analysis Scope:**
- HTTP/HTTPS header and body collection
- DNS resolution (A, AAAA, CNAME records)
- TLS certificate inspection
- Content analysis for phishing indicators
- Redirect chain mapping

**Security Measures:**
- Maximum response size: ${MAX_BYTES}KB
- Connection timeout: ${TIMEOUT}s
- Maximum redirects: ${MAX_REDIRECTS}
- No JavaScript execution
- No credential submission

---

## URL Analysis Summary

| # | Original URL | Status | Server | IPs | Redirects | Suspicious Flags |
|---|-------------|--------|--------|-----|-----------|------------------|
EOF

        # Populate table
        local idx=1
        for url_dir in "$report_dir"/per_url/*/; do
            [[ ! -d "$url_dir" ]] && continue

            local meta_file="$url_dir/metadata.env"
            [[ ! -f "$meta_file" ]] && continue

            # Source metadata
            source "$meta_file"

            # Extract suspicious flags
            local flags=""
            local analysis_file="$url_dir/analysis/content_analysis.txt"
            if [[ -f "$analysis_file" ]]; then
                local susp_count=$(grep -E "(microsoft|office|login|password|verify|update|atob|localStorage|fetch)" "$analysis_file" 2>/dev/null | wc -l || echo "0")
                [[ $susp_count -gt 5 ]] && flags="⚠️ High"
                [[ $susp_count -gt 2 && $susp_count -le 5 ]] && flags="⚠️ Medium"
            fi

            # Redact URLs for display
            local display_url=$(redact_url "$ORIGINAL_URL" | cut -c1-50)
            [[ ${#ORIGINAL_URL} -gt 50 ]] && display_url="${display_url}..."

            local display_ips=$(echo "$IPS" | cut -c1-30)

            echo "| $idx | \`$display_url\` | $STATUS_CODE | $SERVER | $display_ips | $REDIRECT_COUNT | $flags |"

            ((idx++))
        done

        echo ""
        echo "---"
        echo ""

        cat <<'EOF'
## Indicators of Compromise (IOCs)

### Domains Observed

EOF
        echo '```'
        find "$report_dir/per_url" -name "metadata.env" -exec grep "DOMAIN=" {} \; 2>/dev/null | cut -d= -f2 | sort -u || true
        echo '```'

        echo ""
        echo "### IP Addresses"
        echo ""
        echo '```'
        find "$report_dir/per_url" -type f -name "resolution.txt" -exec grep -hE "^[0-9]+\." {} \; 2>/dev/null | sort -u || true
        echo '```'

        echo ""
        echo "### Final URLs (Post-Redirect)"
        echo ""
        echo '```'
        find "$report_dir/per_url" -name "metadata.env" -exec grep "EFFECTIVE_URL=" {} \; 2>/dev/null | cut -d= -f2- | grep -v "^$" | sort -u || true
        echo '```'

        echo ""
        echo "### TLS Certificate Fingerprints"
        echo ""
        echo '```'
        find "$report_dir/per_url" -type f -name "certificate.txt" -exec grep -h "SHA256 Fingerprint" {} \; 2>/dev/null | sort -u || echo "(none collected)"
        echo '```'

        echo ""
        echo "---"
        echo ""

        cat <<EOF
## Evidence Files

All collected artifacts are stored in the following structure:

\`\`\`
$report_dir/
├── REPORT.md (this file)
├── urls_normalized.txt (deduplicated input)
├── per_url/
│   ├── <sanitized_url_1>/
│   │   ├── raw/
│   │   │   ├── headers.txt
│   │   │   ├── body.html
│   │   │   └── *.stderr
│   │   ├── dns/
│   │   │   └── resolution.txt
│   │   ├── tls/
│   │   │   ├── certificate.txt
│   │   │   └── certificate_chain.pem
│   │   ├── analysis/
│   │   │   └── content_analysis.txt
│   │   ├── metadata.env
│   │   └── hashes.txt
│   └── <sanitized_url_N>/
└── sha256sum_all.txt (chain of custody)
\`\`\`

---

## Methodology & Limitations

**Collection Methods:**
- HTTP: \`curl\` with controlled timeouts and size limits
- DNS: \`dig\` or \`host\` (UDP/TCP fallback)
- TLS: \`openssl s_client\`
- Hashing: \`sha256sum\` for all artifacts

**Limitations:**
- No JavaScript execution (client-side behavior not captured)
- No form submissions or POST requests
- Limited to surface-level content analysis
- DNS/TLS failures may occur due to network restrictions
- Some malicious sites may fingerprint automated requests

**Ethical & Legal:**
- This analysis is passive and defensive in nature
- No exploitation or vulnerability testing performed
- Intended for authorized security triage and incident response
- Users must ensure proper authorization for analyzing URLs

---

## Recommendations

1. **High-Risk URLs:** Review any URLs with ⚠️ flags in detail
2. **IOC Matching:** Cross-reference domains/IPs with threat intelligence feeds
3. **Certificate Validation:** Check for self-signed, expired, or suspicious certificates
4. **Redirect Patterns:** Investigate URLs with multiple redirects (possible cloaking)
5. **Further Analysis:** Consider sandboxed browser analysis for high-risk candidates

---

**Report End**
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

        ((idx++))
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
