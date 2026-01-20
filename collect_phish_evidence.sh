#!/usr/bin/env bash
set -euo pipefail

# =========================
# Phishing kit collector (curl) + DNS + TLS + SHA256
# =========================

TARGET_BASE="${1:-https://bacnati.com/adtelef/}"
OUTDIR="${2:-report_$(date -u +%Y%m%dT%H%M%SZ)}"
UA="${UA:-Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0}"
TIMEOUT="${TIMEOUT:-20}"
POST_DI="${POST_DI:-test@example.com}"
POST_PR="${POST_PR:-FakePassword123!}"

mkdir -p "$OUTDIR"/{raw,artifacts,logs,hashes,tls,dns}
REPORT="$OUTDIR/REPORT.md"

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$OUTDIR/logs/run.log" >&2; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }

need curl
need grep
need sed
need awk
need head
need tr

# Normalize base URL (ensure trailing slash)
if [[ "$TARGET_BASE" != */ ]]; then TARGET_BASE="${TARGET_BASE}/"; fi
TARGET_NEXT="${TARGET_BASE}next.php"

# Extract host + port from URL
ORIGIN="$(echo "$TARGET_BASE" | sed -E 's#(https?://[^/]+).*#\1#')"
HOSTPORT="$(echo "$ORIGIN" | sed -E 's#https?://##')"
HOST="${HOSTPORT%%:*}"
PORT="443"
if [[ "$HOSTPORT" == *:* ]]; then
  PORT="${HOSTPORT##*:}"
fi

log "Target base: $TARGET_BASE"
log "Origin     : $ORIGIN"
log "Host       : $HOST"
log "Port       : $PORT"
log "Output dir : $OUTDIR"
log "User-Agent : $UA"

curl_save() {
  local url="$1"
  local out="$2"
  local extra_args="${3:-}"
  # shellcheck disable=SC2086
  curl -vkL --max-time "$TIMEOUT" -A "$UA" $extra_args "$url" \
    1>"$out" 2>"$out.stderr" || true
}

curl_headers() {
  local url="$1"
  local out="$2"
  curl -vkI --max-time "$TIMEOUT" -A "$UA" "$url" \
    1>"$out" 2>"$out.stderr" || true
}

curl_effective_url() {
  local url="$1"
  curl -skL --max-time "$TIMEOUT" -A "$UA" -o /dev/null -w '%{url_effective}\n' "$url" || true
}

# =========================
# 0) DNS resolution (UDP + TCP best-effort)
# =========================
log "Collecting DNS (dig/host) ..."
if command -v dig >/dev/null 2>&1; then
  {
    echo "## dig (UDP) — A/AAAA/CNAME/NS/MX/TXT"
    dig +time=3 +tries=1 A "$HOST"
    dig +time=3 +tries=1 AAAA "$HOST"
    dig +time=3 +tries=1 CNAME "$HOST"
    dig +time=3 +tries=1 NS "$HOST"
    dig +time=3 +tries=1 MX "$HOST"
    dig +time=3 +tries=1 TXT "$HOST"
    echo
    echo "## dig (TCP) — A/AAAA (best-effort)"
    dig +tcp +time=3 +tries=1 A "$HOST"
    dig +tcp +time=3 +tries=1 AAAA "$HOST"
  } > "$OUTDIR/dns/dig.txt" 2> "$OUTDIR/dns/dig.stderr" || true
else
  echo "dig not found" > "$OUTDIR/dns/dig.txt"
fi

if command -v host >/dev/null 2>&1; then
  {
    echo "## host"
    host "$HOST" || true
    host -t a "$HOST" || true
    host -t aaaa "$HOST" || true
    host -t cname "$HOST" || true
    host -t ns "$HOST" || true
    host -t mx "$HOST" || true
    host -t txt "$HOST" || true
  } > "$OUTDIR/dns/host.txt" 2> "$OUTDIR/dns/host.stderr" || true
else
  echo "host not found" > "$OUTDIR/dns/host.txt"
fi

# =========================
# 0.1) TLS certificate capture
# =========================
log "Collecting TLS certificate (openssl s_client) ..."
if command -v openssl >/dev/null 2>&1; then
  # Save full handshake + cert chain (PEM blocks included)
  {
    echo | openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" -showcerts 2>&1
  } > "$OUTDIR/tls/openssl_s_client.txt" || true

  # Extract first certificate block to PEM (leaf cert)
  awk 'BEGIN{in=0} /BEGIN CERTIFICATE/{in=1} {if(in) print} /END CERTIFICATE/{exit}' \
    "$OUTDIR/tls/openssl_s_client.txt" > "$OUTDIR/tls/leaf.pem" 2>/dev/null || true

  # Fingerprints (if leaf.pem exists)
  if [[ -s "$OUTDIR/tls/leaf.pem" ]]; then
    openssl x509 -in "$OUTDIR/tls/leaf.pem" -noout -subject -issuer -dates \
      > "$OUTDIR/tls/leaf_meta.txt" 2>/dev/null || true
    openssl x509 -in "$OUTDIR/tls/leaf.pem" -noout -fingerprint -sha256 \
      > "$OUTDIR/tls/leaf_fingerprint_sha256.txt" 2>/dev/null || true
  fi
else
  echo "openssl not found" > "$OUTDIR/tls/openssl_s_client.txt"
fi

# =========================
# 1) Headers / fingerprint
# =========================
log "Collecting headers (HEAD) for landing page..."
curl_headers "$TARGET_BASE" "$OUTDIR/raw/headers_landing.txt"

log "Collecting headers (HEAD) for next.php..."
curl_headers "$TARGET_NEXT" "$OUTDIR/raw/headers_nextphp.txt"

# =========================
# 2) Download landing HTML
# =========================
log "Downloading landing HTML..."
curl_save "$TARGET_BASE" "$OUTDIR/artifacts/landing.html"

log "Capturing effective URL (landing)..."
LANDING_EFFECTIVE="$(curl_effective_url "$TARGET_BASE")"
printf '%s\n' "$LANDING_EFFECTIVE" > "$OUTDIR/raw/effective_url_landing.txt"

# =========================
# 3) Extract and download linked resources (best-effort)
# =========================
log "Extracting resource links (src/href) from landing HTML..."
grep -oE '(src|href)=\"[^\"]+\"' "$OUTDIR/artifacts/landing.html" \
  | sed -E 's/^(src|href)=\"//; s/\"$//' \
  | sed 's/&amp;/\&/g' \
  | awk 'NF' \
  > "$OUTDIR/raw/landing_links.txt" || true

log "Filtering candidate JS/CSS resources..."
grep -Ei '\.js(\?|$)|\.css(\?|$)' "$OUTDIR/raw/landing_links.txt" \
  > "$OUTDIR/raw/landing_assets_js_css.txt" || true

log "Downloading local JS/CSS assets (best-effort)..."
while IFS= read -r link; do
  [[ -z "$link" ]] && continue

  if [[ "$link" =~ ^https?:// ]]; then
    if [[ "$link" == "$TARGET_BASE"* ]]; then asset_url="$link"; else continue; fi
  elif [[ "$link" =~ ^// ]]; then
    continue
  elif [[ "$link" =~ ^/ ]]; then
    origin="$(echo "$TARGET_BASE" | sed -E 's#(https?://[^/]+).*#\1#')"
    asset_url="${origin}${link}"
  else
    asset_url="${TARGET_BASE}${link}"
  fi

  fname="$(echo "$asset_url" | sed -E 's#https?://##; s#[^A-Za-z0-9._-]#_#g')"
  outpath="$OUTDIR/artifacts/$fname"
  log "  - $asset_url"
  curl_save "$asset_url" "$outpath"
done < "$OUTDIR/raw/landing_assets_js_css.txt"

log "Searching for 'next.php' references in artifacts..."
grep -Rni "next\.php" "$OUTDIR/artifacts" > "$OUTDIR/raw/grep_nextphp.txt" || true

log "Searching for suspicious patterns (atob/localStorage/ajax/post)..."
grep -RniE "atob\(|localStorage|\\$\\.post|\\$\\.ajax|fetch\\(|XMLHttpRequest|application/x-www-form-urlencoded|di\\b|pr\\b" \
  "$OUTDIR/artifacts" > "$OUTDIR/raw/grep_suspicious.txt" || true

# =========================
# 4) Fetch next.php directly (GET)
# =========================
log "Fetching next.php (GET)..."
curl_save "$TARGET_NEXT" "$OUTDIR/artifacts/nextphp_get.txt"

# =========================
# 5) Simulate controlled POST to next.php
# =========================
log "Posting controlled test credentials to next.php (POST di/pr)..."
POST_DATA="di=${POST_DI}&pr=${POST_PR}"
curl_save "$TARGET_NEXT" "$OUTDIR/artifacts/nextphp_post.txt" \
  "-X POST -H Content-Type:application/x-www-form-urlencoded --data $POST_DATA"

log "Capturing effective URL (POST)..."
POST_EFFECTIVE="$(curl -skL --max-time "$TIMEOUT" -A "$UA" -o /dev/null -w '%{url_effective}\n' \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" --data "$POST_DATA" "$TARGET_NEXT" || true)"
printf '%s\n' "$POST_EFFECTIVE" > "$OUTDIR/raw/effective_url_post.txt"

# =========================
# 6) Hashes SHA256 for chain of custody
# =========================
log "Hashing artifacts (SHA256)..."
if command -v sha256sum >/dev/null 2>&1; then
  # Hash everything except the hashes folder itself
  (cd "$OUTDIR" && find . -type f ! -path "./hashes/*" -print0 | sort -z | xargs -0 sha256sum) \
    > "$OUTDIR/hashes/sha256sum_all.txt" || true
else
  echo "sha256sum not found" > "$OUTDIR/hashes/sha256sum_all.txt"
fi

# =========================
# 7) Build Markdown report
# =========================
log "Generating Markdown report..."
{
  echo "# Relatório técnico (curl) — recolha de evidência"
  echo
  echo "- **Target base:** \`$TARGET_BASE\`"
  echo "- **Origin:** \`$ORIGIN\`"
  echo "- **Host:** \`$HOST\`"
  echo "- **Port:** \`$PORT\`"
  echo "- **next.php:** \`$TARGET_NEXT\`"
  echo "- **Data (UTC):** \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\`"
  echo "- **User-Agent:** \`$UA\`"
  echo "- **Timeout:** \`${TIMEOUT}s\`"
  echo "- **POST (controlado):** \`di=<redacted>\`, \`pr=<redacted>\`"
  echo
  echo "## 1) URLs efetivos (após redirects)"
  echo
  echo "- Landing effective URL: \`$(cat "$OUTDIR/raw/effective_url_landing.txt")\`"
  echo "- POST effective URL: \`$(cat "$OUTDIR/raw/effective_url_post.txt")\`"
  echo
  echo "## 2) DNS"
  echo
  echo "### dig"
  echo '```'
  sed -n '1,240p' "$OUTDIR/dns/dig.txt" 2>/dev/null || true
  echo '```'
  echo
  echo "### host"
  echo '```'
  sed -n '1,240p' "$OUTDIR/dns/host.txt" 2>/dev/null || true
  echo '```'
  echo
  echo "## 3) TLS (openssl s_client)"
  echo
  echo "### Leaf cert metadata"
  echo '```'
  sed -n '1,120p' "$OUTDIR/tls/leaf_meta.txt" 2>/dev/null || true
  echo '```'
  echo
  echo "### Leaf cert SHA256 fingerprint"
  echo '```'
  sed -n '1,40p' "$OUTDIR/tls/leaf_fingerprint_sha256.txt" 2>/dev/null || true
  echo '```'
  echo
  echo "### Raw openssl output (amostra)"
  echo '```'
  sed -n '1,200p' "$OUTDIR/tls/openssl_s_client.txt" 2>/dev/null || true
  echo '```'
  echo
  echo "## 4) Headers (fingerprint)"
  echo
  echo "### Landing (HEAD)"
  echo '```'
  sed -n '1,200p' "$OUTDIR/raw/headers_landing.txt" || true
  echo '```'
  echo
  echo "### next.php (HEAD)"
  echo '```'
  sed -n '1,200p' "$OUTDIR/raw/headers_nextphp.txt" || true
  echo '```'
  echo
  echo "## 5) Landing HTML (amostra)"
  echo '```html'
  sed -n '1,200p' "$OUTDIR/artifacts/landing.html"
  echo '```'
  echo
  echo "## 6) Links extraídos do HTML"
  echo '```'
  sed -n '1,200p' "$OUTDIR/raw/landing_links.txt" || true
  echo '```'
  echo
  echo "## 7) Evidência next.php"
  echo
  echo "### GET next.php (output + stderr)"
  echo '```'
  sed -n '1,200p' "$OUTDIR/artifacts/nextphp_get.txt" || true
  echo '```'
  echo
  echo "_stderr:_"
  echo '```'
  sed -n '1,120p' "$OUTDIR/artifacts/nextphp_get.txt.stderr" || true
  echo '```'
  echo
  echo "### POST next.php (output + stderr) — valores redigidos"
  echo '```'
  sed -E 's/(di=)[^& ]+/\1<redacted>/g; s/(pr=)[^& ]+/\1<redacted>/g' "$OUTDIR/artifacts/nextphp_post.txt" | sed -n '1,200p' || true
  echo '```'
  echo
  echo "_stderr:_"
  echo '```'
  sed -E 's/(di=)[^& ]+/\1<redacted>/g; s/(pr=)[^& ]+/\1<redacted>/g' "$OUTDIR/artifacts/nextphp_post.txt.stderr" | sed -n '1,120p' || true
  echo '```'
  echo
  echo "## 8) Referências no kit (grep)"
  echo
  echo "### Ocorrências de next.php"
  echo '```'
  sed -n '1,200p' "$OUTDIR/raw/grep_nextphp.txt" || true
  echo '```'
  echo
  echo "### Padrões suspeitos (atob/localStorage/ajax/post/di/pr)"
  echo '```'
  sed -n '1,200p' "$OUTDIR/raw/grep_suspicious.txt" || true
  echo '```'
  echo
  echo "## 9) Hashes SHA256 (cadeia de custódia)"
  echo '```'
  sed -n '1,200p' "$OUTDIR/hashes/sha256sum_all.txt" || true
  echo '```'
  echo
  echo "## 10) Artefactos gerados"
  echo "- \`artifacts/\` (HTML/JS/CSS + outputs)"
  echo "- \`raw/\` (headers, greps, urls efetivos)"
  echo "- \`dns/\` (dig/host)"
  echo "- \`tls/\` (openssl, leaf.pem, fingerprints)"
  echo "- \`hashes/sha256sum_all.txt\`"
  echo
  echo "## 11) Observações"
  echo "- Recolha passiva e controlada (sem brute force / sem enumeração agressiva)."
  echo "- Se houver proxy/CDN, o IP real pode não ser visível apenas por DNS/TLS."
} > "$REPORT"

log "Done. Report: $REPORT"
log "Tip: tar -czf ${OUTDIR}.tar.gz $OUTDIR"
exit 0
