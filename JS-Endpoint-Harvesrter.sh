#!/usr/bin/env bash
# Js-endpoint-harvester.sh (optimized with parallelism + Interlace integration for multi-target)
# Usage:
# ./Js-endpoint-harvester.sh example.com
# ./Js-endpoint-harvester.sh -f targets.txt
# Note: If Interlace is installed and -f is used, targets will be processed in parallel using Interlace.
# ========================
# JS ENDPOINT HARVESTER v1.0
# Animated + Colored + Figlet-Style Splash
# ========================

# Colors
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
WHITE=$(tput setaf 7)
BOLD=$(tput bold)
RESET=$(tput sgr0)

# Figlet-style custom font (hand-crafted)
FIGLET_LINES=(
"   ${BOLD}${MAGENTA}   _ ____    ____  _   _ _   _ _     _     ${RESET}"
"   ${BOLD}${MAGENTA}  | |  _ \  / ___|| | | | \ | | |   | |    ${RESET}"
"   ${BOLD}${MAGENTA}  | | | | | \___ \| | | |  \| | |   | |    ${RESET}"
"   ${BOLD}${MAGENTA}  | | |_| |  ___) | |_| | |\  | |___| |___ ${RESET}"
"   ${BOLD}${MAGENTA}  | |____/  |____/ \___/|_| \_|_____|_____|${RESET}"
"   ${BOLD}${CYAN}   \\ \\        / /  |  _ \\ / _ \\| \\ | |  ${RESET}"
"   ${BOLD}${CYAN}    \\ \\  /\\  / /   | |_) | | | |  \\| |  ${RESET}"
"   ${BOLD}${CYAN}     \\ \\/  \\/ /    |  __/| |_| | |\\  |  ${RESET}"
"   ${BOLD}${CYAN}      \\  /\\  /     |_|    \\___/|_| \\_|  ${RESET}"
"   ${BOLD}${YELLOW}       \\/  \\/  ${BOLD}${GREEN}JS ENDPOINT HARVESTER ${BOLD}${RED}v1.0${RESET}"
)

# Subtitle
SUBTITLE="${BOLD}${WHITE}JavaScript-Driven Endpoint Discovery & Parameter Enumeration By Clark Voss${RESET}"
TOOLS="${CYAN}• LinkFinder • SecretFinder • Arjun • ParamSpider • GF • httpx • katana • gospider${RESET}"

# Animation function
animate_splash() {
  clear
  local delay=0.03
  local line

  # Typewriter effect for figlet
  for line in "${FIGLET_LINES[@]}"; do
    for ((i=0; i<${#line}; i++)); do
      printf "%s" "${line:$i:1}"
      [[ "${line:$i:1}" =~ [a-zA-Z0-9] ]] && sleep 0.01
    done
    echo
    sleep 0.05
  done

  # Fade in subtitle
  echo
  for ((i=0; i<${#SUBTITLE}; i++)); do
    printf "%s" "${SUBTITLE:$i:1}"
    sleep 0.02
  done
  echo
  echo

  # Tools line
  echo -e "$TOOLS"
  echo

  # Pulse version number
  for _ in {1..3}; do
    echo -e "${BOLD}${RED}          >>> HARVESTING ENDPOINTS <<<${RESET}"
    sleep 0.4
    echo -e "${BOLD}${YELLOW}          >>> HARVESTING ENDPOINTS <<<${RESET}"
    sleep 0.4
  done

  echo
  sleep 1.2
  clear
}

# Run animation only in interactive terminal
if [[ -t 1 ]]; then
  animate_splash
else
  # Non-interactive: just print static version
  for line in "${FIGLET_LINES[@]}"; do echo -e "$line"; done
  echo -e "$SUBTITLE"
  echo -e "$TOOLS"
  echo
fi

#!/usr/bin/env bash
# Js-endpoint-harvester.sh (optimized with parallelism + Interlace integration for multi-target)
# Usage:
# ./Js-endpoint-harvester.sh example.com
# ./Js-endpoint-harvester.sh -f targets.txt
# Note: If Interlace is installed and -f is used, targets will be processed in parallel using Interlace.
set -uo pipefail
IFS=$'\n\t'
# --------------------
# Input parsing
# --------------------
if [ "$#" -eq 0 ]; then
  echo "Usage: $0 <target> OR $0 -f targets.txt"
  exit 2
fi
if [ "$1" = "-f" ]; then
  if [ "$#" -ne 2 ]; then
    echo "Usage: $0 -f targets.txt"
    exit 2
  fi
  FILE="$2"
  if [ ! -f "$FILE" ]; then
    echo "File not found: $FILE"
    exit 2
  fi
  if command -v interlace >/dev/null 2>&1; then
    echo "[+] Using Interlace for parallel processing of multiple targets."
    interlace -tL "$FILE" -threads 10 -c "$0 _target_"
    exit 0
  else
    echo "[!] Interlace not found, processing targets sequentially."
    mapfile -t TARGETS < "$FILE"
  fi
else
  TARGETS=("$1")
fi
# --------------------
# Helper: sanitize a target for directory naming
# --------------------
sanitize_target() {
  echo "$1" | sed -E 's~https?://~~' | sed 's:/*$::' | sed 's/[^a-zA-Z0-9._-]/_/g'
}
# --------------------
# Helper: extract domain for filtering
# --------------------
extract_domain() {
  echo "$1" | sed -E 's~https?://~~' | sed 's~/.*~~' | sed 's/:[0-9]+//'
}
# --------------------
# Dependencies (warn only)
# --------------------
REQS=(waybackurls gau hakrawler httpx python3 jq curl sort sha1sum katana arjun gospider paramspider cewl gf parallel interlace)
for r in "${REQS[@]}"; do
  if ! command -v "$r" >/dev/null 2>&1; then
    echo "[!] Warning: $r not found (some phases may be skipped)."
  fi
done
# Enhanced secret regex battery
SECRET_REGEX="(AIza[0-9A-Za-z\\-_]{35})|(sk_live_[0-9A-Za-z]{24,})|(AKIA[0-9A-Z]{16})|(ghp_[0-9A-Za-z]{36})|(xoxa-[0-9A-Za-z-]{10,})|(xox[baprs]-[0-9a-zA-Z-]{10,})|([A-Za-z0-9_-]{20,}:?[A-Za-z0-9_\-]{20,})|(eyJ[A-Za-z0-9_\-\.]{10,})|(postgres:\/\/[^ \"']+)|(mysql:\/\/[^ \"']+)|(api_key[\"']?\s*[:=]\s*[A-Za-z0-9_\-]{16,})"
# Expanded GF patterns for endpoints/vulns
GF_PATTERNS=(xss sqli ssrf redirect lfi rce ssti admin api cors graphql idor secrets debug)
# --------------------
# Main per-target loop
# --------------------
for TARGET_RAW in "${TARGETS[@]}"; do
  echo "========================================"
  echo "Processing target: $TARGET_RAW"
  echo "========================================"
  TARGET_DOMAIN=$(sanitize_target "$TARGET_RAW")
  TARGET_FILTER=$(extract_domain "$TARGET_RAW")
  OUT_DIR="OUT/${TARGET_DOMAIN}"
  RAW_DIR="$OUT_DIR/raw_urls"
  JS_DIR="$OUT_DIR/js"
  FIND_DIR="$OUT_DIR/findings"
  LINKFINDER_DIR="$FIND_DIR/linkfinder"
  SECRETFINDER_DIR="$FIND_DIR/secrets"
  REPORT_DIR="$FIND_DIR/reports"
  WORDLIST_DIR="$FIND_DIR/wordlists"
  GF_DIR="$FIND_DIR/gf"
  # Create required directories
  mkdir -p "$RAW_DIR" "$JS_DIR" "$FIND_DIR" "$LINKFINDER_DIR" "$SECRETFINDER_DIR" "$REPORT_DIR" "$WORDLIST_DIR" "$GF_DIR"
  # File paths
  RAW_ENDPOINTS="$FIND_DIR/raw_endpoints.txt"
  JS_CANDIDATES_FILE="$JS_DIR/js_candidates.txt"
  DOWNLOAD_LIST="$JS_DIR/download_list.txt"
  DOWNLOAD_MAP="$JS_DIR/download_map.txt"
  INLINE_JS="$JS_DIR/inline_scripts.js"
  ALL_RAW="$FIND_DIR/all_endpoints_raw.txt"
  SORTED="$FIND_DIR/all_endpoints_uniq.txt"
  VALIDATED="$FIND_DIR/validated_endpoints.txt"
  PARAMLESS_FILE="$FIND_DIR/paramless_endpoints.txt"
  ARJUN_PARAMS="$FIND_DIR/arjun_params.txt"
  KATANA_VALIDATED="$FIND_DIR/katana_validated.txt"
  PARAMSPIDER_PARAMS="$FIND_DIR/paramspider_params.txt"
  CEWL_WORDLIST="$WORDLIST_DIR/cewl_wordlist.txt"
  HTML_REPORT="$REPORT_DIR/report.html"
  # Initialize files
  : > "$RAW_ENDPOINTS"
  : > "$JS_CANDIDATES_FILE"
  : > "$DOWNLOAD_LIST"
  : > "$DOWNLOAD_MAP"
  : > "$INLINE_JS"
  : > "$ALL_RAW"
  : > "$SORTED"
  : > "$VALIDATED"
  : > "$PARAMLESS_FILE"
  : > "$ARJUN_PARAMS"
  : > "$KATANA_VALIDATED"
  : > "$PARAMSPIDER_PARAMS"
  : > "$CEWL_WORDLIST"
  # Resolve final URL
  FINAL_URL=$(curl -kLs -o /dev/null -w '%{url_effective}' "https://${TARGET_DOMAIN}" 2>/dev/null || true)
  [ -z "$FINAL_URL" ] && FINAL_URL="https://${TARGET_DOMAIN}"
  echo "[+] Final URL: $FINAL_URL"
  # --------------------
  # Phase 1: Harvest endpoints (parallel where possible)
  # --------------------
  echo "[+] Phase 1: Harvesting endpoints..."
  # Parallel: waybackurls and gau (independent)
  WAYBACK_PID=""
  GAU_PID=""
  if command -v waybackurls >/dev/null 2>&1; then
    echo " - waybackurls (parallel)"
    (echo "$TARGET_RAW" | waybackurls > "$RAW_DIR/wayback.txt" 2>/dev/null || true) &
    WAYBACK_PID=$!
  fi
  if command -v gau >/dev/null 2>&1; then
    echo " - gau (parallel)"
    (gau "$TARGET_RAW" > "$RAW_DIR/gau.txt" 2>/dev/null || true) &
    GAU_PID=$!
  fi
  wait ${WAYBACK_PID} ${GAU_PID} 2>/dev/null || true
  # Process wayback
  if [ -n "$WAYBACK_PID" ] && [ -f "$RAW_DIR/wayback.txt" ]; then
    grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/wayback.txt" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS" 2>/dev/null || true
  fi
  # Process gau
  if [ -n "$GAU_PID" ] && [ -f "$RAW_DIR/gau.txt" ]; then
    grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/gau.txt" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS" 2>/dev/null || true
  fi
  # Seed with final URL
  if [ ! -s "$RAW_ENDPOINTS" ]; then
    echo "$FINAL_URL" > "$RAW_ENDPOINTS"
  fi
  # Sequential: hakrawler (depends on initial raw)
  if command -v hakrawler >/dev/null 2>&1; then
    echo " - hakrawler (sequential)"
    cat "$RAW_ENDPOINTS" | hakrawler -subs -d 2 > "$RAW_DIR/haka.txt" 2>/dev/null || true
    grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/haka.txt" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS" 2>/dev/null || true
  fi
  # Parallel: katana and gospider (independent crawlers)
  KATANA_PID=""
  GOSPIDER_PID=""
  if command -v katana >/dev/null 2>&1; then
    echo " - katana (parallel)"
    (timeout 120 katana -u "$FINAL_URL" -d 3 -jc -hl -silent -o "$RAW_DIR/katana.txt" 2>/dev/null || true) &
    KATANA_PID=$!
  fi
  if command -v gospider >/dev/null 2>&1; then
    echo " - gospider (parallel)"
    (gospider -s "$FINAL_URL" -d 3 -c 10 -t 20 --quiet > "$RAW_DIR/gospider.txt" 2>/dev/null || true) &
    GOSPIDER_PID=$!
  fi
  wait ${KATANA_PID} ${GOSPIDER_PID} 2>/dev/null || true
  # Process katana
  if [ -n "$KATANA_PID" ] && [ -f "$RAW_DIR/katana.txt" ]; then
    grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/katana.txt" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS" 2>/dev/null || true
    grep -Eo "https?://[^'\" ]+\.js(\?[^'\" ]*)?" "$RAW_DIR/katana.txt" | grep -i "$TARGET_FILTER" >> "$JS_CANDIDATES_FILE" 2>/dev/null || true
  fi
  # Process gospider
  if [ -n "$GOSPIDER_PID" ] && [ -f "$RAW_DIR/gospider.txt" ]; then
    grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/gospider.txt" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS" 2>/dev/null || true
    grep -Eo "https?://[^'\" ]+\.js(\?[^'\" ]*)?" "$RAW_DIR/gospider.txt" | grep -i "$TARGET_FILTER" >> "$JS_CANDIDATES_FILE" 2>/dev/null || true
  fi
  # Sequential: root page (fast)
  if command -v curl >/dev/null 2>&1; then
    echo " - fetching root page"
    curl -k -sL "$FINAL_URL" -o "$RAW_DIR/root.html" || touch "$RAW_DIR/root.html"
    grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/root.html" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS" 2>/dev/null || true
  fi
  # Deduplicate
  sort -u "$RAW_ENDPOINTS" -o "$RAW_ENDPOINTS" || true
  echo "[+] Total harvested endpoints: $(wc -l < "$RAW_ENDPOINTS" 2>/dev/null || echo 0)"
  # Extract param'd URLs
  grep -Eo "https?://[^?]+\?[^ \"'<>]+" "$RAW_ENDPOINTS" | sort -u > "$FIND_DIR/params.txt" 2>/dev/null || true
  # --------------------
  # Phase 1.5: Scrape words for parameter enumeration (CeWL)
  # --------------------
  echo "[+] Phase 1.5: Scraping words with CeWL for parameter wordlist..."
  if command -v cewl >/dev/null 2>&1; then
    cewl -d 3 -m 5 -w "$CEWL_WORDLIST" "$FINAL_URL" 2>/dev/null || true
    CEWL_COUNT=$(wc -l < "$CEWL_WORDLIST" 2>/dev/null || echo 0)
    echo " - CeWL wordlist generated: $CEWL_COUNT words"
  else
    echo " - CeWL not installed; skipping wordlist generation."
  fi
  # --------------------
  # Phase 2: JS discovery
  # --------------------
  echo "[+] Phase 2: Extracting JS assets..."
  # From harvested lists
  for f in "$RAW_DIR"/*.txt; do
    [ -f "$f" ] || continue
    grep -Eo "https?://[^'\" ]+\.js(\?[^'\" ]*)?" "$f" | grep -i "$TARGET_FILTER" || true
  done >> "$JS_CANDIDATES_FILE" 2>/dev/null || true
  # Parse <script src> from root.html
  if [ -f "$RAW_DIR/root.html" ]; then
    grep -Eo "<script[^>]+src=[\"']?([^\"'> ]+)" "$RAW_DIR/root.html" 2>/dev/null \
      | sed -E "s/.*src=['\"]?([^'\"]+).*/\1/" \
      | while read -r src; do
          if [[ "$src" =~ ^https?:// ]]; then
            echo "$src" | grep -i "$TARGET_FILTER"
          elif [[ "$src" =~ ^/ ]]; then
            echo "${FINAL_URL%/}${src}" | grep -i "$TARGET_FILTER"
          else
            echo "${FINAL_URL%/}/${src#./}" | grep -i "$TARGET_FILTER"
          fi
        done >> "$JS_CANDIDATES_FILE" 2>/dev/null || true
  fi
  # Inline scripts
  if [ -f "$RAW_DIR/root.html" ]; then
    if grep -Pzo "(?s)<script[^>]*>(.*?)</script>" "$RAW_DIR/root.html" >/dev/null 2>&1; then
      grep -Pzo "(?s)<script[^>]*>(.*?)</script>" "$RAW_DIR/root.html" 2>/dev/null \
        | sed -E 's/<script[^>]*>//g; s#</script>##g' > "$INLINE_JS" 2>/dev/null || true
    else
      awk '/<script/{f=1;next}/<\/script>/{f=0}f{print}' "$RAW_DIR/root.html" > "$INLINE_JS" 2>/dev/null || true
    fi
  fi
  # Katana inline JS extraction
  if [ -f "$RAW_DIR/katana.txt" ] && command -v katana >/dev/null 2>&1; then
    echo " - extracting inline JS from katana pages"
    grep -E "<script[^>]*>" "$RAW_DIR/katana.txt" -A 1000 | \
      sed -n '1,/<script/p' | \
      sed -E 's/<script[^>]*>//g; s#</script>##g' >> "$INLINE_JS" 2>/dev/null || true
  fi
  # Fallback JS paths
  if [ ! -s "$JS_CANDIDATES_FILE" ]; then
    echo "[!] No external JS found — adding common fallbacks"
    echo "${FINAL_URL%/}/static/js/app.js" >> "$JS_CANDIDATES_FILE"
    echo "${FINAL_URL%/}/main.js" >> "$JS_CANDIDATES_FILE"
    echo "${FINAL_URL%/}/bundle.js" >> "$JS_CANDIDATES_FILE"
  fi
  sort -u "$JS_CANDIDATES_FILE" -o "$JS_CANDIDATES_FILE" || true
  JS_COUNT=$(wc -l < "$JS_CANDIDATES_FILE" 2>/dev/null || echo 0)
  echo "[+] JS candidates: $JS_COUNT"
  # --------------------
  # Phase 3: Download JS files
  # --------------------
  echo "[+] Phase 3: Downloading JS files..."
  mkdir -p "$JS_DIR"
  : > "$DOWNLOAD_LIST"
  : > "$DOWNLOAD_MAP"
  DOWNLOADED=0
  while read -r url || [ -n "$url" ]; do
    url="${url%%$'\r'}"
    [ -z "$url" ] && continue
    hash=$(echo -n "$url" | md5sum | awk '{print $1}')
    out="$JS_DIR/${hash}.js"
    success=0
    for attempt in 1 2 3; do
      http_code=$(curl -k -L -sS --max-time 30 -w "%{http_code}" -o "$out" "$url" 2>/dev/null || echo "000")
      size=$(stat -c%s "$out" 2>/dev/null || echo 0)
      echo " - $url -> HTTP $http_code, ${size} bytes (attempt $attempt)"
      if [[ "$http_code" =~ ^(200|203|206|302|304)$ ]] && [ "$size" -gt 100 ]; then
        success=1
        break
      fi
      rm -f "$out"
      sleep 1
    done
    if [ "$success" -eq 1 ]; then
      echo "$url -> ${hash}.js" >> "$DOWNLOAD_MAP"
      echo "$url" >> "$DOWNLOAD_LIST"
      DOWNLOADED=$((DOWNLOADED+1))
    else
      echo " failed after 3 attempts: $url"
    fi
  done < "$JS_CANDIDATES_FILE"
  echo "[+] Downloaded JS files: $DOWNLOADED"
  # --------------------
  # Phase 4: Analysis (LinkFinder, SecretFinder, regex)
  # --------------------
  echo "[+] Phase 4: Running LinkFinder & SecretFinder..."
  if [ -f "/opt/LinkFinder/linkfinder.py" ] || command -v linkfinder >/dev/null 2>&1; then
    for js in "$JS_DIR"/*.js; do
      [ -f "$js" ] || continue
      base=$(basename "$js")
      if [ -f "/opt/LinkFinder/linkfinder.py" ]; then
        python3 "/opt/LinkFinder/linkfinder.py" -i "$js" -o cli 2>/dev/null | sed '/^\s*$/d' > "$LINKFINDER_DIR/${base}.txt" || true
      else
        linkfinder -i "$js" -o cli > "$LINKFINDER_DIR/${base}.txt" 2>/dev/null || true
      fi
    done
  else
    echo " - LinkFinder not installed, skipping."
  fi
  if [ -f "/opt/SecretFinder/SecretFinder.py" ] || command -v SecretFinder >/dev/null 2>&1; then
    for js in "$JS_DIR"/*.js; do
      [ -f "$js" ] || continue
      base=$(basename "$js")
      if [ -f "/opt/SecretFinder/SecretFinder.py" ]; then
        python3 "/opt/SecretFinder/SecretFinder.py" -i "$js" -o cli > "$SECRETFINDER_DIR/${base}.txt" 2>/dev/null || true
      else
        SecretFinder -i "$js" -o cli > "$SECRETFINDER_DIR/${base}.txt" 2>/dev/null || true
      fi
    done
  else
    echo " - SecretFinder not installed, using fallback regex."
  fi
  grep -Eho "$SECRET_REGEX" "$JS_DIR"/*.js 2>/dev/null | sort -u > "$SECRETFINDER_DIR/fallback_secrets.txt" || true
  FALLBACK_COUNT=$(wc -l < "$SECRETFINDER_DIR/fallback_secrets.txt" 2>/dev/null || echo 0)
  echo " - Fallback secrets found: $FALLBACK_COUNT"
  # --------------------
  # Phase 5: Aggregate, categorize, validate
  # --------------------
  echo "[+] Phase 5: Aggregating endpoints..."
  : > "$ALL_RAW"
  for f in "$LINKFINDER_DIR"/*.txt; do [ -f "$f" ] && cat "$f" | grep -i "$TARGET_FILTER" >> "$ALL_RAW" 2>/dev/null || true; done
  for f in "$SECRETFINDER_DIR"/*.txt; do [ -f "$f" ] && grep -Eo "https?://[^ \"']+" "$f" | grep -i "$TARGET_FILTER" >> "$ALL_RAW" 2>/dev/null || true; done
  cat "$RAW_ENDPOINTS" >> "$ALL_RAW" 2>/dev/null || true
  if [ -s "$ALL_RAW" ]; then
    sed 's/[",'\'' ]$//g' "$ALL_RAW" | sed 's/#.*$//' | sort -u > "$SORTED" || true
  else
    : > "$SORTED"
  fi
  TOTAL_ENDPOINTS=$(wc -l < "$SORTED" 2>/dev/null || echo 0)
  echo "[+] Candidate endpoints (uniq): $TOTAL_ENDPOINTS"
  # Categorize
  API_FILE="$FIND_DIR/api_endpoints.txt"
  ADMIN_FILE="$FIND_DIR/admin_endpoints.txt"
  UPLOAD_FILE="$FIND_DIR/upload_endpoints.txt"
  grep -Ei "/api/v[0-9]+/|/api/v[0-9]+$" "$SORTED" > "$API_FILE" 2>/dev/null || true
  grep -Ei "/api/|\.json" "$SORTED" | grep -Fvxf "$API_FILE" >> "$API_FILE" 2>/dev/null || true
  grep -Ei "/admin/|/admin$|/dashboard/|/wp-admin|/manage|/console|/administrator" "$SORTED" > "$ADMIN_FILE" 2>/dev/null || true
  grep -Ei "/upload/|/uploads/|/files/|/attachments/|/import/|/file-upload" "$SORTED" > "$UPLOAD_FILE" 2>/dev/null || true
  API_COUNT=$(wc -l < "$API_FILE" 2>/dev/null || echo 0)
  ADMIN_COUNT=$(wc -l < "$ADMIN_FILE" 2>/dev/null || echo 0)
  UPLOAD_COUNT=$(wc -l < "$UPLOAD_FILE" 2>/dev/null || echo 0)
  # Validate with httpx
  VALIDATED_COUNT=0
  if command -v httpx >/dev/null 2>&1; then
    echo "[+] Validating endpoints with httpx..."
    cat "$SORTED" | httpx -silent -status-code -threads 40 -o "$VALIDATED" || true
    VALIDATED_COUNT=$(wc -l < "$VALIDATED" 2>/dev/null || echo 0)
  else
    echo " - httpx not installed; skipping validation"
  fi
  # Katana validation
  if [ -f "$RAW_DIR/katana.txt" ] && command -v httpx >/dev/null 2>&1; then
    echo "[+] Validating Katana endpoints..."
    grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/katana.txt" | sort -u | \
      httpx -silent -status-code -threads 40 -o "$KATANA_VALIDATED" || true
  fi
  # --------------------
  # Phase 5.5: Arjun parameter discovery
  # --------------------
  echo "[+] Phase 5.5: Discovering hidden parameters with Arjun..."
  grep -v "\?" "$SORTED" | head -100 > "$PARAMLESS_FILE" 2>/dev/null || true
  ARJUN_DISCOVERED=0
  if command -v arjun >/dev/null 2>&1 && [ -s "$PARAMLESS_FILE" ]; then
    echo " - Running Arjun on $(wc -l < "$PARAMLESS_FILE") param-less endpoints..."
    if [ -s "$CEWL_WORDLIST" ]; then
      echo " - Using CeWL wordlist for Arjun"
      ARJUN_WORDLIST_OPT="-w $CEWL_WORDLIST"
    else
      ARJUN_WORDLIST_OPT=""
    fi
    ARJUN_COUNT=0
    while read -r url || [ -n "$url" ]; do
      [ -z "$url" ] && continue
      temp_out=$(mktemp)
      timeout 60 arjun -u "$url" -m GET,POST --stable --no-colors $ARJUN_WORDLIST_OPT > "$temp_out" 2>/dev/null || true
      grep -E "^\[\+\] Parameter.*\(.*\): .*" "$temp_out" 2>/dev/null | \
        sed -E 's/^\[(\+|\-)\] Parameter: ([^ ]+) \(Status: ([0-9]+)\): .*/\1 \2/' | \
        grep "^\+ " | \
        awk -v url="$url" '{print url (index(url, "?") > 0 ? "&" : "?") $2 "=DUMMY"}' >> "$ARJUN_PARAMS" 2>/dev/null || true
      rm -f "$temp_out"
      ARJUN_COUNT=$((ARJUN_COUNT+1))
      [ $((ARJUN_COUNT % 10)) -eq 0 ] && echo " - Processed $ARJUN_COUNT"
    done < "$PARAMLESS_FILE"
    sort -u "$ARJUN_PARAMS" -o "$ARJUN_PARAMS" || true
    ARJUN_DISCOVERED=$(wc -l < "$ARJUN_PARAMS" 2>/dev/null || echo 0)
    echo " - Discovered $ARJUN_DISCOVERED new parameterized URLs with Arjun"
  else
    echo " - Arjun not installed or no param-less endpoints; skipping."
  fi
  # --------------------
  # Phase 5.6: ParamSpider parameter discovery
  # --------------------
  echo "[+] Phase 5.6: Discovering parameters with ParamSpider..."
  PARAMSPIDER_DISCOVERED=0
  if command -v paramspider >/dev/null 2>&1; then
    paramspider -d "$TARGET_FILTER" -l high -o "$PARAMSPIDER_PARAMS" 2>/dev/null || true
    sort -u "$PARAMSPIDER_PARAMS" -o "$PARAMSPIDER_PARAMS" || true
    PARAMSPIDER_DISCOVERED=$(wc -l < "$PARAMSPIDER_PARAMS" 2>/dev/null || echo 0)
    echo " - Discovered $PARAMSPIDER_DISCOVERED parameters with ParamSpider"
  else
    echo " - ParamSpider not installed; skipping."
  fi
  # --------------------
  # Phase 5.7: GF patterns for potential vulnerabilities (parallel if possible)
  # --------------------
  echo "[+] Phase 5.7: Applying GF patterns to endpoints..."
  GF_COUNTS=()
  if command -v gf >/dev/null 2>&1 && [ -s "$SORTED" ]; then
    if command -v parallel >/dev/null 2>&1; then
      echo " - Using GNU parallel for GF (optimized)"
      printf '%s\n' "${GF_PATTERNS[@]}" | parallel -j0 'cat "$SORTED" | gf {} 2>/dev/null | sort -u > "$GF_DIR/{}.txt" || true'
    else
      echo " - Sequential GF (install parallel for speedup)"
      for pattern in "${GF_PATTERNS[@]}"; do
        cat "$SORTED" | gf "$pattern" 2>/dev/null | sort -u > "$GF_DIR/${pattern}.txt" || true
      done
    fi
    for pattern in "${GF_PATTERNS[@]}"; do
      count=$(wc -l < "$GF_DIR/${pattern}.txt" 2>/dev/null || echo 0)
      GF_COUNTS+=("${pattern^^}: ${count}")
      echo " - GF $pattern: $count endpoints"
    done
  else
    echo " - GF not installed or no endpoints; skipping."
    for pattern in "${GF_PATTERNS[@]}"; do
      GF_COUNTS+=("${pattern^^}: 0")
    done
  fi
  # --------------------
  # Phase 6: HTML report
  # --------------------
  echo "[+] Phase 6: Generating HTML report..."
  KATANA_COUNT=$( [ -f "$RAW_DIR/katana.txt" ] && wc -l < "$RAW_DIR/katana.txt" 2>/dev/null || echo 0 )
  GOSPIDER_COUNT=$( [ -f "$RAW_DIR/gospider.txt" ] && wc -l < "$RAW_DIR/gospider.txt" 2>/dev/null || echo 0 )
  CEWL_COUNT=$( [ -f "$CEWL_WORDLIST" ] && wc -l < "$CEWL_WORDLIST" 2>/dev/null || echo 0 )
  GF_SUMMARY=""
  for gc in "${GF_COUNTS[@]}"; do
    GF_SUMMARY+="<div>GF $gc</div>"
  done
  GF_SECTIONS=""
  for pattern in "${GF_PATTERNS[@]}"; do
    GF_SECTIONS+="<section><h2>GF ${pattern^^} Endpoints</h2><pre>$( [ -s "$GF_DIR/${pattern}.txt" ] && sed -n '1,1000p' "$GF_DIR/${pattern}.txt" || echo "None")</pre></section>"
  done
  cat > "$HTML_REPORT" <<HTML_EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Js-endpoint-harvester report - ${TARGET_DOMAIN}</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:20px;color:#222;}
h1{color:#0b69a5;}
section{margin-bottom:24px;padding:12px;border:1px solid #eee;border-radius:6px;background:#fafafa;}
pre{background:#fff;border:1px solid #e6e6e6;padding:10px;overflow:auto;max-height:360px;font-size:13px;}
a{color:#0b69a5;text-decoration:none;}
a:hover{text-decoration:underline;}
.summary{display:flex;gap:20px;flex-wrap:wrap;}
.summary div{padding:8px;background:#fff;border:1px solid #efefef;border-radius:6px;}
</style>
</head>
<body>
<h1>Js-endpoint-harvester report</h1>
<p><strong>Target:</strong> ${TARGET_DOMAIN}</p>
<p><strong>Final URL:</strong> <a href="${FINAL_URL}">${FINAL_URL}</a></p>
<section>
<h2>Summary</h2>
<div class="summary">
  <div>Harvested endpoints: $(wc -l < "$RAW_ENDPOINTS" 2>/dev/null || echo 0)</div>
  <div>Unique candidates: ${TOTAL_ENDPOINTS}</div>
  <div>JS candidates: ${JS_COUNT}</div>
  <div>JS downloaded: ${DOWNLOADED}</div>
  <div>API endpoints: ${API_COUNT}</div>
  <div>Admin endpoints: ${ADMIN_COUNT}</div>
  <div>Upload endpoints: ${UPLOAD_COUNT}</div>
  <div>Validated endpoints: ${VALIDATED_COUNT}</div>
  <div>Katana endpoints: ${KATANA_COUNT}</div>
  <div>GoSpider endpoints: ${GOSPIDER_COUNT}</div>
  <div>Arjun params discovered: ${ARJUN_DISCOVERED}</div>
  <div>ParamSpider params discovered: ${PARAMSPIDER_DISCOVERED}</div>
  <div>CeWL words: ${CEWL_COUNT}</div>
  <div>Fallback secrets: ${FALLBACK_COUNT}</div>
  ${GF_SUMMARY}
</div>
</section>
<section><h2>API Endpoints</h2><pre>$( [ -s "$API_FILE" ] && sed -n '1,1000p' "$API_FILE" || echo "None")</pre></section>
<section><h2>Admin Endpoints</h2><pre>$( [ -s "$ADMIN_FILE" ] && sed -n '1,1000p' "$ADMIN_FILE" || echo "None")</pre></section>
<section><h2>Upload Endpoints</h2><pre>$( [ -s "$UPLOAD_FILE" ] && sed -n '1,1000p' "$UPLOAD_FILE" || echo "None")</pre></section>
<section><h2>All Candidate Endpoints (clickable)</h2><pre>
$(if [ -s "$SORTED" ]; then while read -r u; do echo "<a href=\"$u\">$u</a>"; done < "$SORTED"; else echo "None"; fi)
</pre></section>
<section><h2>JS Candidates</h2><pre>$( [ -s "$JS_CANDIDATES_FILE" ] && sed -n '1,1000p' "$JS_CANDIDATES_FILE" || echo "None")</pre></section>
<section><h2>Fallback Secrets</h2><pre>$( [ -s "$SECRETFINDER_DIR/fallback_secrets.txt" ] && sed -n '1,1000p' "$SECRETFINDER_DIR/fallback_secrets.txt" || echo "None")</pre></section>
<section><h2>Validated Endpoints (httpx)</h2><pre>$( [ -s "$VALIDATED" ] && sed -n '1,1000p' "$VALIDATED" || echo "None or httpx not installed")</pre></section>
<section><h2>Katana Validated Endpoints</h2><pre>$( [ -s "$KATANA_VALIDATED" ] && sed -n '1,1000p' "$KATANA_VALIDATED" || echo "None")</pre></section>
<section><h2>Arjun Discovered Parameters</h2><pre>$( [ -s "$ARJUN_PARAMS" ] && sed -n '1,1000p' "$ARJUN_PARAMS" || echo "None or Arjun not installed")</pre></section>
<section><h2>ParamSpider Discovered Parameters</h2><pre>$( [ -s "$PARAMSPIDER_PARAMS" ] && sed -n '1,1000p' "$PARAMSPIDER_PARAMS" || echo "None or ParamSpider not installed")</pre></section>
<section><h2>CeWL Wordlist (Top 100)</h2><pre>$( [ -s "$CEWL_WORDLIST" ] && sed -n '1,100p' "$CEWL_WORDLIST" || echo "None or CeWL not installed")</pre></section>
${GF_SECTIONS}
</body>
</html>
HTML_EOF
  echo "[+] HTML report: $HTML_REPORT"
  # --------------------
  # Final console summary
  # --------------------
  echo "----- FINISHED: $TARGET_DOMAIN -----"
  echo "Workspace: $OUT_DIR"
  echo "JS candidates: $JS_COUNT | Downloaded: $DOWNLOADED"
  echo "Candidate endpoints: ${TOTAL_ENDPOINTS}"
  echo "API: ${API_COUNT} | Admin: ${ADMIN_COUNT} | Upload: ${UPLOAD_COUNT}"
  echo "Katana: ${KATANA_COUNT} | GoSpider: ${GOSPIDER_COUNT}"
  echo "Arjun params: ${ARJUN_DISCOVERED} | ParamSpider params: ${PARAMSPIDER_DISCOVERED}"
  echo "CeWL words: ${CEWL_COUNT}"
  echo "Fallback secrets: ${FALLBACK_COUNT}"
  for gc in "${GF_COUNTS[@]}"; do
    echo "GF $gc"
  done
  echo "Report: $HTML_REPORT"
  echo "-------------------------------------"
done
echo "All targets processed. Check OUT/ for results."
exit 0
