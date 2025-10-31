#!/usr/bin/env bash
# Js-endpoint-harvester.sh (with PROGRESS BARS + VERBOSE LOGGING)
# Usage: ./Js-endpoint-harvester.sh [-v] <target> | [-v] -f targets.txt
#!/usr/bin/env bash
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

# ========================
# SCRIPT STARTS HERE
# ========================

set -uo pipefail
IFS=$'\n\t'

# --------------------
# Flags
# --------------------
VERBOSE=0
FILE_MODE=0
TARGETS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -v|--verbose) VERBOSE=1; shift ;;
    -f) FILE_MODE=1; FILE="$2"; shift 2 ;;
    *) TARGETS+=("$1"); shift ;;
  esac
done

# --------------------
# Input parsing
# --------------------
if [[ $FILE_MODE -eq 1 ]]; then
  [[ ! -f "$FILE" ]] && { echo "File not found: $FILE"; exit 2; }
  if command -v interlace >/dev/null 2>&1; then
    echo "[+] Using Interlace for parallel processing."
    interlace -tL "$FILE" -threads 10 -c "$0 -v _target_"
    exit 0
  else
    echo "[!] Interlace not found – sequential mode."
    mapfile -t TARGETS < "$FILE"
  fi
else
  [[ ${#TARGETS[@]} -eq 0 ]] && { echo "Usage: $0 [-v] <target> OR $0 [-v] -f targets.txt"; exit 2; }
fi

# --------------------
# Helpers
# --------------------
sanitize_target() { echo "$1" | sed -E 's~https?://~~' | sed 's:/*$::' | sed 's/[^a-zA-Z0-9._-]/_/g'; }
extract_domain()  { echo "$1" | sed -E 's~https?://~~' | sed 's~/.*~~' | sed 's/:[0-9]+//'; }

# --------------------
# Progress Bar Function
# --------------------
progress_bar() {
  local current=$1 total=$2 label=$3
  local width=40
  local percent=$(( 100 * current / total ))
  local filled=$(( width * current / total ))
  local empty=$(( width - filled ))
  printf "\r%s: [%s%s] %d/%d (%d%%)" "$label" \
    "$(printf '█%.0s' $(seq 1 $filled))" \
    "$(printf '░%.0s' $(seq 1 $empty))" \
    "$current" "$total" "$percent"
  [[ $current -eq $total ]] && echo
}

# --------------------
# Logging
# --------------------
log() {
  local level=$1; shift; local msg="$*"
  local ts=$(date '+%Y-%m-%d %H:%M:%S')
  local line="[$ts] [$level] $msg"
  [[ $level =~ ^(INFO|WARN|ERROR)$ ]] && echo "$line"
  [[ $VERBOSE -eq 1 && $level == "DEBUG" ]] && echo "$line"
  [[ $VERBOSE -eq 1 && -n "${CURRENT_LOG_FILE:-}" ]] && echo "$line" >> "$CURRENT_LOG_FILE"
}

# --------------------
# Dependency check
# --------------------
REQS=(~/go/bin/waybackurls ~/go/bin/gau ~/go/bin/hakrawler httpx katana arjun ~/go/bin/gospider paramspider ~/CeWL/cewl.rb gf parallel curl jq sort)
for r in "${REQS[@]}"; do
  command -v "$r" >/dev/null 2>&1 || log "WARN" "$r not found"
done

SECRET_REGEX="(AIza[0-9A-Za-z\\-_]{35})|(sk_live_[0-9A-Za-z]{24,})|(AKIA[0-9A-Z]{16})|(ghp_[0-9A-Za-z]{36})|(xoxa-[0-9A-Za-z-]{10,})|(xox[baprs]-[0-9a-zA-Z-]{10,})|([A-Za-z0-9_-]{20,}:?[A-Za-z0-9_\-]{20,})|(eyJ[A-Za-z0-9_\-\.]{10,})|(postgres:\/\/[^ \"']+)|(mysql:\/\/[^ \"']+)|(api_key[\"']?\s*[:=]\s*[A-Za-z0-9_\-]{16,})"
GF_PATTERNS=(xss sqli ssrf redirect lfi rce ssti admin api cors graphql idor secrets debug)

# --------------------
# Main loop
# --------------------
for TARGET_RAW in "${TARGETS[@]}"; do
  log "INFO" "========================================"
  log "INFO" "Processing target: $TARGET_RAW"
  log "INFO" "========================================"

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

  # Verbose log
  if [[ $VERBOSE -eq 1 ]]; then
    CURRENT_LOG_FILE="$OUT_DIR/debug.log"
    mkdir -p "$OUT_DIR"
    : > "$CURRENT_LOG_FILE"
    log "DEBUG" "Verbose log → $CURRENT_LOG_FILE"
  fi

  mkdir -p "$RAW_DIR" "$JS_DIR" "$FIND_DIR" "$LINKFINDER_DIR" "$SECRETFINDER_DIR" "$REPORT_DIR" "$WORDLIST_DIR" "$GF_DIR"

  # File paths
  RAW_ENDPOINTS="$FIND_DIR/raw_endpoints.txt"
  JS_CANDIDATES_FILE="$JS_DIR/js_candidates.txt"
  DOWNLOAD_LIST="$JS_DIR/download_list.txt"
  DOWNLOAD_MAP="$JS_DIR/download_map.txt"
  ALL_RAW="$FIND_DIR/all_endpoints_raw.txt"
  SORTED="$FIND_DIR/all_endpoints_uniq.txt"
  VALIDATED="$FIND_DIR/validated_endpoints.txt"
  PARAMLESS_FILE="$FIND_DIR/paramless_endpoints.txt"
  ARJUN_PARAMS="$FIND_DIR/arjun_params.txt"
  KATANA_VALIDATED="$FIND_DIR/katana_validated.txt"
  PARAMSPIDER_PARAMS="$FIND_DIR/paramspider_params.txt"
  CEWL_WORDLIST="$WORDLIST_DIR/cewl_wordlist.txt"
  HTML_REPORT="$REPORT_DIR/report.html"

  : > "$RAW_ENDPOINTS" "$JS_CANDIDATES_FILE" "$DOWNLOAD_LIST" "$DOWNLOAD_MAP" \
     "$ALL_RAW" "$SORTED" "$VALIDATED" "$PARAMLESS_FILE" "$ARJUN_PARAMS" \
     "$KATANA_VALIDATED" "$PARAMSPIDER_PARAMS" "$CEWL_WORDLIST"

  FINAL_URL=$(curl -kLs -o /dev/null -w '%{url_effective}' "https://${TARGET_DOMAIN}" 2>/dev/null || echo "https://${TARGET_DOMAIN}")
  log "INFO" "Final URL: $FINAL_URL"

  # --------------------
  # Phase 1: Harvest
  # --------------------
  log "INFO" "Phase 1: Harvesting endpoints..."

  WAYBACK_PID="" GAU_PID="" KATANA_PID="" GOSPIDER_PID=""

  if command -v ~/go/bin/waybackurls >/dev/null; then
    (echo "$TARGET_RAW" | waybackurls > "$RAW_DIR/wayback.txt" 2>"$OUT_DIR/wayback.err") &
    WAYBACK_PID=$!
  fi
  if command -v ~/go/bin/gau >/dev/null; then
    (gau "$TARGET_RAW" > "$RAW_DIR/gau.txt" 2>"$OUT_DIR/gau.err") &
    GAU_PID=$!
  fi
  wait ${WAYBACK_PID:-} ${GAU_PID:-} 2>/dev/null

  [[ -f "$RAW_DIR/wayback.txt" ]] && grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/wayback.txt" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS"
  [[ -f "$RAW_DIR/gau.txt" ]] && grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/gau.txt" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS"

  [[ ! -s "$RAW_ENDPOINTS" ]] && echo "$FINAL_URL" > "$RAW_ENDPOINTS"

  if command -v ~/go/bin/hakrawler >/dev/null; then
    cat "$RAW_ENDPOINTS" | hakrawler -subs -d 2 > "$RAW_DIR/haka.txt" 2>"$OUT_DIR/haka.err"
    grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/haka.txt" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS"
  fi

  if command -v katana >/dev/null; then
    (timeout 120 katana -u "$FINAL_URL" -d 3 -jc -hl -silent -o "$RAW_DIR/katana.txt" 2>"$OUT_DIR/katana.err") &
    KATANA_PID=$!
  fi
  if command -v ~/go/bin/gospider >/dev/null; then
    (gospider -s "$FINAL_URL" -d 3 -c 10 -t 20 --quiet > "$RAW_DIR/gospider.txt" 2>"$OUT_DIR/gospider.err") &
    GOSPIDER_PID=$!
  fi
  wait ${KATANA_PID:-} ${GOSPIDER_PID:-} 2>/dev/null

  [[ -f "$RAW_DIR/katana.txt" ]] && {
    grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/katana.txt" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS"
    grep -Eo "https?://[^'\" ]+\.js(\?[^'\" ]*)?" "$RAW_DIR/katana.txt" | grep -i "$TARGET_FILTER" >> "$JS_CANDIDATES_FILE"
  }
  [[ -f "$RAW_DIR/gospider.txt" ]] && {
    grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/gospider.txt" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS"
    grep -Eo "https?://[^'\" ]+\.js(\?[^'\" ]*)?" "$RAW_DIR/gospider.txt" | grep -i "$TARGET_FILTER" >> "$JS_CANDIDATES_FILE"
  }

  curl -k -sL "$FINAL_URL" -o "$RAW_DIR/root.html" 2>"$OUT_DIR/root.err" || touch "$RAW_DIR/root.html"
  grep -Eo "https?://[^ \"'<>]+" "$RAW_DIR/root.html" | grep -i "$TARGET_FILTER" >> "$RAW_ENDPOINTS"

  sort -u "$RAW_ENDPOINTS" -o "$RAW_ENDPOINTS"
  log "INFO" "Total harvested endpoints: $(wc -l < "$RAW_ENDPOINTS")"

  # CeWL
  if command -v ~/CEWL/cewl.rb >/dev/null; then
    ~/CeWL/cewl.rb -d 3 -m 5 -w "$CEWL_WORDLIST" "$FINAL_URL" 2>"$OUT_DIR/cewl.err"
    log "INFO" "CeWL wordlist: $(wc -l < "$CEWL_WORDLIST") words"
  fi

  # --------------------
  # Phase 2: JS Discovery
  # --------------------
  log "INFO" "Phase 2: Extracting JS assets..."
  for f in "$RAW_DIR"/*.txt; do [[ -f "$f" ]] && grep -Eo "https?://[^'\" ]+\.js(\?[^'\" ]*)?" "$f" | grep -i "$TARGET_FILTER" >> "$JS_CANDIDATES_FILE"; done
  [[ -f "$RAW_DIR/root.html" ]] && grep -Eo "<script[^>]+src=[\"']?([^\"'> ]+)" "$RAW_DIR/root.html" |
    sed -E "s/.*src=['\"]?([^'\"]+).*/\1/" |
    while read -r src; do
      [[ $src =~ ^https?:// ]] && echo "$src"
      [[ $src =~ ^/ ]] && echo "${FINAL_URL%/}${src}"
      [[ $src =~ ^\./ ]] && echo "${FINAL_URL%/}/${src#./}"
    done | grep -i "$TARGET_FILTER" >> "$JS_CANDIDATES_FILE"

  [[ ! -s "$JS_CANDIDATES_FILE" ]] && {
    printf '%s\n' \
      "${FINAL_URL%/}/static/js/app.js" \
      "${FINAL_URL%/}/main.js" \
      "${FINAL_URL%/}/bundle.js" >> "$JS_CANDIDATES_FILE"
  }

  sort -u "$JS_CANDIDATES_FILE" -o "$JS_CANDIDATES_FILE"
  JS_COUNT=$(wc -l < "$JS_CANDIDATES_FILE")
  log "INFO" "JS candidates: $JS_COUNT"

  # --------------------
  # Phase 3: Download JS (WITH PROGRESS BAR)
  # --------------------
  log "INFO" "Phase 3: Downloading JS files..."
  DOWNLOADED=0
  TOTAL_JS=$JS_COUNT
  i=0

  while read -r url; do
    ((i++))
    [[ -z "$url" ]] && continue
    hash=$(echo -n "$url" | md5sum | awk '{print $1}')
    out="$JS_DIR/${hash}.js"
    success=0
    for attempt in {1..3}; do
      code=$(curl -k -L -sS --max-time 30 -w "%{http_code}" -o "$out" "$url" 2>/dev/null || echo 000)
      size=$(stat -c%s "$out" 2>/dev/null || echo 0)
      [[ "$code" =~ ^(200|203|206|302|304)$ ]] && ((size > 100)) && { success=1; break; }
      rm -f "$out"; sleep 0.5
    done
    [[ $success -eq 1 ]] && { echo "$url -> ${hash}.js" >> "$DOWNLOAD_MAP"; ((DOWNLOADED++)); }
    progress_bar $i $TOTAL_JS "Downloading JS"
  done < "$JS_CANDIDATES_FILE"
  echo

  log "INFO" "Downloaded JS files: $DOWNLOADED"

  # --------------------
  # Phase 4: LinkFinder + SecretFinder (WITH PROGRESS BAR)
  # --------------------
  JS_FILES=("$JS_DIR"/*.js)
  JS_FILES_COUNT=${#JS_FILES[@]}

  if [[ $JS_FILES_COUNT -gt 0 ]] && [[ -f /opt/LinkFinder/linkfinder.py ]] || command -v linkfinder >/dev/null; then
    log "INFO" "Phase 4: Running LinkFinder..."
    i=0
    for js in "${JS_FILES[@]}"; do
      ((i++))
      [[ ! -f "$js" ]] && continue
      base=$(basename "$js")
      if [[ -f ~/LinkFinder/linkfinder.py ]]; then
        python3.9 ~/LinkFinder/linkfinder.py -i "$js" -o cli 2>/dev/null | sed '/^\s*$/d' > "$LINKFINDER_DIR/${base}.txt"
      else
        linkfinder -i "$js" -o cli > "$LINKFINDER_DIR/${base}.txt" 2>/dev/null
      fi
      progress_bar $i $JS_FILES_COUNT "LinkFinder"
    done
    echo
  fi

  if [[ $JS_FILES_COUNT -gt 0 ]] && [[ -f ~/SecretFinder/SecretFinder.py ]] || command -v SecretFinder >/dev/null; then
    log "INFO" "Phase 4: Running SecretFinder..."
    i=0
    for js in "${JS_FILES[@]}"; do
      ((i++))
      [[ ! -f "$js" ]] && continue
      base=$(basename "$js")
      if [[ -f ~/SecretFinder/SecretFinder.py ]]; then
        python3.9 ~/SecretFinder/SecretFinder.py -i "$js" -o cli 2>/dev/null > "$SECRETFINDER_DIR/${base}.txt"
      else
        SecretFinder -i "$js" -o cli > "$SECRETFINDER_DIR/${base}.txt" 2>/dev/null
      fi
      progress_bar $i $JS_FILES_COUNT "SecretFinder"
    done
    echo
  fi

  grep -Eho "$SECRET_REGEX" "$JS_DIR"/*.js 2>/dev/null | sort -u > "$SECRETFINDER_DIR/fallback_secrets.txt"
  log "INFO" "Fallback secrets: $(wc -l < "$SECRETFINDER_DIR/fallback_secrets.txt")"

  # --------------------
  # Phase 5: Arjun (WITH PROGRESS BAR)
  # --------------------
  grep -v "\?" "$SORTED" 2>/dev/null | head -100 > "$PARAMLESS_FILE"
  ARJUN_TOTAL=$(wc -l < "$PARAMLESS_FILE")
  if [[ $ARJUN_TOTAL -gt 0 ]] && command -v arjun >/dev/null; then
    log "INFO" "Phase 5.5: Running Arjun on $ARJUN_TOTAL endpoints..."
    i=0
    ARJUN_WORDLIST_OPT=""
    [[ -s "$CEWL_WORDLIST" ]] && ARJUN_WORDLIST_OPT="-w $CEWL_WORDLIST"
    while read -r url; do
      ((i++))
      temp_out=$(mktemp)
      timeout 60 arjun -u "$url" -m GET,POST --stable --no-colors $ARJUN_WORDLIST_OPT > "$temp_out" 2>/dev/null || true
      grep -E "^\[\+\] Parameter" "$temp_out" | sed -E 's/.*Parameter: ([^ ]+).*/\1/' | \
        awk -v url="$url" '{print url (index(url,"?")?"&":"?") $1 "=DUMMY"}' >> "$ARJUN_PARAMS"
      rm -f "$temp_out"
      progress_bar $i $ARJUN_TOTAL "Arjun"
    done < "$PARAMLESS_FILE"
    echo
    sort -u "$ARJUN_PARAMS" -o "$ARJUN_PARAMS"
    log "INFO" "Arjun discovered: $(wc -l < "$ARJUN_PARAMS") params"
  fi

  # --------------------
  # Phase 5.7: GF Patterns (WITH PROGRESS BAR)
  # --------------------
  if command -v gf >/dev/null && [[ -s "$SORTED" ]]; then
    log "INFO" "Phase 5.7: Running GF patterns..."
    TOTAL_GF=${#GF_PATTERNS[@]}
    i=0
    for pattern in "${GF_PATTERNS[@]}"; do
      ((i++))
      cat "$SORTED" | gf "$pattern" 2>/dev/null | sort -u > "$GF_DIR/${pattern}.txt"
      progress_bar $i $TOTAL_GF "GF Patterns"
    done
    echo
  fi

  # --------------------
  # Phase 6: HTML Report
  # --------------------
  log "INFO" "Phase 6: Generating HTML report..."
  # (Report generation unchanged — omitted for brevity)

  echo "[+] HTML report: $HTML_REPORT"
  echo "----- FINISHED: $TARGET_DOMAIN -----"
  echo "Workspace: $OUT_DIR"
  echo "Report: $HTML_REPORT"
  echo "-------------------------------------"

  [[ $VERBOSE -eq 1 ]] && log "DEBUG" "Log → $CURRENT_LOG_FILE"
  unset CURRENT_LOG_FILE
done

log "INFO" "All targets processed. Results in OUT/"
exit 0
