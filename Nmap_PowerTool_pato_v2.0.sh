#!/usr/bin/env bash
# =====================================================
# NMAP POWER TOOL für Gaia  –  HARDENED EDITION
# Kategorien-Menü, Dispatch-Tabellen, echte Scan-Historie,
# Projekt-Integration, Searchsploit-Korrelation, Scan-Diff,
# Zielliste, UDP-Scan, Host-Ausschluss, Desktop-Benachrichtigung
#
# Copyright by Patrick 2026
#
# NUR für eigene Lab-Umgebung oder schriftlich autorisierte Tests!
# Unbefugtes Scannen fremder Systeme ist in vielen Ländern strafbar
# (z.B. § 202a/§ 303b StGB, Computer Misuse Act, CFAA).
# =====================================================

set -uo pipefail
shopt -s nullglob
umask 077

# =====================================================
# KONSTANTEN / STATE
# =====================================================
readonly SCRIPT_NAME="${0##*/}"
readonly SCRIPT_VERSION="2.0-hardened"
readonly LOGFILE="${NMAP_PATO_LOG:-$HOME/nmap_pato.log}"
readonly LOG_MAX_BYTES=5242880          # 5 MB
readonly ENGAGEMENTS_DIR="${NMAP_PATO_ENGAGEMENTS:-$HOME/engagements}"
readonly HISTORY_FILE="${NMAP_PATO_HISTORY:-$HOME/.nmap_pato_history.log}"
readonly AUTH_FILE="$HOME/.nmap_pato_authorizations.log"
readonly NMAP_XSL="/usr/share/nmap/nmap.xsl"
readonly AUTH_PHRASE="ICH BIN AUTORISIERT"
readonly MAX_INPUT_LEN=512

SCOPE_FILE="${NMAP_PATO_SCOPE:-$HOME/.nmap_pato_scope}"
ASSUME_AUTHORIZED=0
AUTHORIZED=0
ENGAGEMENT_REF=""

TARGET=""                 # Anzeige-String (IP/Subnetz ODER "Liste: <Datei>")
declare -a TARGET_SPEC=() # Echte nmap-Zielargumente: ("$TARGET") oder ("-iL" "$file")
declare -a TARGET_HOSTS=() # Für Scope-Prüfung aufgelöste Einzelziele
EXCLUDE_HOSTS=""
RECON_DIR=""
BETTERCAP_CAPLET=""
BETTERCAP_PID=""
SCAN_PID=""
SCAN_INTERRUPTED=0
SUDO_KEEPALIVE_PID=""
CLEANED_UP=0

# =====================================================
# FARBEN (nur wenn TTY)
# =====================================================
if [[ -t 1 ]]; then
    readonly RED=$'\033[0;31m'
    readonly GREEN=$'\033[0;32m'
    readonly YELLOW=$'\033[1;33m'
    readonly BLUE=$'\033[0;34m'
    readonly CYAN=$'\033[0;36m'
    readonly BOLD=$'\033[1m'
    readonly NC=$'\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''
fi

# =====================================================
# BASIS-HELFER
# =====================================================
strip_ansi() { sed -e 's/\x1b\[[0-9;]*[mK]//g'; }

init_files() {
    local f
    for f in "$LOGFILE" "$HISTORY_FILE" "$AUTH_FILE"; do
        if [[ -L "$f" ]]; then
            printf '%s\n' "${RED}[FATAL] $f ist ein Symlink – Abbruch (TOCTOU-Schutz).${NC}" >&2
            exit 1
        fi
        : >> "$f" || { printf '%s\n' "${RED}[FATAL] Kann $f nicht schreiben.${NC}" >&2; exit 1; }
        chmod 600 "$f" 2>/dev/null || true
    done
}

rotate_log_if_needed() {
    [[ -f "$LOGFILE" ]] || return 0
    local size
    size=$(stat -c%s -- "$LOGFILE" 2>/dev/null || printf '0')
    [[ "$size" =~ ^[0-9]+$ ]] || size=0
    if (( size > LOG_MAX_BYTES )); then
        mv -f -- "$LOGFILE" "${LOGFILE}.old" && chmod 600 "${LOGFILE}.old" 2>/dev/null || true
        : > "$LOGFILE"; chmod 600 "$LOGFILE" 2>/dev/null || true
    fi
}

log() {
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${USER:-unknown}" "$1" >> "$LOGFILE" 2>/dev/null || true
}

msg() {
    printf '%b\n' "$1"
    log "$(printf '%b' "$1" | strip_ansi)"
}

die() {
    msg "${RED}[FATAL] $1${NC}"
    exit 1
}

warn_fail() {
    msg "${RED}[FEHLER] $1${NC}"
    return 1
}

pause() {
    read -r -p "Drücke ENTER zum Fortfahren..." _ || true
}

# Sicheres Einlesen: begrenzt Länge, entfernt NUL/Steuerzeichen, EOF-fest.
read_input() {
    local __prompt="$1" __varname="$2" __val=""
    if ! IFS= read -r -p "$__prompt" __val; then
        printf '\n'
        return 1
    fi
    __val="${__val//$'\r'/}"
    __val="$(printf '%s' "$__val" | tr -d '\000-\010\013\014\016-\037\177')"
    if (( ${#__val} > MAX_INPUT_LEN )); then
        warn_fail "Eingabe zu lang (max. $MAX_INPUT_LEN Zeichen)."
        return 1
    fi
    printf -v "$__varname" '%s' "$__val"
    return 0
}

is_uint() { [[ "${1:-}" =~ ^[0-9]{1,6}$ ]]; }

ask_yes_no() {
    local prompt="$1" ans=""
    read_input "$prompt [ja/nein]: " ans || return 1
    [[ "${ans,,}" == "ja" || "${ans,,}" == "j" || "${ans,,}" == "yes" || "${ans,,}" == "y" ]]
}

check_tool() { command -v -- "$1" >/dev/null 2>&1; }

require_tools() {
    local missing=() tool
    for tool in "$@"; do
        check_tool "$tool" || missing+=("$tool")
    done
    if (( ${#missing[@]} > 0 )); then
        warn_fail "Fehlende Programme: ${missing[*]}"
        msg "${YELLOW}Installation (Debian/Kali): sudo apt update && sudo apt install -y ${missing[*]}${NC}"
        return 1
    fi
    return 0
}

require_not_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        die "Bitte NICHT als root starten. Das Skript nutzt sudo gezielt nur dort, wo es nötig ist."
    fi
}

notify() {
    check_tool notify-send && notify-send -- "Nmap Power Tool" "$1" >/dev/null 2>&1 || true
}

# =====================================================
# AUTORISIERUNGS-GATE
# =====================================================
show_legal_banner() {
    cat <<'EOF'
------------------------------------------------------------------
 RECHTLICHER HINWEIS / AUTHORIZATION GATE
------------------------------------------------------------------
 Aktive Netzwerk-Scans, Vulnerability-Scans und insbesondere
 ARP-Spoofing (MITM) greifen in fremde Systeme ein.

 Du darfst dieses Werkzeug AUSSCHLIESSLICH einsetzen gegen:
   * Systeme, die dir selbst gehören (eigenes Lab), ODER
   * Systeme, für die eine SCHRIFTLICHE Beauftragung mit
     definiertem Scope und Zeitfenster vorliegt.

 Jede andere Nutzung kann strafbar sein. Alle Aktionen dieser
 Sitzung werden lokal protokolliert.
------------------------------------------------------------------
EOF
}

authorization_gate() {
    local ans=""
    show_legal_banner
    if (( ASSUME_AUTHORIZED == 1 )); then
        msg "${YELLOW}[!] Autorisierung per --assume-authorized bestätigt (nicht-interaktiv).${NC}"
    else
        read_input "Bestätige durch Eingabe von '${AUTH_PHRASE}': " ans || die "Abbruch."
        [[ "$ans" == "$AUTH_PHRASE" ]] || die "Autorisierung nicht bestätigt. Beende."
    fi

    read_input "Referenz (Auftrags-/Ticket-Nr. oder 'LAB'): " ENGAGEMENT_REF || ENGAGEMENT_REF=""
    ENGAGEMENT_REF="$(printf '%s' "$ENGAGEMENT_REF" | tr -cd '[:alnum:]._/#- ')"
    [[ -n "$ENGAGEMENT_REF" ]] || ENGAGEMENT_REF="UNBENANNT"

    AUTHORIZED=1
    printf '%s | user=%s | host=%s | ref=%s | pid=%s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "${USER:-unknown}" "$(hostname 2>/dev/null || echo n/a)" \
        "$ENGAGEMENT_REF" "$$" >> "$AUTH_FILE"
    msg "${GREEN}[+] Autorisierung protokolliert (Referenz: $ENGAGEMENT_REF).${NC}"

    if [[ -s "$SCOPE_FILE" ]]; then
        msg "${GREEN}[+] Scope-Datei aktiv: $SCOPE_FILE ($(grep -cvE '^\s*(#|$)' -- "$SCOPE_FILE" 2>/dev/null || echo 0) Einträge)${NC}"
    else
        msg "${YELLOW}[!] Keine Scope-Datei ($SCOPE_FILE). Scope-Erzwingung ist DEAKTIVIERT.${NC}"
        msg "${YELLOW}    Empfehlung: erlaubte Netze/Hosts zeilenweise dort eintragen.${NC}"
    fi
}

require_authorized() {
    (( AUTHORIZED == 1 )) || { warn_fail "Nicht autorisiert – Aktion blockiert."; return 1; }
    return 0
}

# =====================================================
# ZIEL-VALIDIERUNG
# =====================================================
is_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a _oct <<< "$ip"
    for o in "${_oct[@]}"; do
        [[ "$o" =~ ^[0-9]{1,3}$ ]] || return 1
        ((10#$o <= 255)) || return 1
    done
    return 0
}

is_ipv4_cidr() {
    local ip="${1%%/*}" mask="${1##*/}"
    [[ "$1" == */* ]] || return 1
    is_ipv4 "$ip" || return 1
    [[ "$mask" =~ ^[0-9]{1,2}$ ]] || return 1
    ((10#$mask <= 32))
}

is_ipv4_range() {
    # nmap-Stil: 192.168.1.1-50  oder  192.168.1-3.1-254
    [[ "$1" =~ ^([0-9]{1,3}(-[0-9]{1,3})?\.){3}[0-9]{1,3}(-[0-9]{1,3})?$ ]]
}

is_ipv6() {
    [[ "$1" =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ ]] && [[ "$1" == *:* ]]
}

is_hostname() {
    local h="$1"
    (( ${#h} <= 253 )) || return 1
    [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

# Einzelziel (kein Komma)
valid_single_target() {
    local t="${1:-}"
    [[ -n "$t" ]] || return 1
    [[ "$t" == -* ]] && return 1
    [[ "$t" =~ [[:space:]\;\&\|\`\$\(\)\<\>\'\"\\\!\*\?\[\]\{\}] ]] && return 1
    is_ipv4 "$t" || is_ipv4_cidr "$t" || is_ipv4_range "$t" || is_ipv6 "$t" || is_hostname "$t"
}

# Ziel oder kommaseparierte Liste
valid_target() {
    local t="${1:-}" part
    [[ -n "$t" ]] || return 1
    IFS=',' read -r -a _parts <<< "$t"
    (( ${#_parts[@]} > 0 )) || return 1
    for part in "${_parts[@]}"; do
        valid_single_target "$part" || return 1
    done
    return 0
}

# =====================================================
# SCOPE-PRÜFUNG
# =====================================================
scope_check_host() {
    local t="$1"
    [[ -s "$SCOPE_FILE" ]] || return 0
    if check_tool python3; then
        python3 - "$t" "$SCOPE_FILE" <<'PY'
import ipaddress, sys
target, scopefile = sys.argv[1], sys.argv[2]
nets, names = [], []
try:
    with open(scopefile, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                names.append(line.lower())
except OSError:
    sys.exit(0)

def contained(net):
    return any(net.version == s.version and net.subnet_of(s) for s in nets)

# IP / CIDR
try:
    sys.exit(0 if contained(ipaddress.ip_network(target, strict=False)) else 1)
except ValueError:
    pass

# IPv4-Range a.b.c.d-e
if '-' in target and target.count('.') == 3:
    head, _, tail = target.rpartition('.')
    if '-' in tail:
        lo, _, hi = tail.partition('-')
        try:
            a = ipaddress.ip_network(f"{head}.{lo}/32")
            b = ipaddress.ip_network(f"{head}.{hi}/32")
            sys.exit(0 if contained(a) and contained(b) else 1)
        except ValueError:
            pass

tl = target.lower()
sys.exit(0 if any(tl == n or tl.endswith('.' + n) for n in names) else 1)
PY
        return $?
    fi
    grep -qxF -- "$t" "$SCOPE_FILE"
}

scope_guard() {
    [[ -s "$SCOPE_FILE" ]] || return 0
    local h bad=()
    for h in "${TARGET_HOSTS[@]}"; do
        scope_check_host "$h" || bad+=("$h")
    done
    if (( ${#bad[@]} > 0 )); then
        warn_fail "Ziel(e) ausserhalb des definierten Scopes: ${bad[*]}"
        msg "${YELLOW}    Scope-Datei: $SCOPE_FILE – Aktion blockiert.${NC}"
        log "SCOPE-VERLETZUNG blockiert: ${bad[*]}"
        return 1
    fi
    return 0
}

# =====================================================
# ZIELVERWALTUNG
# =====================================================
set_target_single() {
    local t="$1"
    TARGET="$t"
    TARGET_SPEC=("$t")
    TARGET_HOSTS=()
    IFS=',' read -r -a TARGET_HOSTS <<< "$t"
}

ask_target() {
    local newtarget=""
    read_input "Ziel (IP/CIDR/Range/Hostname) [aktuell: ${TARGET:-keines}]: " newtarget || return 1
    if [[ -n "$newtarget" ]]; then
        if valid_target "$newtarget"; then
            set_target_single "$newtarget"
        else
            warn_fail "Ungültiges Ziel-Format: $newtarget"
            return 1
        fi
    fi
    (( ${#TARGET_SPEC[@]} > 0 )) || { warn_fail "Kein Ziel gesetzt."; return 1; }
    scope_guard || return 1
    return 0
}

action_set_target_file() {
    local file="" line lineno=0 bad=0 count=0
    read_input "Pfad zur Zielliste (eine IP/Host pro Zeile): " file || return 1
    file="${file/#\~/$HOME}"
    [[ -n "$file" ]] || { warn_fail "Kein Pfad angegeben."; return 1; }
    [[ -f "$file" && -r "$file" ]] || { warn_fail "Datei nicht gefunden oder nicht lesbar: $file"; return 1; }
    [[ -L "$file" ]] && msg "${YELLOW}[!] Hinweis: $file ist ein Symlink.${NC}"

    local hosts=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((lineno++))
        line="${line%%#*}"
        line="${line//$'\r'/}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        if valid_single_target "$line"; then
            hosts+=("$line"); ((count++))
        else
            msg "${RED}  Zeile $lineno ungültig: $line${NC}"; ((bad++))
        fi
    done < "$file"

    if (( bad > 0 )); then
        warn_fail "$bad ungültige Einträge gefunden – Datei wird NICHT verwendet."
        return 1
    fi
    (( count > 0 )) || { warn_fail "Keine gültigen Ziele in der Datei."; return 1; }

    TARGET="Liste: $file"
    TARGET_SPEC=("-iL" "$file")
    TARGET_HOSTS=("${hosts[@]}")
    if ! scope_guard; then
        TARGET=""; TARGET_SPEC=(); TARGET_HOSTS=()
        return 1
    fi
    msg "${GREEN}✅ Zielmodus auf Liste umgestellt: $file ($count gültige Einträge)${NC}"
}

action_set_exclude() {
    local ex=""
    read_input "Auszuschließende Hosts (kommasepariert, leer = löschen): " ex || return 1
    if [[ -n "$ex" ]] && ! valid_target "$ex"; then
        warn_fail "Ungültiges Format."
        return 1
    fi
    EXCLUDE_HOSTS="$ex"
    if [[ -n "$EXCLUDE_HOSTS" ]]; then
        msg "${GREEN}✅ Ausschluss gesetzt: $EXCLUDE_HOSTS${NC}"
    else
        msg "${YELLOW}Ausschluss entfernt.${NC}"
    fi
}

action_change_target() {
    local newtarget=""
    read_input "Neues Ziel / Subnetz eingeben: " newtarget || return 1
    if valid_target "$newtarget"; then
        local old_t="$TARGET"; local -a old_spec=("${TARGET_SPEC[@]:-}") old_hosts=("${TARGET_HOSTS[@]:-}")
        set_target_single "$newtarget"
        if ! scope_guard; then
            TARGET="$old_t"; TARGET_SPEC=("${old_spec[@]:-}"); TARGET_HOSTS=("${old_hosts[@]:-}")
            return 1
        fi
        msg "${GREEN}✅ Target aktualisiert auf: $TARGET${NC}"
    else
        warn_fail "Ungültiges Ziel-Format."
    fi
}

# =====================================================
# NETZWERK-ERKENNUNG
# =====================================================
get_default_iface() {
    local iface=""
    if check_tool ip; then
        iface=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    fi
    [[ "$iface" =~ ^[A-Za-z0-9._:-]{1,16}$ ]] || iface=""
    printf '%s' "$iface"
}

detect_current_network() {
    local iface ip
    iface="$(get_default_iface)"
    if [[ -n "$iface" ]]; then
        ip=$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null | awk '{print $4; exit}')
        ip="${ip%%/*}"
        if is_ipv4 "${ip:-}"; then
            set_target_single "${ip%.*}.0/24"
            msg "${GREEN}[+] Aktuelles Netzwerk erkannt: ${YELLOW}$TARGET${NC}${GREEN} (Interface: $iface, IP: $ip)${NC}"
            return 0
        fi
    fi
    set_target_single "192.168.0.0/24"
    msg "${YELLOW}[!] Kein aktives Interface mit Default-Route gefunden. Fallback: $TARGET${NC}"
}

action_redetect_network() { detect_current_network; }

# =====================================================
# PROJEKT-INTEGRATION
# =====================================================
sanitize_name() {
    local n="$1"
    n="${n//[^A-Za-z0-9._-]/_}"
    n="${n#.}"
    printf '%s' "${n:0:64}"
}

select_project() {
    mkdir -p -- "$ENGAGEMENTS_DIR" || { warn_fail "Kann $ENGAGEMENTS_DIR nicht anlegen."; return 1; }
    chmod 700 -- "$ENGAGEMENTS_DIR" 2>/dev/null || true

    echo -e "${CYAN}Vorhandene Projekte:${NC}"
    local projects=("$ENGAGEMENTS_DIR"/*/) names=() p i=1
    for p in "${projects[@]}"; do
        [[ -d "$p" ]] || continue
        names+=("$(basename -- "${p%/}")")
        echo "  $i) ${names[-1]}"
        ((i++))
    done
    (( ${#names[@]} == 0 )) && echo "  (keine)"
    echo "  n) Neues Projekt anlegen"

    local sel="" newname=""
    read_input "Projekt wählen (Nummer oder 'n'): " sel || return 1

    if [[ "${sel,,}" == "n" ]]; then
        read_input "Name des neuen Projekts: " newname || return 1
        newname="$(sanitize_name "$newname")"
        [[ -n "$newname" ]] || { warn_fail "Ungültiger Projektname."; return 1; }
        mkdir -p -- "$ENGAGEMENTS_DIR/$newname"/{recon,exploit,loot,report} || { warn_fail "Anlegen fehlgeschlagen."; return 1; }
        RECON_DIR="$ENGAGEMENTS_DIR/$newname/recon"
    elif is_uint "$sel"; then
        local idx=$((10#$sel - 1))
        if (( idx >= 0 && idx < ${#names[@]} )); then
            RECON_DIR="$ENGAGEMENTS_DIR/${names[$idx]}/recon"
            mkdir -p -- "$RECON_DIR" || { warn_fail "Anlegen fehlgeschlagen."; return 1; }
        else
            msg "${YELLOW}Ungültige Auswahl, nutze Standard-Ordner.${NC}"
            RECON_DIR="$ENGAGEMENTS_DIR/default/recon"
            mkdir -p -- "$RECON_DIR"
        fi
    else
        msg "${YELLOW}Ungültige Eingabe, nutze Standard-Ordner.${NC}"
        RECON_DIR="$ENGAGEMENTS_DIR/default/recon"
        mkdir -p -- "$RECON_DIR"
    fi
    chmod -R go-rwx -- "$(dirname -- "$RECON_DIR")" 2>/dev/null || true
    msg "${GREEN}[+] Recon-Verzeichnis: $RECON_DIR${NC}"
}

require_project() {
    if [[ -z "$RECON_DIR" || ! -d "$RECON_DIR" ]]; then
        warn_fail "Kein gültiges Projekt-/Recon-Verzeichnis gesetzt."
        select_project || return 1
    fi
    [[ -w "$RECON_DIR" ]] || { warn_fail "Recon-Verzeichnis nicht beschreibbar: $RECON_DIR"; return 1; }
    return 0
}

# =====================================================
# UNTERBRECHBARE KOMMANDO-AUSFÜHRUNG
# =====================================================
_scan_int_handler() {
    SCAN_INTERRUPTED=1
    [[ -n "$SCAN_PID" ]] && sudo -n kill -INT -- "$SCAN_PID" 2>/dev/null || true
}

run_interruptible() {
    local rc=0
    SCAN_INTERRUPTED=0
    trap '_scan_int_handler' INT
    "$@" &
    SCAN_PID=$!
    wait "$SCAN_PID"; rc=$?
    SCAN_PID=""
    trap 'cleanup; exit 130' INT
    (( SCAN_INTERRUPTED == 1 )) && rc=130
    return $rc
}

# =====================================================
# SCAN-AUSFÜHRUNG
# =====================================================
run_scan() {
    require_authorized || return 1
    require_project || return 1
    scope_guard || return 1

    local scan_type="$1"; shift
    scan_type="$(sanitize_name "$scan_type")"
    local timestamp base rc duration start_ts
    timestamp=$(date +%Y%m%d_%H%M%S)
    base="$RECON_DIR/${scan_type}_${timestamp}"

    local exclude_args=()
    [[ -n "$EXCLUDE_HOSTS" ]] && exclude_args=(--exclude "$EXCLUDE_HOSTS")

    local nmap_cmd=(sudo -n nmap "$@" "${exclude_args[@]}" --stats-every 30s -oA "$base" -- "${TARGET_SPEC[@]}")
    msg "${YELLOW}[*] ${scan_type}-Scan auf ${TARGET} ...${NC}"
    log "CMD: ${nmap_cmd[*]}"

    start_ts=$(date +%s)
    run_interruptible "${nmap_cmd[@]}"
    rc=$?
    duration=$(( $(date +%s) - start_ts ))

    if (( rc == 0 )) && [[ -f "${base}.nmap" ]]; then
        chmod 600 -- "${base}".* 2>/dev/null || true
        printf '%s | %s | %s | %s | %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$scan_type" "$TARGET" "$ENGAGEMENT_REF" "${base}.nmap" >> "$HISTORY_FILE"
        msg "${GREEN}✅ Scan abgeschlossen (${duration}s). Ergebnis: ${base}.nmap${NC}"
        (( duration > 60 )) && notify "Scan '$scan_type' abgeschlossen (${duration}s)"
    elif (( rc == 130 )); then
        msg "${YELLOW}[!] Scan durch Benutzer abgebrochen (Teilergebnisse ggf. unter ${base}.*).${NC}"
    else
        warn_fail "Scan fehlgeschlagen (Exit-Code $rc). Details siehe oben / $LOGFILE."
    fi
    return 0
}

# =====================================================
# AKTIONEN: SCANNING
# =====================================================
action_host_discovery() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "discovery" -sn -n -T3 -PE -PS21,22,80,443,3389 -PA80,443
}

action_normal_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "normal" -T3 -sV --version-intensity 5 --open
}

action_stealth_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "stealth" -sS -sV -O -T3 --open
}

action_aggressive_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    msg "${YELLOW}[!] -A ist laut/aufdringlich (OS, Scripts, Traceroute).${NC}"
    ask_yes_no "Wirklich fortfahren?" || { msg "${YELLOW}Abgebrochen.${NC}"; return 0; }
    run_scan "aggressive" -A -T4
}

action_web_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "web" -p 80,443,8080,8443,8000,8888 -sV --open -T4
}

action_subnet_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "subnet" -T4 -sV --open
}

action_t4_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "t4" -T4 -sS -sV -O --open
}

action_udp_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    msg "${YELLOW}[!] UDP-Scans sind deutlich langsamer als TCP. Top 20 UDP-Ports werden geprüft.${NC}"
    run_scan "udp" -sU -T4 --top-ports 20 --open
}

# =====================================================
# AKTIONEN: TIEFENSCANS
# =====================================================
action_full_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    msg "${YELLOW}[!] Vollscan (65535 Ports + OS + Vuln-Scripts) kann SEHR lange dauern (20+ min/Host) und ist sehr laut.${NC}"
    ask_yes_no "Wirklich fortfahren?" || { msg "${YELLOW}Abgebrochen.${NC}"; return 0; }
    local scripts="vuln"
    nmap --script-help vulners >/dev/null 2>&1 && scripts="vuln,vulners"
    run_scan "full" -sS -sV -O -p- --script "$scripts" -T4 --max-retries 2
}

action_vuln_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    msg "${YELLOW}[!] Vuln-Scripts können Dienste destabilisieren. Nur mit Freigabe ausführen.${NC}"
    ask_yes_no "Wirklich fortfahren?" || { msg "${YELLOW}Abgebrochen.${NC}"; return 0; }
    local scripts="vuln"
    nmap --script-help vulners >/dev/null 2>&1 && scripts="vulners,vuln"
    run_scan "vuln" -sV --script "$scripts" -T4
}

# =====================================================
# AKTIONEN: EXPORT & REPORTING
# =====================================================
action_html_export() {
    require_tools nmap xsltproc || return 1
    require_authorized || return 1
    ask_target || return 1
    require_project || return 1

    local timestamp base rc
    timestamp=$(date +%Y%m%d_%H%M%S)
    base="$RECON_DIR/html_${timestamp}"
    local exclude_args=()
    [[ -n "$EXCLUDE_HOSTS" ]] && exclude_args=(--exclude "$EXCLUDE_HOSTS")

    msg "${YELLOW}[*] HTML-Export wird erstellt...${NC}"
    if [[ -f "$NMAP_XSL" ]]; then
        run_interruptible sudo -n nmap -sS -sV -O -T4 "${exclude_args[@]}" -oX "${base}.xml" -- "${TARGET_SPEC[@]}"
        rc=$?
        (( rc == 0 )) && xsltproc -o "${base}.html" -- "$NMAP_XSL" "${base}.xml"
    else
        msg "${YELLOW}[!] Lokales nmap.xsl nicht gefunden – nutze eingebettetes Online-Stylesheet (benötigt Internet).${NC}"
        if ! ask_yes_no "Externes Stylesheet laden?"; then
            msg "${YELLOW}Abgebrochen.${NC}"; return 0
        fi
        run_interruptible sudo -n nmap -sS -sV -O -T4 --webxml "${exclude_args[@]}" -oX "${base}.xml" -- "${TARGET_SPEC[@]}"
        rc=$?
        (( rc == 0 )) && xsltproc -o "${base}.html" -- "${base}.xml"
    fi

    if [[ -f "${base}.html" ]]; then
        chmod 600 -- "${base}".* 2>/dev/null || true
        printf '%s | %s | %s | %s | %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "html" "$TARGET" "$ENGAGEMENT_REF" "${base}.html" >> "$HISTORY_FILE"
        msg "${GREEN}✅ HTML-Report erstellt: ${base}.html${NC}"
    else
        warn_fail "HTML-Export fehlgeschlagen (Exit-Code ${rc:-?})."
    fi
}

action_show_history() {
    echo -e "${BLUE}=== Scan-Historie (letzte 20 Einträge) ===${NC}"
    if [[ -s "$HISTORY_FILE" ]]; then
        if check_tool column; then
            tail -n 20 -- "$HISTORY_FILE" | column -t -s '|'
        else
            tail -n 20 -- "$HISTORY_FILE"
        fi
    else
        echo -e "${RED}Noch keine Scans in der Historie.${NC}"
    fi
}

# Dateiauswahl-Helfer: füllt globales SELECTED_FILE
SELECTED_FILE=""
pick_file() {
    local pattern="$1" prompt="$2"
    local files=() f sel idx
    while IFS= read -r -d '' f; do files+=("$f"); done \
        < <(find "$ENGAGEMENTS_DIR" -type f -name "$pattern" -print0 2>/dev/null | sort -z)
    if (( ${#files[@]} == 0 )); then
        warn_fail "Keine Dateien ($pattern) unter $ENGAGEMENTS_DIR gefunden."
        return 1
    fi
    echo -e "${CYAN}Verfügbare Dateien:${NC}"
    local i=1
    for f in "${files[@]}"; do echo "  $i) $f"; ((i++)); done
    read_input "$prompt (Nummer): " sel || return 1
    is_uint "$sel" || { warn_fail "Keine gültige Nummer."; return 1; }
    idx=$((10#$sel - 1))
    (( idx >= 0 && idx < ${#files[@]} )) || { warn_fail "Ungültige Auswahl."; return 1; }
    SELECTED_FILE="${files[$idx]}"
    return 0
}

action_searchsploit_correlate() {
    require_tools searchsploit || return 1
    require_project || return 1
    pick_file "*.nmap" "Welche Scan-Datei?" || return 1
    local scanfile="$SELECTED_FILE"

    local services
    services=$(grep -aE '^[0-9]+/(tcp|udp)[[:space:]]+open' -- "$scanfile" \
        | awk '{$1="";$2="";$3="";print}' \
        | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]\+$//' \
        | grep -v '^$' | sort -u)

    if [[ -z "$services" ]]; then
        warn_fail "Keine Dienst-/Versionsinformationen gefunden (Scan ohne -sV?)."
        return 1
    fi

    local timestamp report
    timestamp=$(date +%Y%m%d_%H%M%S)
    report="$RECON_DIR/searchsploit_${timestamp}.txt"
    : > "$report"; chmod 600 -- "$report" 2>/dev/null || true

    msg "${YELLOW}[*] Korreliere gefundene Dienste mit Searchsploit...${NC}"
    {
        printf 'Searchsploit-Korrelation für: %s\n' "$scanfile"
        printf 'Referenz: %s\nErstellt: %s\n' "$ENGAGEMENT_REF" "$(date)"
        printf '========================================\n'
    } >> "$report"

    local svc term
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        # Harte Sanitisierung: nur alnum, Punkt, Minus, Unterstrich, Space
        term="$(printf '%s' "$svc" | tr -c '[:alnum:]._ -' ' ' | tr -s ' ')"
        term="${term#"${term%%[![:space:]]*}"}"
        term="${term%"${term##*[![:space:]]}"}"
        term="${term:0:80}"
        [[ -n "$term" ]] || continue
        echo -e "${CYAN}--- $term ---${NC}"
        { printf '\n### %s\n' "$term"; } >> "$report"
        searchsploit -- "$term" 2>/dev/null | strip_ansi | tee -a "$report" || true
    done <<< "$services"

    msg "${GREEN}✅ Korrelation abgeschlossen. Bericht: $report${NC}"
}

action_scan_diff() {
    local files=() f
    while IFS= read -r -d '' f; do files+=("$f"); done \
        < <(find "$ENGAGEMENTS_DIR" -type f -name "*.gnmap" -print0 2>/dev/null | sort -z)
    if (( ${#files[@]} < 2 )); then
        warn_fail "Mindestens zwei .gnmap-Scans nötig (aktuell: ${#files[@]})."
        return 1
    fi

    echo -e "${CYAN}Verfügbare Scans:${NC}"
    local i=1
    for f in "${files[@]}"; do echo "  $i) $f"; ((i++)); done

    local sel1 sel2 idx1 idx2
    read_input "Älterer Scan (Nummer): " sel1 || return 1
    read_input "Neuerer Scan (Nummer): " sel2 || return 1
    is_uint "$sel1" && is_uint "$sel2" || { warn_fail "Keine gültigen Nummern."; return 1; }
    idx1=$((10#$sel1 - 1)); idx2=$((10#$sel2 - 1))
    (( idx1 >= 0 && idx1 < ${#files[@]} && idx2 >= 0 && idx2 < ${#files[@]} )) \
        || { warn_fail "Ungültige Auswahl."; return 1; }
    (( idx1 == idx2 )) && { warn_fail "Bitte zwei unterschiedliche Scans wählen."; return 1; }

    local old="${files[$idx1]}" new="${files[$idx2]}"
    local old_ports new_ports
    old_ports=$(grep -aoE '[0-9]+/open/[a-z]+//[a-zA-Z0-9_.-]*' -- "$old" | sort -u)
    new_ports=$(grep -aoE '[0-9]+/open/[a-z]+//[a-zA-Z0-9_.-]*' -- "$new" | sort -u)

    echo -e "${BLUE}=== Neu geöffnete Ports (in $new, nicht in $old) ===${NC}"
    comm -13 <(printf '%s\n' "$old_ports") <(printf '%s\n' "$new_ports") | { grep . || echo "  (keine)"; }

    echo -e "${BLUE}=== Weggefallene Ports (in $old, nicht mehr in $new) ===${NC}"
    comm -23 <(printf '%s\n' "$old_ports") <(printf '%s\n' "$new_ports") | { grep . || echo "  (keine)"; }
}

# =====================================================
# AKTIONEN: MITM (ARP-Spoofing)
# =====================================================
action_arp_mitm() {
    require_tools bettercap || return 1
    require_authorized || return 1

    echo -e "${RED}${BOLD}WARNUNG: ARP-Spoofing manipuliert fremden Netzwerkverkehr.${NC}"
    echo -e "${RED}Nur im eigenen Lab oder mit ausdrücklicher schriftlicher Erlaubnis!${NC}"
    ask_yes_no "Liegt eine ausdrückliche Freigabe für MITM vor?" || { msg "${YELLOW}Abgebrochen.${NC}"; return 0; }

    if [[ -n "$BETTERCAP_PID" ]] && kill -0 "$BETTERCAP_PID" 2>/dev/null; then
        warn_fail "Es läuft bereits ein ARP-Spoofing-Prozess (PID $BETTERCAP_PID)."
        return 1
    fi

    local spoof_target=""
    read_input "Ziel-IP zum Spoofen (z.B. 192.168.0.1): " spoof_target || return 1
    is_ipv4 "$spoof_target" || { warn_fail "Ungültige IPv4-Adresse."; return 1; }
    if [[ -s "$SCOPE_FILE" ]] && ! scope_check_host "$spoof_target"; then
        warn_fail "Ziel ausserhalb des Scopes – MITM blockiert."
        log "SCOPE-VERLETZUNG (MITM) blockiert: $spoof_target"
        return 1
    fi

    local iface; iface="$(get_default_iface)"
    [[ -n "$iface" ]] || { warn_fail "Kein Default-Interface ermittelbar."; return 1; }

    BETTERCAP_CAPLET="$(mktemp -t "arpspoof_XXXXXXXX.cap")" || { warn_fail "mktemp fehlgeschlagen."; return 1; }
    chmod 600 -- "$BETTERCAP_CAPLET"
    cat > "$BETTERCAP_CAPLET" <<EOF
net.probe on
set arp.spoof.targets $spoof_target
set arp.spoof.internal false
arp.spoof on
EOF

    msg "${YELLOW}[*] Starte ARP-Spoofing (iface: $iface) gegen $spoof_target ...${NC}"
    log "MITM START: target=$spoof_target iface=$iface ref=$ENGAGEMENT_REF"
    sudo -n bettercap -iface "$iface" -caplet "$BETTERCAP_CAPLET" >/dev/null 2>&1 &
    BETTERCAP_PID=$!
    sleep 3

    if kill -0 "$BETTERCAP_PID" 2>/dev/null; then
        msg "${GREEN}✅ ARP-Spoofing läuft (PID $BETTERCAP_PID).${NC}"
        msg "${CYAN}Paralleles Scannen möglich (z.B. 'Normaler Port-Scan' gegen $spoof_target).${NC}"
        msg "${YELLOW}Zum Beenden: Menüpunkt 'ARP-Spoofing stoppen' nutzen.${NC}"
    else
        warn_fail "Bettercap konnte nicht gestartet werden (Rechte? Interface?)."
        rm -f -- "$BETTERCAP_CAPLET"; BETTERCAP_CAPLET=""; BETTERCAP_PID=""
    fi
}

action_arp_mitm_stop() {
    if [[ -n "$BETTERCAP_PID" ]] && kill -0 "$BETTERCAP_PID" 2>/dev/null; then
        sudo -n kill -TERM -- "$BETTERCAP_PID" 2>/dev/null || true
        sleep 2
        kill -0 "$BETTERCAP_PID" 2>/dev/null && sudo -n kill -KILL -- "$BETTERCAP_PID" 2>/dev/null || true
        msg "${GREEN}✅ ARP-Spoofing gestoppt (PID $BETTERCAP_PID).${NC}"
        log "MITM STOP: pid=$BETTERCAP_PID"
    else
        msg "${YELLOW}Kein aktiver ARP-Spoofing-Prozess.${NC}"
    fi
    [[ -n "$BETTERCAP_CAPLET" ]] && rm -f -- "$BETTERCAP_CAPLET"
    BETTERCAP_CAPLET=""
    BETTERCAP_PID=""
}

# =====================================================
# EINSTELLUNGEN
# =====================================================
action_show_log() {
    if [[ -s "$LOGFILE" ]]; then
        tail -n 30 -- "$LOGFILE"
    else
        echo "Noch keine Log-Einträge."
    fi
}

action_show_scope() {
    echo -e "${BLUE}=== Scope-Datei: $SCOPE_FILE ===${NC}"
    if [[ -s "$SCOPE_FILE" ]]; then
        grep -vE '^\s*(#|$)' -- "$SCOPE_FILE" | sed 's/^/  /'
    else
        echo -e "${YELLOW}  (keine Scope-Datei – Scope-Erzwingung deaktiviert)${NC}"
        echo -e "${CYAN}  Anlegen z.B.: printf '192.168.56.0/24\\nlab.local\\n' > $SCOPE_FILE${NC}"
    fi
}

# =====================================================
# HEADER
# =====================================================
show_header() {
    local mitm="aus"
    [[ -n "$BETTERCAP_PID" ]] && kill -0 "$BETTERCAP_PID" 2>/dev/null && mitm="AKTIV"
    local scope="deaktiviert"
    [[ -s "$SCOPE_FILE" ]] && scope="aktiv ($SCOPE_FILE)"
    echo -e "${CYAN}Referenz    : ${YELLOW}${ENGAGEMENT_REF:-n/a}${NC}"
    echo -e "${CYAN}Ziel        : ${YELLOW}${TARGET:-Keines}${NC}"
    echo -e "${CYAN}Ausschluss  : ${YELLOW}${EXCLUDE_HOSTS:-keiner}${NC}"
    echo -e "${CYAN}Scope       : ${YELLOW}${scope}${NC}"
    echo -e "${CYAN}Projekt     : ${YELLOW}${RECON_DIR:-nicht gesetzt}${NC}"
    echo -e "${CYAN}ARP-Spoof   : ${YELLOW}${mitm}${NC}"
    echo ""
}

# =====================================================
# GENERISCHES MENÜ-SYSTEM
# =====================================================
run_menu() {
    local title="$1"; shift
    local -a entries=("$@")

    while true; do
        clear
        show_header
        echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
        echo -e "                   ${GREEN}${title}${NC}"
        echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

        local i=1 entry
        for entry in "${entries[@]}"; do
            printf ' %d) %s\n' "$i" "${entry%%|*}"
            ((i++))
        done
        echo " 0) Zurück"
        echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

        local choice="" idx fn
        read_input "Wähle eine Option: " choice || return 0
        [[ "$choice" == "0" ]] && return 0
        if ! is_uint "$choice"; then
            msg "${RED}Ungültige Option!${NC}"; sleep 1; continue
        fi
        idx=$((10#$choice - 1))
        if (( idx >= 0 && idx < ${#entries[@]} )); then
            fn="${entries[$idx]#*|}"
            if declare -F "$fn" >/dev/null; then
                "$fn" || true
            else
                msg "${RED}Interner Fehler: Funktion '$fn' existiert nicht.${NC}"
            fi
        else
            msg "${RED}Ungültige Option!${NC}"
        fi
        echo ""
        pause
    done
}

menu_scanning() {
    run_menu "Discovery & Scanning" \
        "Schneller Host-Discovery (Ping-Scan)|action_host_discovery" \
        "Normaler Port-Scan (Top 1000)|action_normal_scan" \
        "Stealth SYN-Scan + Version + OS|action_stealth_scan" \
        "Aggressiver Scan (-A)|action_aggressive_scan" \
        "Nur Web-Ports scannen|action_web_scan" \
        "Ganzes Subnetz scannen|action_subnet_scan" \
        "Scan mit Timing T4 (schnell)|action_t4_scan" \
        "UDP-Scan (Top 20 Ports)|action_udp_scan"
}

menu_deepscans() {
    run_menu "Tiefenscans" \
        "Kompletter Scan (alle Ports + OS + Vuln)|action_full_scan" \
        "Schwachstellen-Scan (vulners + vuln)|action_vuln_scan"
}

menu_export() {
    run_menu "Export & Reporting" \
        "Scan-Ergebnis als HTML exportieren|action_html_export" \
        "Scan-Historie anzeigen|action_show_history" \
        "Searchsploit-Korrelation aus Scan|action_searchsploit_correlate" \
        "Scan-Diff (zwei Scans vergleichen)|action_scan_diff"
}

menu_mitm() {
    run_menu "MITM (ARP-Spoofing)" \
        "ARP-Spoofing starten|action_arp_mitm" \
        "ARP-Spoofing stoppen|action_arp_mitm_stop"
}

menu_settings() {
    run_menu "Einstellungen" \
        "Ziel-IP / Subnetz ändern|action_change_target" \
        "Zielliste aus Datei verwenden (-iL)|action_set_target_file" \
        "Host-Ausschluss setzen (--exclude)|action_set_exclude" \
        "Projekt wechseln|select_project" \
        "Netzwerk neu erkennen|action_redetect_network" \
        "Scope anzeigen|action_show_scope" \
        "Log-Datei anzeigen|action_show_log"
}

# =====================================================
# CLEANUP
# =====================================================
cleanup() {
    (( CLEANED_UP == 1 )) && return 0
    CLEANED_UP=1
    printf '\n'
    if [[ -n "$SCAN_PID" ]] && kill -0 "$SCAN_PID" 2>/dev/null; then
        sudo -n kill -TERM -- "$SCAN_PID" 2>/dev/null || true
    fi
    if [[ -n "$BETTERCAP_PID" ]] && kill -0 "$BETTERCAP_PID" 2>/dev/null; then
        msg "${YELLOW}[*] Stoppe laufendes ARP-Spoofing (PID $BETTERCAP_PID) ...${NC}"
        sudo -n kill -TERM -- "$BETTERCAP_PID" 2>/dev/null || true
        sleep 1
        kill -0 "$BETTERCAP_PID" 2>/dev/null && sudo -n kill -KILL -- "$BETTERCAP_PID" 2>/dev/null || true
    fi
    [[ -n "$BETTERCAP_CAPLET" ]] && rm -f -- "$BETTERCAP_CAPLET"
    [[ -n "$SUDO_KEEPALIVE_PID" ]] && kill -- "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    msg "${GREEN}✅ Aufgeräumt. Auf Wiedersehen!${NC}"
}
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# =====================================================
# CLI-ARGUMENTE
# =====================================================
usage() {
    cat <<EOF
$SCRIPT_NAME $SCRIPT_VERSION

Verwendung: $SCRIPT_NAME [Optionen]

  -s, --scope DATEI         Scope-Datei (erlaubte Netze/Hosts, eine pro Zeile)
  -y, --assume-authorized   Autorisierung nicht-interaktiv bestätigen (wird protokolliert)
  -h, --help                Diese Hilfe

Nur für eigene Lab-Umgebungen oder schriftlich autorisierte Tests.
EOF
}

while (( $# > 0 )); do
    case "$1" in
        -s|--scope)
            [[ -n "${2:-}" ]] || die "--scope benötigt einen Pfad."
            SCOPE_FILE="${2/#\~/$HOME}"
            [[ -f "$SCOPE_FILE" && -r "$SCOPE_FILE" ]] || die "Scope-Datei nicht lesbar: $SCOPE_FILE"
            shift 2 ;;
        -y|--assume-authorized) ASSUME_AUTHORIZED=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "Unbekannte Option: $1" ;;
    esac
done

# =====================================================
# START
# =====================================================
require_not_root
[[ -n "${BASH_VERSION:-}" ]] || die "Dieses Skript benötigt Bash."
(( ${BASH_VERSINFO[0]} >= 4 )) || die "Bash >= 4 erforderlich."
init_files
rotate_log_if_needed

clear
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║            NMAP POWER TOOL für Gaia  –  hardened              ║"
echo "║   Discovery • Scanning • Export • MITM • Searchsploit • Diff   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

require_tools nmap || die "nmap ist zwingend erforderlich."
authorization_gate
log "SESSION START (v$SCRIPT_VERSION, ref=$ENGAGEMENT_REF)"

msg "${CYAN}[*] Fordere sudo-Rechte einmalig an ...${NC}"
sudo -v || die "sudo-Authentifizierung fehlgeschlagen."
(
    while kill -0 "$$" 2>/dev/null; do
        sudo -n true 2>/dev/null || exit 0
        sleep 50
    done
) >/dev/null 2>&1 &
SUDO_KEEPALIVE_PID=$!
disown "$SUDO_KEEPALIVE_PID" 2>/dev/null || true

detect_current_network
select_project || die "Kein Projektverzeichnis verfügbar."

# ---------- Hauptmenü ----------
while true; do
    clear
    show_header
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "                   ${GREEN}Hauptmenü${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo " 1) Discovery & Scanning"
    echo " 2) Tiefenscans (Vollscan, Vuln-Scan)"
    echo " 3) Export & Reporting (inkl. Searchsploit, Diff)"
    echo " 4) MITM (ARP-Spoofing)"
    echo " 5) Einstellungen (Ziel, Ausschluss, Projekt, Netzwerk, Scope, Log)"
    echo " 6) Beenden"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

    choice=""
    read_input "Wähle eine Option (1-6): " choice || { msg "${GREEN}Auf Wiedersehen!${NC}"; exit 0; }

    case "$choice" in
        1) menu_scanning ;;
        2) menu_deepscans ;;
        3) menu_export ;;
        4) menu_mitm ;;
        5) menu_settings ;;
        6) msg "${GREEN}Auf Wiedersehen!${NC}"; exit 0 ;;
        *) msg "${RED}Ungültige Option!${NC}"; sleep 1 ;;
    esac
done
