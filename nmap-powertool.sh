#!/bin/bash
# =====================================================
# NMAP POWER TOOL        
# Kategorien-Menü, Dispatch-Tabellen, echte Scan-Historie,
# Projekt-Integration, Searchsploit-Korrelation, Scan-Diff,
# Zielliste, UDP-Scan, Host-Ausschluss, Desktop-Benachrichtigung
# (c) Patrick May 2026 - All rights reserved (portfolio use)
# NUR für eigene Lab-Umgebung / autorisierte Tests!
# =====================================================

set -uo pipefail

# =====================================================
# STATE
# =====================================================
readonly LOGFILE="$HOME/nmap_pato.log"
readonly LOG_MAX_BYTES=5242880  # 5 MB
readonly ENGAGEMENTS_DIR="$HOME/engagements"
readonly HISTORY_FILE="$HOME/.nmap_pato_history.log"
readonly NMAP_XSL="/usr/share/nmap/nmap.xsl"

TARGET=""              # Anzeige-String (IP/Subnetz ODER "Liste: <Datei>")
TARGET_SPEC=()          # Tatsächliche nmap-Zielargumente, z.B. ("$TARGET") oder ("-iL" "$file")
EXCLUDE_HOSTS=""        # Optional: --exclude Wert
RECON_DIR=""
BETTERCAP_CAPLET=""
BETTERCAP_PID=""

# =====================================================
# FARBEN
# =====================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# =====================================================
# BASIS-HELFER
# =====================================================

rotate_log_if_needed() {
    if [ -f "$LOGFILE" ]; then
        local size
        size=$(stat -c%s "$LOGFILE" 2>/dev/null || echo 0)
        [ "$size" -gt "$LOG_MAX_BYTES" ] && mv -f "$LOGFILE" "${LOGFILE}.old"
    fi
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOGFILE"
}

msg() {
    echo -e "$1"
    log "$(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')"
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
    read -rp "Drücke ENTER zum Fortfahren..."
}

check_tool() {
    command -v "$1" &>/dev/null
}

require_tools() {
    local missing=()
    for tool in "$@"; do
        check_tool "$tool" || missing+=("$tool")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        warn_fail "Fehlende Programme: ${missing[*]}"
        msg "${YELLOW}Installiere mit: sudo apt install ${missing[*]} -y${NC}"
        return 1
    fi
    return 0
}

require_root_actions() {
    if [ "$EUID" -eq 0 ]; then
        die "Bitte NICHT als root starten. Das Skript nutzt sudo gezielt nur wo nötig."
    fi
}

# Desktop-Benachrichtigung, falls verfügbar - schlägt lautlos fehl, wenn nicht.
notify() {
    check_tool notify-send && notify-send "Nmap Power Tool" "$1" 2>/dev/null
}

# =====================================================
# ZIEL-VALIDIERUNG & ZIELVERWALTUNG
# =====================================================
valid_target() {
    local t="$1"
    [ -n "$t" ] || return 1
    [[ "$t" == -* ]] && return 1
    [[ "$t" =~ [\;\&\|\`\$\(\)\<\>] ]] && return 1
    [[ "$t" =~ ^[a-zA-Z0-9.:/,_-]+$ ]] || return 1
    return 0
}

# Fragt nach einem Einzelziel/Subnetz (Enter = aktuelles behalten), validiert,
# setzt sowohl TARGET (Anzeige) als auch TARGET_SPEC (echtes nmap-Argument).
ask_target() {
    read -rp "Ziel (IP/Subnetz/Hostname) [aktuell: ${TARGET:-keines}]: " newtarget
    if [ -n "$newtarget" ]; then
        if valid_target "$newtarget"; then
            TARGET="$newtarget"
            TARGET_SPEC=("$TARGET")
        else
            warn_fail "Ungültiges Ziel-Format: $newtarget"
            return 1
        fi
    fi
    [ ${#TARGET_SPEC[@]} -gt 0 ] || { warn_fail "Kein Ziel gesetzt."; return 1; }
    return 0
}

# Wechselt den Zielmodus auf eine Datei mit Host-Liste (-iL).
action_set_target_file() {
    read -rp "Pfad zur Zielliste (eine IP/Host pro Zeile): " file
    file="${file/#\~/$HOME}"
    if [ ! -f "$file" ]; then
        warn_fail "Datei nicht gefunden: $file"
        return 1
    fi
    TARGET="Liste: $file"
    TARGET_SPEC=("-iL" "$file")
    msg "${GREEN}✅ Zielmodus auf Liste umgestellt: $file ($(wc -l < "$file") Einträge)${NC}"
}

action_set_exclude() {
    read -rp "Auszuschließende Hosts (kommasepariert, leer = löschen): " ex
    if [ -n "$ex" ] && ! valid_target "$ex"; then
        warn_fail "Ungültiges Format."
        return 1
    fi
    EXCLUDE_HOSTS="$ex"
    if [ -n "$EXCLUDE_HOSTS" ]; then
        msg "${GREEN}✅ Ausschluss gesetzt: $EXCLUDE_HOSTS${NC}"
    else
        msg "${YELLOW}Ausschluss entfernt.${NC}"
    fi
}

# =====================================================
# NETZWERK-ERKENNUNG
# =====================================================
detect_current_network() {
    local iface ip
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    if [ -n "$iface" ]; then
        ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
        if [ -n "$ip" ]; then
            TARGET="${ip%.*}.0/24"
            TARGET_SPEC=("$TARGET")
            msg "${GREEN}[+] Aktuelles Netzwerk automatisch erkannt: ${YELLOW}$TARGET${NC} (Interface: $iface, IP: $ip)"
            return 0
        fi
    fi
    TARGET="192.168.0.0/24"
    TARGET_SPEC=("$TARGET")
    msg "${YELLOW}[!] Kein aktives Interface mit Default-Route gefunden. Fallback: $TARGET${NC}"
}

action_redetect_network() {
    detect_current_network
}

# =====================================================
# PROJEKT-INTEGRATION
# =====================================================
select_project() {
    mkdir -p "$ENGAGEMENTS_DIR"
    echo -e "${CYAN}Vorhandene Projekte:${NC}"
    local projects=("$ENGAGEMENTS_DIR"/*/)
    local names=() i=1
    for p in "${projects[@]}"; do
        [ -d "$p" ] || continue
        names+=("$(basename "$p")")
        echo "  $i) ${names[-1]}"
        ((i++))
    done
    echo "  n) Neues Projekt anlegen"
    read -rp "Projekt wählen (Nummer oder 'n'): " sel

    if [ "$sel" = "n" ]; then
        read -rp "Name des neuen Projekts: " newname
        newname=$(echo "$newname" | tr ' ' '_')
        mkdir -p "$ENGAGEMENTS_DIR/$newname"/{recon,exploit,loot,report}
        RECON_DIR="$ENGAGEMENTS_DIR/$newname/recon"
    else
        local idx=$((sel - 1))
        if [ "$idx" -ge 0 ] && [ "$idx" -lt ${#names[@]} ]; then
            RECON_DIR="$ENGAGEMENTS_DIR/${names[$idx]}/recon"
            mkdir -p "$RECON_DIR"
        else
            msg "${YELLOW}Ungültige Auswahl, nutze Standard-Ordner.${NC}"
            RECON_DIR="$ENGAGEMENTS_DIR/default/recon"
            mkdir -p "$RECON_DIR"
        fi
    fi
    msg "${GREEN}[+] Recon-Verzeichnis: $RECON_DIR${NC}"
}

# =====================================================
# SCAN-AUSFÜHRUNG (echte Dateien, echte Historie, Benachrichtigung)
# =====================================================
run_scan() {
    local scan_type="$1"; shift
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local base="$RECON_DIR/${scan_type}_${timestamp}"
    local exclude_args=()
    [ -n "$EXCLUDE_HOSTS" ] && exclude_args=(--exclude "$EXCLUDE_HOSTS")

    msg "${YELLOW}[*] $scan_type-Scan auf ${TARGET}...${NC}"
    local start_ts
    start_ts=$(date +%s)

    # shellcheck disable=SC2068
    sudo nmap "$@" "${exclude_args[@]}" -oA "$base" "${TARGET_SPEC[@]}"
    local rc=$?

    local duration=$(( $(date +%s) - start_ts ))

    if [ $rc -eq 0 ] && [ -f "${base}.nmap" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') | $scan_type | $TARGET | ${base}.nmap" >> "$HISTORY_FILE"
        msg "${GREEN}✅ Scan abgeschlossen (${duration}s). Ergebnis: ${base}.nmap${NC}"
        [ "$duration" -gt 60 ] && notify "Scan '$scan_type' abgeschlossen (${duration}s)"
    else
        warn_fail "Scan fehlgeschlagen oder abgebrochen (Exit-Code $rc)."
    fi
}

# =====================================================
# AKTIONEN: SCANNING
# =====================================================

action_host_discovery() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "discovery" -sn -T4
}

action_normal_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "normal" -T4 -sV
}

action_stealth_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "stealth" -sS -sV -O -T4
}

action_aggressive_scan() {
    require_tools nmap || return 1
    ask_target || return 1
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
    run_scan "subnet" -T4 -sV
}

action_t4_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "t4" -T4 -sS -sV -O
}

action_udp_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    msg "${YELLOW}[!] UDP-Scans sind deutlich langsamer als TCP. Top 20 UDP-Ports werden geprüft.${NC}"
    run_scan "udp" -sU -T4 --top-ports 20
}

# =====================================================
# AKTIONEN: TIEFENSCANS
# =====================================================

action_full_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    msg "${YELLOW}[!] Vollständiger Scan (alle 65535 Ports + OS + Vuln-Scripts) kann je nach Ziel SEHR lange dauern (oft 20+ Minuten pro Host).${NC}"
    read -rp "Wirklich fortfahren? (ja/nein): " confirm
    [[ "$confirm" == "ja" ]] || { msg "${YELLOW}Abgebrochen.${NC}"; return 0; }
    run_scan "full" -sS -sV -O -p- --script vuln,vulners -T4
}

action_vuln_scan() {
    require_tools nmap || return 1
    ask_target || return 1
    run_scan "vuln" -sV --script vulners,vuln -T4
}

# =====================================================
# AKTIONEN: EXPORT & REPORTING
# =====================================================

action_html_export() {
    require_tools nmap xsltproc || return 1
    ask_target || return 1
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local base="$RECON_DIR/html_${timestamp}"
    msg "${YELLOW}[*] HTML-Export wird erstellt...${NC}"

    if [ -f "$NMAP_XSL" ]; then
        sudo nmap -sS -sV -O -T4 -oX "${base}.xml" "${TARGET_SPEC[@]}" \
            && xsltproc -o "${base}.html" "$NMAP_XSL" "${base}.xml"
    else
        msg "${YELLOW}[!] Lokales nmap.xsl nicht gefunden, nutze Online-Stylesheet (braucht Internet).${NC}"
        sudo nmap -sS -sV -O -T4 --webxml -oX "${base}.xml" "${TARGET_SPEC[@]}" \
            && xsltproc -o "${base}.html" "${base}.xml"
    fi

    if [ -f "${base}.html" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') | html | $TARGET | ${base}.html" >> "$HISTORY_FILE"
        msg "${GREEN}✅ HTML-Report erstellt: ${base}.html${NC}"
    else
        warn_fail "HTML-Export fehlgeschlagen."
    fi
}

action_show_history() {
    echo -e "${BLUE}=== Scan-Historie (echte Ergebnisdateien) ===${NC}"
    if [ -f "$HISTORY_FILE" ]; then
        tail -n 20 "$HISTORY_FILE" | column -t -s '|'
    else
        echo -e "${RED}Noch keine Scans in der Historie.${NC}"
    fi
}

# Extrahiert Dienst/Versions-Zeilen aus einer .nmap-Datei und lässt
# searchsploit gegen jede eindeutige Version laufen - schließt den Loop
# von "Dienst gefunden" zu "bekannter Exploit vorhanden".
action_searchsploit_correlate() {
    require_tools searchsploit || return 1
    local files=()
    while IFS= read -r f; do files+=("$f"); done < <(find "$ENGAGEMENTS_DIR" -name "*.nmap" 2>/dev/null | sort)
    if [ ${#files[@]} -eq 0 ]; then
        warn_fail "Keine .nmap-Ergebnisdateien gefunden. Erst einen Scan mit -sV durchführen."
        return 1
    fi

    echo -e "${CYAN}Verfügbare Scan-Ergebnisse:${NC}"
    local i=1
    for f in "${files[@]}"; do
        echo "  $i) $f"
        ((i++))
    done
    read -rp "Welche Datei? (Nummer): " sel
    local idx=$((sel - 1))
    { [ "$idx" -ge 0 ] && [ "$idx" -lt ${#files[@]} ]; } || { warn_fail "Ungültige Auswahl."; return 1; }
    local scanfile="${files[$idx]}"

    # Zeilen wie: "80/tcp open  http    Apache httpd 2.4.54 ((Debian))"
    # Spalten 1-3 (Port/State/Service) abschneiden, Rest ist die Versions-Beschreibung.
    local services
    services=$(grep -E '^[0-9]+/(tcp|udp)\s+open' "$scanfile" | awk '{$1="";$2="";$3="";print}' | sed 's/^ *//' | sort -u)

    if [ -z "$services" ]; then
        warn_fail "Keine Dienst-/Versionsinformationen in dieser Datei gefunden (Scan evtl. ohne -sV gemacht?)."
        return 1
    fi

    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local report="$RECON_DIR/searchsploit_${timestamp}.txt"
    msg "${YELLOW}[*] Korreliere gefundene Dienste mit Searchsploit...${NC}"
    {
        echo "Searchsploit-Korrelation für: $scanfile"
        echo "Erstellt: $(date)"
        echo "========================================"
    } > "$report"

    while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        echo -e "${CYAN}--- $svc ---${NC}"
        {
            echo ""
            echo "### $svc"
        } >> "$report"
        searchsploit "$svc" 2>/dev/null | tee -a "$report"
    done <<< "$services"

    msg "${GREEN}✅ Korrelation abgeschlossen. Bericht: $report${NC}"
}

# Vergleicht zwei .gnmap-Dateien (greppable Format) desselben Ziels und zeigt
# neu geöffnete / weggefallene Ports zwischen den beiden Zeitpunkten.
action_scan_diff() {
    local files=()
    while IFS= read -r f; do files+=("$f"); done < <(find "$ENGAGEMENTS_DIR" -name "*.gnmap" 2>/dev/null | sort)
    if [ ${#files[@]} -lt 2 ]; then
        warn_fail "Mindestens zwei .gnmap-Scans nötig (aktuell: ${#files[@]})."
        return 1
    fi

    echo -e "${CYAN}Verfügbare Scans:${NC}"
    local i=1
    for f in "${files[@]}"; do
        echo "  $i) $f"
        ((i++))
    done
    read -rp "Älterer Scan (Nummer): " sel1
    read -rp "Neuerer Scan (Nummer): " sel2
    local idx1=$((sel1 - 1)) idx2=$((sel2 - 1))
    { [ "$idx1" -ge 0 ] && [ "$idx1" -lt ${#files[@]} ] && [ "$idx2" -ge 0 ] && [ "$idx2" -lt ${#files[@]} ]; } \
        || { warn_fail "Ungültige Auswahl."; return 1; }

    local old="${files[$idx1]}" new="${files[$idx2]}"
    local old_ports new_ports
    old_ports=$(grep -oE '[0-9]+/open/[a-z]+//[a-zA-Z0-9_-]*' "$old" | sort -u)
    new_ports=$(grep -oE '[0-9]+/open/[a-z]+//[a-zA-Z0-9_-]*' "$new" | sort -u)

    echo -e "${BLUE}=== Neu geöffnete Ports (in $new, nicht in $old) ===${NC}"
    comm -13 <(echo "$old_ports") <(echo "$new_ports") | { grep . || echo "  (keine)"; }

    echo -e "${BLUE}=== Weggefallene Ports (in $old, nicht mehr in $new) ===${NC}"
    comm -23 <(echo "$old_ports") <(echo "$new_ports") | { grep . || echo "  (keine)"; }
}

# =====================================================
# AKTIONEN: MITM (ARP-Spoofing + Nmap)
# =====================================================

action_arp_mitm() {
    require_tools bettercap nmap || return 1
    echo -e "${RED}Nur im eigenen Netzwerk / mit ausdrücklicher Erlaubnis!${NC}"
    read -rp "Ziel-IP zum Spoofen (z.B. 192.168.0.1): " spoof_target
    valid_target "$spoof_target" || { warn_fail "Ungültige Ziel-IP."; return 1; }

    BETTERCAP_CAPLET=$(mktemp /tmp/arpspoof_XXXXXX.cap)
    cat > "$BETTERCAP_CAPLET" <<EOF
net.probe on
set arp.spoof.targets $spoof_target
arp.spoof on
EOF

    msg "${YELLOW}[*] Starte ARP-Spoofing im Hintergrund gegen $spoof_target...${NC}"
    sudo bettercap -iface "$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')" \
        -caplet "$BETTERCAP_CAPLET" &>/dev/null &
    BETTERCAP_PID=$!
    sleep 2

    if kill -0 "$BETTERCAP_PID" 2>/dev/null; then
        msg "${GREEN}✅ ARP-Spoofing läuft (PID $BETTERCAP_PID). Traffic von $spoof_target wird jetzt umgeleitet.${NC}"
        msg "${CYAN}Du kannst jetzt parallel scannen (z.B. Option 'Normaler Port-Scan' gegen $spoof_target).${NC}"
        msg "${YELLOW}Zum Beenden: Menüpunkt 'ARP-Spoofing stoppen' nutzen.${NC}"
    else
        warn_fail "Bettercap konnte nicht gestartet werden."
        rm -f "$BETTERCAP_CAPLET"
    fi
}

action_arp_mitm_stop() {
    if [ -n "$BETTERCAP_PID" ] && kill -0 "$BETTERCAP_PID" 2>/dev/null; then
        sudo kill "$BETTERCAP_PID" 2>/dev/null
        msg "${GREEN}✅ ARP-Spoofing gestoppt.${NC}"
    else
        msg "${YELLOW}Kein aktiver ARP-Spoofing-Prozess.${NC}"
    fi
    [ -n "$BETTERCAP_CAPLET" ] && rm -f "$BETTERCAP_CAPLET"
    BETTERCAP_PID=""
}

# =====================================================
# EINSTELLUNGEN
# =====================================================

action_change_target() {
    read -rp "Neues Ziel / Subnetz eingeben: " newtarget
    if valid_target "$newtarget"; then
        TARGET="$newtarget"
        TARGET_SPEC=("$TARGET")
        msg "${GREEN}✅ Target aktualisiert auf: $TARGET${NC}"
    else
        warn_fail "Ungültiges Ziel-Format."
    fi
}

action_show_log() {
    tail -n 30 "$LOGFILE" 2>/dev/null || echo "Noch keine Log-Einträge."
}

# =====================================================
# HEADER
# =====================================================
show_header() {
    echo -e "${CYAN}Ziel        : ${YELLOW}${TARGET:-Keines}${NC}"
    echo -e "${CYAN}Ausschluss  : ${YELLOW}${EXCLUDE_HOSTS:-keiner}${NC}"
    echo -e "${CYAN}Projekt     : ${YELLOW}${RECON_DIR:-nicht gesetzt}${NC}"
    echo -e "${CYAN}ARP-Spoof   : ${YELLOW}$([ -n "$BETTERCAP_PID" ] && kill -0 "$BETTERCAP_PID" 2>/dev/null && echo 'aktiv' || echo 'aus')${NC}"
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

        local i=1
        for entry in "${entries[@]}"; do
            echo " $i) ${entry%%|*}"
            ((i++))
        done
        echo " 0) Zurück"
        echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

        read -rp "Wähle eine Option: " choice
        [ "$choice" = "0" ] && return 0

        local idx=$((choice - 1))
        if [ "$idx" -ge 0 ] && [ "$idx" -lt ${#entries[@]} ]; then
            "${entries[$idx]#*|}"
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
        "Log-Datei anzeigen|action_show_log"
}

# =====================================================
# CLEANUP
# =====================================================
cleanup() {
    echo ""
    if [ -n "$BETTERCAP_PID" ] && kill -0 "$BETTERCAP_PID" 2>/dev/null; then
        msg "${YELLOW}[*] Stoppe laufendes ARP-Spoofing...${NC}"
        sudo kill "$BETTERCAP_PID" 2>/dev/null
    fi
    [ -n "$BETTERCAP_CAPLET" ] && rm -f "$BETTERCAP_CAPLET"
    [ -n "${SUDO_KEEPALIVE_PID:-}" ] && kill "$SUDO_KEEPALIVE_PID" 2>/dev/null
    msg "${GREEN}✅ Aufgeräumt. Auf Wiedersehen!${NC}"
}
trap cleanup EXIT INT TERM

# =====================================================
# START
# =====================================================
clear
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    NMAP POWER TOOL                           ║"
echo "║   Discovery • Scanning • Export • MITM • Searchsploit • Diff   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
msg "${YELLOW}Hinweis: Nur in eigener Lab-Umgebung / mit ausdrücklicher Erlaubnis verwenden.${NC}"
echo ""

require_root_actions
rotate_log_if_needed

msg "${CYAN}[*] Fordere sudo-Rechte einmalig an...${NC}"
sudo -v || die "sudo-Authentifizierung fehlgeschlagen."
( while true; do sudo -n true; sleep 60; kill -0 "$$" 2>/dev/null || exit; done ) &>/dev/null &
SUDO_KEEPALIVE_PID=$!

detect_current_network
select_project

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
    echo " 5) Einstellungen (Ziel, Ausschluss, Projekt, Netzwerk, Log)"
    echo " 6) Beenden"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

    read -rp "Wähle eine Option (1-6): " choice

    case $choice in
        1) menu_scanning ;;
        2) menu_deepscans ;;
        3) menu_export ;;
        4) menu_mitm ;;
        5) menu_settings ;;
        6) msg "${GREEN}Auf Wiedersehen!${NC}"; exit 0 ;;
        *) msg "${RED}Ungültige Option!${NC}"; sleep 1 ;;
    esac
done
