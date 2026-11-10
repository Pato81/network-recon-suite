#!/usr/bin/env bash
# =============================================================================
#  WIRESHARK POWER TOOL  –  Capture- und Analyse-Frontend für tshark/dumpcap
# -----------------------------------------------------------------------------
#  Zweck  : Live-Capture (privilegiengetrennt via dumpcap), forensische Analyse
#           gespeicherter Captures, Klartext-Credential-Suche, Objekt-Export,
#           Merge/Filter, Projekt-/Loot-Integration.
#  Autor  : Patrick
#  Lizenz : intern / Lab-Nutzung
#
#  RECHTLICHER HINWEIS
#  Nur in der eigenen Laborumgebung oder mit schriftlicher, dokumentierter
#  Beauftragung (Scope, Zeitfenster, Ansprechpartner) einsetzen. Das Mitlesen
#  fremden Netzverkehrs ist ohne Erlaubnis strafbar (u. a. § 202b StGB).
#
#  SICHERHEITSDESIGN
#   * set -Eeuo pipefail, strikte Quotierung, kein eval, keine Fremddaten in
#     Shell-Kontexten; Filter/Namen werden als einzelne argv-Elemente übergeben
#     und zusätzlich gegen eine Whitelist validiert.
#   * umask 077 – Captures/Reports enthalten potenziell Zugangsdaten.
#   * Keine GUI als root; Capture bevorzugt über dumpcap + Gruppe "wireshark".
#   * Konfiguration wird geparst, niemals gesourct.
#   * Alle schreibenden Pfade liegen unterhalb von $ENGAGEMENTS_DIR (Traversal-
#     Schutz), destruktive Aktionen gibt es nicht; Löschen nur nach Rückfrage.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LC_NUMERIC=C

readonly SCRIPT_NAME="${0##*/}"
readonly SCRIPT_VERSION="2.0.0"
readonly MAIN_PID="$$"

# =============================================================================
#  KONFIGURATION / STATE
# =============================================================================
readonly STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/wireshark-powertool"
readonly CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/wireshark-powertool"
readonly LOGFILE="$STATE_DIR/tool.log"
readonly HISTORY_FILE="$STATE_DIR/captures.history"
readonly CONFIGFILE="$CONF_DIR/config"
readonly LOG_MAX_BYTES=$((5 * 1024 * 1024))
readonly LOG_KEEP=3
readonly ENGAGEMENTS_DIR="${WSPT_ENGAGEMENTS_DIR:-$HOME/engagements}"
readonly MIN_FREE_MB=512            # Warnschwelle freier Plattenplatz vor Capture
readonly CAPTURE_EXT=("pcap" "pcapng" "cap")

IFACE=""
LOOT_DIR=""
ANALYSIS_DIR=""
PROJECT_NAME=""
SELECTED_CAPTURE=""
TMP_ROOT=""
SUDO_KEEPALIVE_PID=""
declare -a PRIV=()                  # ()  = ohne sudo,  (sudo) = mit sudo
ASSUME_YES=0
NO_COLOR=0

# =============================================================================
#  FARBEN (automatisch deaktiviert ohne TTY oder bei NO_COLOR)
# =============================================================================
# Vorbelegung mit leeren Werten, damit fruehe Exit-Pfade (--version sowie die()
# in parse_args) VOR setup_colors unter 'set -u' nicht auf ungebundene Farb-
# variablen laufen. setup_colors() ueberschreibt diese und macht sie readonly.
RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''

setup_colors() {
    if [[ $NO_COLOR -eq 1 || ! -t 1 || -n "${NO_COLOR_ENV:-}" ]]; then
        RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
    else
        RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
        BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
    fi
    readonly RED GREEN YELLOW BLUE CYAN BOLD NC
}
[[ -n "${NO_COLOR:-}" ]] && NO_COLOR_ENV=1

# =============================================================================
#  LOGGING / AUSGABE
# =============================================================================
strip_ansi() { sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g'; }

log() {
    local lvl="$1"; shift
    printf '%s [%-5s] [pid:%d] %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$lvl" "$$" "$*" \
        | strip_ansi 2>/dev/null >>"$LOGFILE" || true
}

msg()  { printf '%b\n' "$*"; log INFO  "$(printf '%b' "$*" | strip_ansi)"; }
info() { msg "${CYAN}[*]${NC} $*"; }
ok()   { msg "${GREEN}[+]${NC} $*"; }
warn() { printf '%b\n' "${YELLOW}[!]${NC} $*" >&2; log WARN "$*"; }
err()  { printf '%b\n' "${RED}[FEHLER]${NC} $*" >&2; log ERROR "$*"; return 1; }
die()  { printf '%b\n' "${RED}[FATAL]${NC} $*" >&2; log FATAL "$*"; exit 1; }

rotate_log() {
    [[ -f "$LOGFILE" ]] || return 0
    local size
    size=$(stat -c%s "$LOGFILE" 2>/dev/null || echo 0)
    (( size > LOG_MAX_BYTES )) || return 0
    local i
    for (( i = LOG_KEEP - 1; i >= 1; i-- )); do
        [[ -f "${LOGFILE}.${i}" ]] && mv -f "${LOGFILE}.${i}" "${LOGFILE}.$((i+1))"
    done
    mv -f "$LOGFILE" "${LOGFILE}.1"
    : >"$LOGFILE"; chmod 600 "$LOGFILE"
}

# =============================================================================
#  FEHLER- UND SIGNALBEHANDLUNG
# =============================================================================
on_error() {
    local rc=$1 line=$2 cmd=$3
    log ERROR "Unerwarteter Fehler (rc=$rc) in Zeile $line: $cmd"
    printf '%b\n' "${RED}[FEHLER]${NC} rc=$rc in Zeile $line: $cmd" >&2
}
trap 'on_error $? ${LINENO} "$BASH_COMMAND"' ERR

cleanup() {
    local rc=$?
    trap - EXIT INT TERM ERR
    if [[ -n "$SUDO_KEEPALIVE_PID" ]] && kill -0 "$SUDO_KEEPALIVE_PID" 2>/dev/null; then
        kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
        wait "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    fi
    if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" && "$TMP_ROOT" == "${TMPDIR:-/tmp}"/wspt.* ]]; then
        rm -rf -- "$TMP_ROOT"
    fi
    log INFO "Beendet (rc=$rc)"
    printf '%b\n' "${GREEN}Auf Wiedersehen.${NC}"
    exit "$rc"
}
on_sigint() { printf '\n'; warn "Abbruch durch Benutzer (SIGINT)."; exit 130; }
trap cleanup EXIT
trap on_sigint INT
trap 'warn "SIGTERM empfangen."; exit 143' TERM

# =============================================================================
#  BASIS-HELFER
# =============================================================================
have() { command -v -- "$1" >/dev/null 2>&1; }

require_tools() {
    local missing=() t
    for t in "$@"; do have "$t" || missing+=("$t"); done
    if (( ${#missing[@]} )); then
        err "Fehlende Programme: ${missing[*]}"
        msg "${YELLOW}Installationshinweis: sudo apt install -y ${missing[*]}${NC}"
        return 1
    fi
    return 0
}

pause() { read -rsp $'\nENTER zum Fortfahren...' _ || true; printf '\n'; }

ask() {   # ask <prompt> <varname> [default]
    local prompt="$1" __var="$2" default="${3:-}" reply
    if (( ASSUME_YES )) && [[ -n "$default" ]]; then
        printf -v "$__var" '%s' "$default"; return 0
    fi
    read -rp "$prompt" reply || return 1
    [[ -z "$reply" && -n "$default" ]] && reply="$default"
    printf -v "$__var" '%s' "$reply"
}

ask_yes_no() {  # ask_yes_no <frage> <default:j|n>
    local q="$1" def="${2:-n}" reply hint="j/N"
    [[ "$def" == "j" ]] && hint="J/n"
    (( ASSUME_YES )) && return 0
    read -rp "$q ($hint): " reply || return 1
    reply="${reply:-$def}"
    [[ "$reply" =~ ^[JjYy]$ ]]
}

ask_int() {   # ask_int <prompt> <varname> <min> <max> [default]
    local prompt="$1" __var="$2" min="$3" max="$4" def="${5:-}" val
    ask "$prompt" val "$def" || return 1
    [[ "$val" =~ ^[0-9]+$ ]] || { err "Keine gültige Zahl: '${val}'"; return 1; }
    (( val >= min && val <= max )) || { err "Wert außerhalb [$min..$max]: $val"; return 1; }
    printf -v "$__var" '%s' "$val"
}

# Whitelist-Validierung: BPF-Capture-Filter
valid_bpf() { [[ "$1" =~ ^[A-Za-z0-9[:space:].:/()\[\]\<\>\=\!\&\|_,%*-]{1,512}$ ]]; }
# Whitelist-Validierung: Wireshark-Displayfilter (zusätzlich Quotes/Backslash)
valid_dfilter() { [[ "$1" =~ ^[A-Za-z0-9[:space:].:/()\[\]\<\>\=\!\&\|_,\"\'\^\$\~\\%*+-]{1,512}$ ]]; }
# Projekt-/Dateinamens-Segmente
sanitize_name() {
    local n="${1//[^A-Za-z0-9._-]/_}"
    n="${n##.}"; n="${n:0:64}"
    printf '%s' "${n:-unbenannt}"
}

timestamp() { date +%Y%m%d_%H%M%S; }

# Pfad muss unterhalb von ENGAGEMENTS_DIR liegen (Traversal-Schutz)
assert_inside_engagements() {
    local p base
    p="$(realpath -m -- "$1")"
    base="$(realpath -m -- "$ENGAGEMENTS_DIR")"
    [[ "$p" == "$base" || "$p" == "$base"/* ]] \
        || die "Pfad außerhalb des Engagement-Verzeichnisses: $1"
}

check_disk_space() {
    local target="$1" free_mb
    free_mb=$(df -Pm -- "$target" 2>/dev/null | awk 'NR==2 {print $4}') || return 0
    [[ "$free_mb" =~ ^[0-9]+$ ]] || return 0
    if (( free_mb < MIN_FREE_MB )); then
        warn "Nur ${free_mb} MB frei unter ${target}. Capture kann das Dateisystem füllen."
        ask_yes_no "Trotzdem fortfahren?" n || return 1
    fi
    return 0
}

notify() { have notify-send && notify-send -a "$SCRIPT_NAME" "Wireshark Power Tool" "$1" 2>/dev/null || true; }

# Führt ein (potenziell langlaufendes) Kommando aus; Strg+C beendet nur das
# Kommando, nicht das Skript.
run_interruptible() {
    local rc=0
    trap 'rc=130' INT
    "$@" || rc=$?
    trap on_sigint INT
    (( rc == 130 )) && info "Vorgang durch Benutzer beendet."
    return 0
}

# Besitzrechte nach privilegiertem Schreibvorgang zurückgeben
reown() {
    local p
    for p in "$@"; do
        [[ -e "$p" ]] || continue
        if (( ${#PRIV[@]} )); then
            "${PRIV[@]}" chown -- "$(id -u):$(id -g)" "$p" 2>/dev/null || true
        fi
        chmod 600 "$p" 2>/dev/null || true
    done
}

history_add() {   # history_add <aktion> <iface> <pfad> [extra]
    printf '%s | %s | %s | %s | %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "${2:--}" "$3" "${4:--}" >>"$HISTORY_FILE"
    chmod 600 "$HISTORY_FILE" 2>/dev/null || true
}

# =============================================================================
#  KONFIGURATION (key=value, wird geparst – NIEMALS gesourct)
# =============================================================================
config_get() {
    local key="$1" line
    [[ -f "$CONFIGFILE" ]] || return 1
    while IFS= read -r line; do
        [[ "$line" == "$key="* ]] || continue
        printf '%s' "${line#*=}"; return 0
    done <"$CONFIGFILE"
    return 1
}

config_set() {
    local key="$1" val="$2" tmp
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    val="${val//$'\n'/}"
    tmp="$(mktemp "${CONFIGFILE}.XXXXXX")"
    if [[ -f "$CONFIGFILE" ]]; then
        grep -v -- "^${key}=" "$CONFIGFILE" >"$tmp" 2>/dev/null || true
    fi
    printf '%s=%s\n' "$key" "$val" >>"$tmp"
    chmod 600 "$tmp"; mv -f "$tmp" "$CONFIGFILE"
}

# =============================================================================
#  PRIVILEGIEN
# =============================================================================
# dumpcap ist das privilegiengetrennte Capture-Backend von Wireshark.
# Ideal: Mitgliedschaft in der Gruppe "wireshark" + CAP_NET_RAW auf dumpcap
#        (dpkg-reconfigure wireshark-common) -> dann wird KEIN sudo benötigt.
determine_privileges() {
    if dumpcap -D >/dev/null 2>&1; then
        PRIV=()
        ok "Capture ohne sudo möglich (dumpcap besitzt die nötigen Capabilities)."
        return 0
    fi
    warn "dumpcap darf nicht unprivilegiert capturen – es wird sudo verwendet."
    msg  "${CYAN}Empfohlene dauerhafte Lösung (einmalig, reversibel):${NC}"
    msg  "  sudo dpkg-reconfigure wireshark-common   # 'Ja' wählen"
    msg  "  sudo usermod -aG wireshark \"\$USER\"      # danach neu anmelden"
    require_tools sudo || die "Weder Capabilities noch sudo verfügbar."
    PRIV=(sudo)
    info "Fordere sudo-Rechte einmalig an..."
    sudo -v || die "sudo-Authentifizierung fehlgeschlagen."
    (
        while kill -0 "$MAIN_PID" 2>/dev/null; do
            sudo -n true 2>/dev/null || exit 0
            sleep 50
        done
    ) >/dev/null 2>&1 &
    SUDO_KEEPALIVE_PID=$!
    log INFO "sudo-Keepalive gestartet (pid=$SUDO_KEEPALIVE_PID)"
}

refuse_root() {
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        die "Bitte NICHT als root starten – Privilegien werden gezielt pro Aktion angefordert."
    fi
}

# =============================================================================
#  INTERFACE-AUSWAHL
# =============================================================================
list_interfaces() {   # gibt reine Interface-Namen aus (eine Zeile je Interface)
    local lister=(dumpcap -D)
    have dumpcap || lister=(tshark -D)
    "${PRIV[@]}" "${lister[@]}" 2>/dev/null \
        | sed -E 's/^[0-9]+\.[[:space:]]*//; s/[[:space:]]+\(.*\)[[:space:]]*$//' \
        | sed -E 's/[[:space:]]+$//' | grep -v '^$' || true
}

interface_exists() {
    local want="$1" i
    while IFS= read -r i; do [[ "$i" == "$want" ]] && return 0; done < <(list_interfaces)
    return 1
}

select_interface() {
    require_tools tshark || return 1
    local saved
    if saved="$(config_get iface 2>/dev/null)" && [[ -n "$saved" ]] && interface_exists "$saved"; then
        if ask_yes_no "Zuletzt genutztes Interface '$saved' wieder verwenden?" j; then
            IFACE="$saved"; ok "Interface: $IFACE"; return 0
        fi
    fi

    local ifaces=()
    mapfile -t ifaces < <(list_interfaces)
    (( ${#ifaces[@]} )) || { err "Keine Capture-Interfaces gefunden (Rechte? dumpcap installiert?)"; return 1; }

    msg "${CYAN}Verfügbare Capture-Interfaces:${NC}"
    local i
    for i in "${!ifaces[@]}"; do printf '  %2d) %s\n' "$((i+1))" "${ifaces[$i]}"; done

    local sel
    ask_int "Interface-Nummer: " sel 1 "${#ifaces[@]}" || return 1
    IFACE="${ifaces[$((sel-1))]}"
    config_set iface "$IFACE"
    ok "Interface gesetzt: $IFACE (gespeichert)"
}

action_reselect_interface() { config_set iface ""; select_interface; }

# =============================================================================
#  PROJEKT-/LOOT-INTEGRATION
# =============================================================================
set_project_paths() {
    local name="$1"
    PROJECT_NAME="$name"
    LOOT_DIR="$ENGAGEMENTS_DIR/$name/loot"
    ANALYSIS_DIR="$LOOT_DIR/analyse"
    assert_inside_engagements "$LOOT_DIR"
    mkdir -p -m 700 "$ENGAGEMENTS_DIR/$name"/{recon,exploit,loot,report} "$ANALYSIS_DIR"
    config_set project "$name"
    ok "Projekt: $name  |  Loot: $LOOT_DIR"
}

select_project() {
    mkdir -p -m 700 "$ENGAGEMENTS_DIR"

    local saved
    if saved="$(config_get project 2>/dev/null)" && [[ -n "$saved" && -d "$ENGAGEMENTS_DIR/$saved" ]]; then
        if ask_yes_no "Letztes Projekt '$saved' weiterverwenden?" j; then
            set_project_paths "$saved"; return 0
        fi
    fi

    local names=() d
    while IFS= read -r -d '' d; do names+=("$(basename -- "$d")"); done \
        < <(find "$ENGAGEMENTS_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z)

    msg "${CYAN}Vorhandene Projekte:${NC}"
    local i
    if (( ${#names[@]} )); then
        for i in "${!names[@]}"; do printf '  %2d) %s\n' "$((i+1))" "${names[$i]}"; done
    else
        msg "  (noch keine)"
    fi
    msg "   n) Neues Projekt anlegen"

    local sel
    ask "Projekt wählen (Nummer oder 'n'): " sel "n" || return 1
    if [[ "$sel" =~ ^[Nn]$ ]]; then
        local raw
        ask "Name des neuen Projekts: " raw "projekt_$(date +%Y%m%d)" || return 1
        set_project_paths "$(sanitize_name "$raw")"
    elif [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#names[@]} )); then
        set_project_paths "${names[$((sel-1))]}"
    else
        warn "Ungültige Auswahl – nutze Projekt 'default'."
        set_project_paths "default"
    fi
}

action_switch_project() { select_project; }

# =============================================================================
#  CAPTURE-DATEI-AUSWAHL (null-sicher, auch bei Leerzeichen im Pfad)
# =============================================================================
find_captures() {   # NUL-separierte Liste aller Captures im Engagement-Baum
    local args=() ext first=1
    for ext in "${CAPTURE_EXT[@]}"; do
        (( first )) && { args+=(-name "*.${ext}"); first=0; } || args+=(-o -name "*.${ext}")
    done
    find "$ENGAGEMENTS_DIR" -type f \( "${args[@]}" \) -print0 2>/dev/null | sort -z
}

choose_capture_file() {
    local files=() f
    while IFS= read -r -d '' f; do files+=("$f"); done < <(find_captures)
    (( ${#files[@]} )) || { err "Keine Capture-Dateien unter $ENGAGEMENTS_DIR gefunden."; return 1; }

    msg "${CYAN}Verfügbare Capture-Dateien:${NC}"
    local i size
    for i in "${!files[@]}"; do
        size=$(du -h -- "${files[$i]}" 2>/dev/null | cut -f1 || echo '?')
        printf '  %2d) %-10s %s\n' "$((i+1))" "[$size]" "${files[$i]#$ENGAGEMENTS_DIR/}"
    done

    local sel
    ask_int "Datei-Nummer: " sel 1 "${#files[@]}" || return 1
    SELECTED_CAPTURE="${files[$((sel-1))]}"
    [[ -r "$SELECTED_CAPTURE" ]] || { err "Datei nicht lesbar: $SELECTED_CAPTURE"; return 1; }
    log INFO "Capture gewählt: $SELECTED_CAPTURE"
    return 0
}

choose_multiple_captures() {   # Ergebnis in globalem Array MULTI_SELECTION
    MULTI_SELECTION=()
    local files=() f
    while IFS= read -r -d '' f; do files+=("$f"); done < <(find_captures)
    (( ${#files[@]} >= 2 )) || { err "Mindestens zwei Capture-Dateien nötig."; return 1; }

    msg "${CYAN}Dateien zum Zusammenführen (kommagetrennte Nummern, z. B. 1,3,4):${NC}"
    local i
    for i in "${!files[@]}"; do printf '  %2d) %s\n' "$((i+1))" "${files[$i]#$ENGAGEMENTS_DIR/}"; done

    local raw idx
    ask "Nummern: " raw || return 1
    local parts=()
    IFS=',' read -ra parts <<<"$raw"
    for idx in "${parts[@]}"; do
        idx="${idx//[[:space:]]/}"
        [[ "$idx" =~ ^[0-9]+$ ]] || continue
        (( idx >= 1 && idx <= ${#files[@]} )) && MULTI_SELECTION+=("${files[$((idx-1))]}")
    done
    (( ${#MULTI_SELECTION[@]} >= 2 )) || { err "Mindestens zwei gültige Dateien auswählen."; return 1; }
    return 0
}

# =============================================================================
#  LIVE CAPTURE  (Backend: dumpcap – privilegiengetrennt, ressourcenschonend)
# =============================================================================
ensure_capture_ready() {
    require_tools dumpcap || return 1
    [[ -n "$IFACE" ]] || select_interface || return 1
    [[ -n "$LOOT_DIR" ]] || select_project
    check_disk_space "$LOOT_DIR" || return 1
    return 0
}

# run_capture <label> <bpf|""> [extra dumpcap-args...]
run_capture() {
    local label="$1" bpf="$2"; shift 2
    local extra=("$@")
    ensure_capture_ready || return 1

    if [[ -n "$bpf" ]] && ! valid_bpf "$bpf"; then
        err "Capture-Filter enthält unzulässige Zeichen – abgebrochen."
        return 1
    fi

    local outfile="$LOOT_DIR/$(sanitize_name "$label")_$(timestamp).pcapng"
    local cmd=("${PRIV[@]}" dumpcap -i "$IFACE" -w "$outfile" -q)
    [[ -n "$bpf" ]] && cmd+=(-f "$bpf")
    (( ${#extra[@]} )) && cmd+=("${extra[@]}")

    msg "${YELLOW}[*] Capture auf '${IFACE}'${bpf:+ (Filter: $bpf)} → ${outfile}${NC}"
    msg "${CYAN}    Beenden mit Strg+C.${NC}"
    log INFO "Capture-Kommando: ${cmd[*]}"
    sleep 1

    run_interruptible "${cmd[@]}"

    if [[ -s "$outfile" ]]; then
        reown "$outfile"
        local size; size=$(du -h -- "$outfile" | cut -f1)
        history_add "$label" "$IFACE" "$outfile" "$size"
        ok "Capture gespeichert: $outfile ($size)"
        notify "Capture '$label' beendet ($size)"
        if ask_yes_no "Jetzt in der Wireshark-GUI öffnen?" n; then
            open_in_gui "$outfile"
        fi
    else
        rm -f -- "$outfile"
        err "Keine Daten aufgezeichnet (Abbruch, falsches Interface oder zu enger Filter)."
    fi
}

action_capture_all()         { run_capture "all" ""; }
action_capture_web()         { run_capture "web" "tcp port 80 or tcp port 443"; }
action_capture_dns()         { run_capture "dns" "port 53 or port 5353 or port 853"; }
action_capture_arp()         { run_capture "arp" "arp"; }

action_capture_unencrypted() {
    info "Klassische Klartext-Protokolle: FTP(21) Telnet(23) HTTP(80) POP3(110) IMAP(143) SMTP(25) SNMP(161)"
    run_capture "cleartext" "tcp port 21 or tcp port 23 or tcp port 80 or tcp port 110 or tcp port 143 or tcp port 25 or udp port 161"
}

action_capture_custom_filter() {
    local filt
    msg "${CYAN}BPF-Syntax (Capture-Filter), z. B.: host 192.0.2.10 and tcp port 445${NC}"
    ask "BPF-Filter: " filt || return 1
    [[ -n "$filt" ]] || { err "Kein Filter angegeben."; return 1; }
    run_capture "custom" "$filt"
}

action_capture_timed() {
    local secs pkts filt=""
    ask_int "Dauer in Sekunden (1-86400): " secs 1 86400 "60" || return 1
    ask_int "Max. Paketanzahl (0 = unbegrenzt): " pkts 0 100000000 "0" || return 1
    ask "Optionaler BPF-Filter (leer = alles): " filt "" || return 1
    local extra=(-a "duration:$secs")
    (( pkts > 0 )) && extra+=(-c "$pkts")
    run_capture "timed${secs}s" "$filt" "${extra[@]}"
}

# Ringpuffer: rotiert nach Größe, hält nur N Segmente – für Langzeit-Monitoring
# ohne das Dateisystem zu füllen.
action_capture_ringbuffer() {
    ensure_capture_ready || return 1
    local size_mb keep
    ask_int "Segmentgröße in MB (1-1024): " size_mb 1 1024 "50" || return 1
    ask_int "Anzahl Segmente im Ring (2-200): " keep 2 200 "10" || return 1

    local prefix="$LOOT_DIR/ring_$(timestamp)"
    msg "${YELLOW}[*] Ringpuffer auf '${IFACE}': ${size_mb} MB × ${keep} Segmente (max. $((size_mb*keep)) MB)${NC}"
    msg "${CYAN}    Beenden mit Strg+C.${NC}"
    sleep 1

    run_interruptible "${PRIV[@]}" dumpcap -i "$IFACE" -q \
        -b "filesize:$((size_mb * 1024))" -b "files:$keep" -w "${prefix}.pcapng"

    local segs=() f
    while IFS= read -r -d '' f; do segs+=("$f"); done \
        < <(find "$LOOT_DIR" -maxdepth 1 -type f -name "$(basename -- "$prefix")*" -print0 2>/dev/null)

    if (( ${#segs[@]} )); then
        reown "${segs[@]}"
        history_add "ringbuffer" "$IFACE" "${prefix}*.pcapng" "${#segs[@]} Segmente"
        ok "Ringpuffer beendet: ${#segs[@]} Segment(e) unter ${prefix}*"
    else
        err "Keine Daten aufgezeichnet."
    fi
}

# Bluetooth nutzt eigene Capture-Quellen (bluetooth-monitor, bluetooth0, ubertooth)
action_capture_bluetooth() {
    require_tools dumpcap || return 1
    local cands=() i
    mapfile -t cands < <(list_interfaces | grep -iE 'bluetooth|ubertooth' || true)
    (( ${#cands[@]} )) || { err "Kein Bluetooth-Capture-Interface gefunden (BlueZ/Ubertooth aktiv?)"; return 1; }

    msg "${CYAN}Bluetooth-fähige Interfaces:${NC}"
    for i in "${!cands[@]}"; do printf '  %2d) %s\n' "$((i+1))" "${cands[$i]}"; done
    local sel
    ask_int "Nummer: " sel 1 "${#cands[@]}" || return 1

    local bt="${cands[$((sel-1))]}" outfile="$LOOT_DIR/bluetooth_$(timestamp).pcapng"
    check_disk_space "$LOOT_DIR" || return 1
    msg "${YELLOW}[*] Bluetooth-Capture auf '${bt}' → ${outfile} (Strg+C beendet)${NC}"
    sleep 1
    run_interruptible "${PRIV[@]}" dumpcap -i "$bt" -w "$outfile" -q

    if [[ -s "$outfile" ]]; then
        reown "$outfile"
        history_add "bluetooth" "$bt" "$outfile"
        ok "Bluetooth-Capture gespeichert: $outfile"
    else
        rm -f -- "$outfile"; err "Keine Daten aufgezeichnet."
    fi
}

# GUI bewusst OHNE sudo (Wireshark als root ist ein etabliertes Risiko:
# riesige Dissector-Angriffsfläche). Capture-Rechte kommen von dumpcap.
action_launch_gui_live() {
    require_tools wireshark || return 1
    [[ -n "$IFACE" ]] || select_interface || return 1
    if (( ${#PRIV[@]} )); then
        warn "Live-GUI benötigt Capture-Rechte für den Benutzer (Gruppe 'wireshark')."
        warn "Wireshark wird NICHT mit sudo gestartet. Siehe Hinweis beim Programmstart."
    fi
    info "Starte Wireshark-GUI live auf $IFACE..."
    setsid wireshark -i "$IFACE" -k >/dev/null 2>&1 < /dev/null &
    disown || true
    ok "Wireshark-GUI gestartet."
}

# =============================================================================
#  ANALYSE GESPEICHERTER CAPTURES (ausschließlich lesend)
# =============================================================================
open_in_gui() {
    require_tools wireshark || return 1
    setsid wireshark -r "$1" >/dev/null 2>&1 < /dev/null &
    disown || true
    ok "In Wireshark-GUI geöffnet: $1"
}

action_open_in_gui() { choose_capture_file || return 1; open_in_gui "$SELECTED_CAPTURE"; }

new_report() {   # new_report <praefix> -> Pfad auf stdout
    [[ -n "$ANALYSIS_DIR" ]] || select_project
    mkdir -p -m 700 "$ANALYSIS_DIR"
    local p="$ANALYSIS_DIR/$(sanitize_name "$1")_$(timestamp).txt"
    : >"$p"; chmod 600 "$p"; printf '%s' "$p"
}

action_protocol_stats() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    msg "${BLUE}=== Protokoll-Hierarchie ===${NC}"
    tshark -r "$SELECTED_CAPTURE" -q -z io,phs 2>/dev/null || err "Analyse fehlgeschlagen."
}

action_conversations() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    local report; report="$(new_report conversations)"
    {
        printf '=== TCP-Conversations ===\n'
        tshark -r "$SELECTED_CAPTURE" -q -z conv,tcp 2>/dev/null || true
        printf '\n=== UDP-Conversations ===\n'
        tshark -r "$SELECTED_CAPTURE" -q -z conv,udp 2>/dev/null || true
        printf '\n=== IP-Endpoints ===\n'
        tshark -r "$SELECTED_CAPTURE" -q -z endpoints,ip 2>/dev/null || true
    } | tee "$report"
    ok "Bericht gespeichert: $report"
}

action_follow_stream() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    local proto idx
    ask "Protokoll (tcp/udp/http) [tcp]: " proto "tcp" || return 1
    [[ "$proto" =~ ^(tcp|udp|http)$ ]] || { err "Nur tcp, udp oder http."; return 1; }
    ask_int "Stream-Index: " idx 0 1000000 "0" || return 1
    msg "${BLUE}=== Stream $idx ($proto, ASCII) ===${NC}"
    tshark -r "$SELECTED_CAPTURE" -q -z "follow,${proto},ascii,${idx}" 2>/dev/null \
        || err "Stream nicht vorhanden oder Analyse fehlgeschlagen."
}

# Credential-Suche in unverschlüsselten Protokollen. Rein lesend.
# Ergebnisdatei ist hochsensibel -> 0600, Ablage im Loot-/Analyse-Ordner.
action_find_cleartext_creds() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    local report; report="$(new_report creds)"
    msg "${YELLOW}[*] Suche Klartext-Zugangsdaten in: $SELECTED_CAPTURE${NC}"
    {
        printf 'Klartext-Credential-Analyse\nQuelle : %s\nErstellt: %s\n' \
               "$SELECTED_CAPTURE" "$(date -Is)"
        printf '%s\n' "==============================================================="

        printf '\n### HTTP Basic/Bearer Authorization ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'http.authorization' -T fields \
            -e frame.number -e ip.src -e ip.dst -e http.host -e http.authorization 2>/dev/null || true

        printf '\n### FTP USER/PASS ###\n'
        tshark -r "$SELECTED_CAPTURE" \
            -Y 'ftp.request.command in {"USER","PASS"}' -T fields \
            -e frame.number -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg 2>/dev/null || true

        printf '\n### POP3 / IMAP Anmeldungen ###\n'
        tshark -r "$SELECTED_CAPTURE" \
            -Y 'pop.request.command in {"USER","PASS"} or imap.request' -T fields \
            -e frame.number -e ip.src -e ip.dst -e pop.request.parameter -e imap.request 2>/dev/null || true

        printf '\n### SMTP AUTH (Base64-kodiert, nicht verschlüsselt) ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'smtp.auth.username or smtp.req.parameter' -T fields \
            -e frame.number -e ip.src -e ip.dst -e smtp.req.parameter 2>/dev/null || true

        printf '\n### HTTP POST mit Formularfeldern (user/pass/pwd/login/token) ###\n'
        tshark -r "$SELECTED_CAPTURE" \
            -Y 'http.request.method == "POST" and (urlencoded-form.key contains "pass" or urlencoded-form.key contains "pwd" or urlencoded-form.key contains "user" or urlencoded-form.key contains "login" or urlencoded-form.key contains "token")' \
            -T fields -e frame.number -e ip.src -e http.host -e http.request.uri \
            -e urlencoded-form.key -e urlencoded-form.value 2>/dev/null || true

        printf '\n### SNMP Community Strings ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'snmp.community' -T fields \
            -e frame.number -e ip.src -e ip.dst -e snmp.community 2>/dev/null || true

        printf '\n### Telnet-Sitzungsdaten (Hinweis auf Logins) ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'telnet' -T fields \
            -e frame.number -e ip.src -e ip.dst -e telnet.data 2>/dev/null | head -n 200 || true

        printf '\n### LDAP Simple Bind (Klartext-Passwort) ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'ldap.authentication == 0 and ldap.simple' -T fields \
            -e frame.number -e ip.src -e ip.dst -e ldap.name -e ldap.simple 2>/dev/null || true
    } | tee "$report"
    chmod 600 "$report"
    ok "Bericht gespeichert (0600): $report"
    warn "Der Bericht enthält Zugangsdaten – vertraulich behandeln und nach Projektende löschen."
}

action_export_http_objects() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    [[ -n "$ANALYSIS_DIR" ]] || select_project
    local proto outdir
    ask "Objekt-Typ (http/smb/tftp/imf/dicom) [http]: " proto "http" || return 1
    [[ "$proto" =~ ^(http|smb|tftp|imf|dicom|ftp-data)$ ]] || { err "Nicht unterstützter Typ."; return 1; }

    outdir="$ANALYSIS_DIR/${proto}_objects_$(timestamp)"
    mkdir -p -m 700 "$outdir"
    msg "${YELLOW}[*] Extrahiere ${proto}-Objekte...${NC}"
    tshark -r "$SELECTED_CAPTURE" --export-objects "${proto},${outdir}" -q >/dev/null 2>&1 || true

    local count
    count=$(find "$outdir" -type f | wc -l)
    if (( count > 0 )); then
        ok "$count Datei(en) extrahiert nach: $outdir"
        warn "Extrahierte Dateien sind nicht vertrauenswürdig – nicht ausführen, ggf. in Sandbox/VM prüfen."
        have file && find "$outdir" -type f -exec file -- {} + | head -n 20
    else
        rmdir -- "$outdir" 2>/dev/null || true
        warn "Keine ${proto}-Objekte in dieser Capture gefunden."
    fi
}

action_wlan_ssids() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    local report; report="$(new_report wlan)"
    {
        printf 'WLAN-Übersicht für: %s\n%s\n' "$SELECTED_CAPTURE" "========================================"
        printf '\n### SSIDs (Beacon / Probe Response) mit BSSID und Kanal ###\n'
        tshark -r "$SELECTED_CAPTURE" \
            -Y 'wlan.fc.type_subtype == 0x08 or wlan.fc.type_subtype == 0x05' \
            -T fields -e wlan.bssid -e wlan.ssid -e wlan.ds.current_channel 2>/dev/null \
            | sort -u | grep -v '^[[:space:]]*$' || true
        printf '\n### Probe Requests (von Clients gesuchte Netze) ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'wlan.fc.type_subtype == 0x04' \
            -T fields -e wlan.sa -e wlan.ssid 2>/dev/null | sort -u | grep -v '^[[:space:]]*$' || true
        printf '\n### Beteiligte MAC-Adressen ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'wlan' -T fields -e wlan.sa -e wlan.da 2>/dev/null \
            | tr '\t' '\n' | sort -u | grep -v '^[[:space:]]*$' || true
        printf '\n### EAPOL-Frames (4-Way-Handshake-Indikator) ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'eapol' -T fields \
            -e frame.number -e wlan.sa -e wlan.da -e eapol.type 2>/dev/null || true
    } | tee "$report"
    ok "Bericht gespeichert: $report"
}

# WPA/WPA2-Entschlüsselung einer vorhandenen Capture mit BEKANNTER Passphrase.
# Die Passphrase wird NICHT als Kommandozeilenargument übergeben (sonst in `ps`
# für alle lokalen Benutzer sichtbar), sondern über ein temporäres Wireshark-
# Profil mit Modus 0600 in einem privaten TMPDIR.
action_wlan_decrypt() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    local ssid pass
    ask "SSID des Netzwerks: " ssid || return 1
    [[ -n "$ssid" ]] || { err "SSID erforderlich."; return 1; }
    read -rsp "WPA/WPA2-Passphrase (wird nicht angezeigt): " pass || return 1
    printf '\n'
    [[ -n "$pass" ]] || { err "Passphrase erforderlich."; return 1; }

    local profile="$TMP_ROOT/wsprofile"
    mkdir -p -m 700 "$profile/.config/wireshark"
    {
        printf '"wpa-pwd","%s:%s"\n' "${pass//\"/\"\"}" "${ssid//\"/\"\"}"
    } >"$profile/.config/wireshark/80211_keys"
    chmod 600 "$profile/.config/wireshark/80211_keys"
    unset pass

    local outfile="$LOOT_DIR/decrypted_$(timestamp).pcapng"
    HOME="$profile" tshark -r "$SELECTED_CAPTURE" \
        -o wlan.enable_decryption:TRUE \
        -w "$outfile" 2>/dev/null || true
    rm -rf -- "$profile"

    if [[ -s "$outfile" ]]; then
        chmod 600 "$outfile"
        history_add "wlan-decrypt" "-" "$outfile"
        ok "Entschlüsselte Capture gespeichert: $outfile"
        info "Prüfe mit der Protokoll-Statistik, ob tatsächlich Klartext-Pakete enthalten sind."
    else
        rm -f -- "$outfile"
        err "Entschlüsselung fehlgeschlagen (falsche Passphrase oder unvollständiger 4-Way-Handshake)."
    fi
}

# TLS: SNI ist immer sichtbar (ClientHello unverschlüsselt, sofern kein ECH).
# Zertifikatsdetails nur bei TLS <= 1.2 im Klartext – bei TLS 1.3 erwartungs-
# gemäß leer, da die Certificate-Message verschlüsselt ist.
action_tls_info() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    local report; report="$(new_report tls)"
    {
        printf 'TLS-Analyse für: %s\nErstellt: %s\n%s\n' \
               "$SELECTED_CAPTURE" "$(date -Is)" "========================================"
        printf '\n### Angefragte Hostnamen (SNI, ClientHello) ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'tls.handshake.type == 1' -T fields \
            -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null | sort -u || true
        printf '\n### Ausgehandelte TLS-Versionen / Cipher Suites (ServerHello) ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'tls.handshake.type == 2' -T fields \
            -e ip.src -e tls.handshake.version -e tls.handshake.ciphersuite 2>/dev/null | sort -u || true
        printf '\n### Zertifikatsdetails (nur TLS <= 1.2 im Klartext) ###\n'
        tshark -r "$SELECTED_CAPTURE" -Y 'tls.handshake.type == 11' -T fields \
            -e ip.src -e x509sat.printableString -e x509af.utcTime 2>/dev/null | sort -u || true
        printf '\n### Veraltete/unsichere Protokollversionen (SSLv3/TLS1.0/1.1) ###\n'
        tshark -r "$SELECTED_CAPTURE" \
            -Y 'tls.record.version <= 0x0302 and tls.handshake.type == 2' -T fields \
            -e ip.src -e ip.dst -e tls.record.version 2>/dev/null | sort -u || true
    } | tee "$report"
    ok "Bericht gespeichert: $report"
    info "Leere Zertifikatsabschnitte sind bei TLS 1.3 normal."
}

action_csv_export() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    [[ -n "$ANALYSIS_DIR" ]] || select_project
    local outfile="$ANALYSIS_DIR/export_$(timestamp).csv"
    : >"$outfile"; chmod 600 "$outfile"
    tshark -r "$SELECTED_CAPTURE" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f \
        -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
        -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport -e frame.len -e _ws.col.Info \
        >>"$outfile" 2>/dev/null || true
    if [[ -s "$outfile" ]] && (( $(wc -l <"$outfile") > 1 )); then
        ok "CSV-Export gespeichert: $outfile ($(( $(wc -l <"$outfile") - 1 )) Zeilen)"
    else
        rm -f -- "$outfile"; err "CSV-Export lieferte keine Daten."
    fi
}

# ARP-Spoofing-Heuristik: eine IP, die im Capture-Verlauf von mehreren MAC-
# Adressen beansprucht wird. Zuverlässiger als der Expert-Info-Filter.
# Hinweis: Legitime Ursachen möglich (HA/VRRP, DHCP-Lease-Wechsel, Dual-NIC).
action_arp_spoof_check() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    msg "${YELLOW}[*] Prüfe ARP-Replies auf mehrfach zugeordnete IP-Adressen...${NC}"

    local mappings
    mappings=$(tshark -r "$SELECTED_CAPTURE" -Y 'arp.opcode == 2' \
        -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac 2>/dev/null | sort -u || true)

    if [[ -z "$mappings" ]]; then
        warn "Keine ARP-Reply-Pakete in dieser Capture gefunden."
        return 0
    fi

    local result
    result=$(printf '%s\n' "$mappings" | awk -F'\t' '
        NF >= 2 && $1 != "" && $2 != "" {
            if (!((($1 SUBSEP $2)) in seen)) {
                seen[$1 SUBSEP $2] = 1
                macs[$1] = (macs[$1] == "" ? $2 : macs[$1] ", " $2)
                cnt[$1]++
            }
        }
        END { for (ip in cnt) if (cnt[ip] > 1) printf "%s -> %s\n", ip, macs[ip] }' | sort)

    if [[ -z "$result" ]]; then
        ok "Keine Mehrfachzuordnungen gefunden – kein Hinweis auf ARP-Spoofing."
    else
        msg "${RED}⚠ Verdächtige IP-Adressen mit mehreren MAC-Zuordnungen:${NC}"
        printf '%s\n' "$result" | sed 's/^/    /'
        warn "Mögliche legitime Ursachen prüfen: VRRP/HSRP, Failover-Cluster, DHCP-Wechsel."
        local report; report="$(new_report arp_spoof)"
        { printf 'ARP-Anomalien in %s\n\n%s\n' "$SELECTED_CAPTURE" "$result"; } >"$report"
        ok "Bericht gespeichert: $report"
    fi
}

action_io_stats() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    msg "${BLUE}=== Durchsatz (10-Sekunden-Intervalle) ===${NC}"
    tshark -r "$SELECTED_CAPTURE" -q -z io,stat,10 2>/dev/null || err "Analyse fehlgeschlagen."
    msg "${BLUE}=== Expert Info (Fehler/Warnungen) ===${NC}"
    tshark -r "$SELECTED_CAPTURE" -q -z expert 2>/dev/null | head -n 40 || true
}

# =============================================================================
#  DATEIVERWALTUNG
# =============================================================================
action_merge_captures() {
    require_tools mergecap || return 1
    [[ -n "$LOOT_DIR" ]] || select_project
    local MULTI_SELECTION=()
    choose_multiple_captures || return 1

    local outfile="$LOOT_DIR/merged_$(timestamp).pcapng"
    if mergecap -w "$outfile" -- "${MULTI_SELECTION[@]}"; then
        chmod 600 "$outfile"
        history_add "merge" "-" "$outfile" "${#MULTI_SELECTION[@]} Quellen"
        ok "Zusammengeführt (${#MULTI_SELECTION[@]} Dateien): $outfile"
    else
        rm -f -- "$outfile"; err "Merge fehlgeschlagen."
    fi
}

action_filter_and_save() {
    require_tools tshark || return 1
    choose_capture_file || return 1
    [[ -n "$LOOT_DIR" ]] || select_project
    local df
    msg "${CYAN}Displayfilter-Syntax, z. B.: ip.addr == 192.0.2.10 && tcp.port == 443${NC}"
    ask "Anzeigefilter: " df || return 1
    [[ -n "$df" ]] || { err "Kein Filter angegeben."; return 1; }
    valid_dfilter "$df" || { err "Filter enthält unzulässige Zeichen."; return 1; }

    local outfile="$LOOT_DIR/filtered_$(timestamp).pcapng"
    if tshark -r "$SELECTED_CAPTURE" -Y "$df" -w "$outfile" 2>/dev/null && [[ -s "$outfile" ]]; then
        chmod 600 "$outfile"
        history_add "filter" "-" "$outfile" "$df"
        ok "Gefilterte Capture gespeichert: $outfile"
    else
        rm -f -- "$outfile"
        err "Kein Treffer oder ungültiger Displayfilter."
    fi
}

action_capture_info() {
    require_tools capinfos || return 1
    choose_capture_file || return 1
    msg "${BLUE}=== Capture-Informationen ===${NC}"
    capinfos -- "$SELECTED_CAPTURE" 2>/dev/null || err "capinfos fehlgeschlagen."
    if have sha256sum; then
        msg "${BLUE}=== Integritäts-Hash (Beweissicherung) ===${NC}"
        sha256sum -- "$SELECTED_CAPTURE"
    fi
}

action_hash_all() {
    [[ -n "$LOOT_DIR" ]] || select_project
    require_tools sha256sum || return 1
    local out="$ANALYSIS_DIR/SHA256SUMS_$(timestamp).txt" f count=0
    : >"$out"; chmod 600 "$out"
    while IFS= read -r -d '' f; do
        sha256sum -- "$f" >>"$out"; ((count++))
    done < <(find_captures)
    if (( count )); then
        ok "$count Prüfsumme(n) gespeichert: $out"
    else
        rm -f -- "$out"; warn "Keine Capture-Dateien gefunden."
    fi
}

action_show_history() {
    msg "${BLUE}=== Capture-Historie (letzte 25 Einträge) ===${NC}"
    if [[ -s "$HISTORY_FILE" ]]; then
        if have column; then
            tail -n 25 "$HISTORY_FILE" | column -t -s '|'
        else
            tail -n 25 "$HISTORY_FILE"
        fi
    else
        warn "Noch keine Captures in der Historie."
    fi
}

action_disk_usage() {
    [[ -n "$LOOT_DIR" ]] || select_project
    msg "${BLUE}=== Speicherverbrauch der Engagements ===${NC}"
    du -sh -- "$ENGAGEMENTS_DIR"/*/ 2>/dev/null | sort -h || warn "Keine Projekte vorhanden."
    printf '\n'
    df -h -- "$ENGAGEMENTS_DIR" 2>/dev/null || true
}

# =============================================================================
#  EINSTELLUNGEN / DIAGNOSE
# =============================================================================
action_show_log() {
    msg "${BLUE}=== Logdatei (letzte 40 Zeilen) ===${NC}"
    tail -n 40 "$LOGFILE" 2>/dev/null || warn "Noch keine Log-Einträge."
}

action_selftest() {
    msg "${BLUE}=== Umgebungs-Selbsttest ===${NC}"
    local t
    for t in dumpcap tshark capinfos mergecap editcap wireshark notify-send column sha256sum; do
        if have "$t"; then
            printf '  %b %-12s %s\n' "${GREEN}[OK]${NC}" "$t" "$(command -v "$t")"
        else
            printf '  %b %-12s %s\n' "${YELLOW}[--]${NC}" "$t" "nicht installiert"
        fi
    done
    printf '\n'
    if dumpcap -D >/dev/null 2>&1; then
        ok "Unprivilegiertes Capture möglich (Gruppe/Capabilities korrekt)."
    else
        warn "Unprivilegiertes Capture NICHT möglich – sudo erforderlich."
    fi
    printf '  Benutzergruppen : %s\n' "$(id -nG)"
    printf '  Engagements     : %s\n' "$ENGAGEMENTS_DIR"
    printf '  Logdatei        : %s\n' "$LOGFILE"
    printf '  Version         : %s\n' "$SCRIPT_VERSION"
}

# =============================================================================
#  MENÜ-SYSTEM
# =============================================================================
show_header() {
    printf '%b\n' "${CYAN}Interface : ${YELLOW}${IFACE:-nicht gesetzt}${NC}"
    printf '%b\n' "${CYAN}Projekt   : ${YELLOW}${PROJECT_NAME:-nicht gesetzt}${NC}"
    printf '%b\n' "${CYAN}Loot      : ${YELLOW}${LOOT_DIR:-nicht gesetzt}${NC}"
    printf '%b\n' "${CYAN}Rechte    : ${YELLOW}$( (( ${#PRIV[@]} )) && echo 'sudo (dumpcap)' || echo 'unprivilegiert (capabilities)')${NC}"
    printf '\n'
}

hr() { printf '%b\n' "${BLUE}──────────────────────────────────────────────────────────────${NC}"; }

# Aktionen laufen mit deaktiviertem errexit, damit ein Teilfehler nie das
# gesamte Menü beendet; der Rückgabewert wird geloggt.
dispatch() {
    local fn="$1" rc=0
    set +e
    "$fn"
    rc=$?
    set -e
    (( rc != 0 )) && log WARN "Aktion '$fn' endete mit rc=$rc"
    return 0
}

run_menu() {
    local title="$1"; shift
    local entries=("$@")
    while true; do
        clear
        show_header
        hr
        printf '%b\n' "                 ${GREEN}${BOLD}${title}${NC}"
        hr
        local i
        for i in "${!entries[@]}"; do
            printf '  %2d) %s\n' "$((i+1))" "${entries[$i]%%|*}"
        done
        printf '   0) Zurück\n'
        hr
        local choice
        read -rp "Option: " choice || return 0
        [[ "$choice" == "0" ]] && return 0
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#entries[@]} )); then
            printf '\n'
            dispatch "${entries[$((choice-1))]#*|}"
            pause
        else
            warn "Ungültige Option."
            sleep 1
        fi
    done
}

menu_live_capture() {
    run_menu "Live Capture" \
        "Alles mitschneiden (ohne Filter)|action_capture_all" \
        "Web-Traffic (80/443)|action_capture_web" \
        "DNS (53/5353/853)|action_capture_dns" \
        "ARP-Traffic|action_capture_arp" \
        "Klartext-Protokolle (FTP/Telnet/HTTP/POP3/IMAP/SMTP/SNMP)|action_capture_unencrypted" \
        "Eigener Capture-Filter (BPF)|action_capture_custom_filter" \
        "Zeit-/Paketbegrenzte Aufzeichnung|action_capture_timed" \
        "Langzeit-Aufzeichnung mit Ringpuffer|action_capture_ringbuffer" \
        "Bluetooth-Capture|action_capture_bluetooth" \
        "Wireshark-GUI live starten|action_launch_gui_live"
}

menu_analysis() {
    run_menu "Analyse gespeicherter Captures" \
        "In Wireshark-GUI öffnen|action_open_in_gui" \
        "Protokoll-Hierarchie|action_protocol_stats" \
        "Conversations / Endpoints|action_conversations" \
        "Durchsatz & Expert Info|action_io_stats" \
        "Stream folgen (TCP/UDP/HTTP)|action_follow_stream" \
        "Klartext-Zugangsdaten suchen|action_find_cleartext_creds" \
        "Objekte/Dateien extrahieren (HTTP/SMB/TFTP)|action_export_http_objects" \
        "WLAN: SSIDs, Clients, EAPOL|action_wlan_ssids" \
        "WLAN: Capture mit Passphrase entschlüsseln|action_wlan_decrypt" \
        "TLS: SNI, Versionen, Zertifikate|action_tls_info" \
        "ARP-Spoofing-Prüfung|action_arp_spoof_check" \
        "Als CSV exportieren|action_csv_export"
}

menu_file_management() {
    run_menu "Dateiverwaltung" \
        "Captures zusammenführen (mergecap)|action_merge_captures" \
        "Capture filtern & speichern|action_filter_and_save" \
        "Capture-Informationen & Hash|action_capture_info" \
        "SHA256-Prüfsummen aller Captures|action_hash_all" \
        "Capture-Historie|action_show_history" \
        "Speicherverbrauch anzeigen|action_disk_usage"
}

menu_settings() {
    run_menu "Einstellungen & Diagnose" \
        "Interface neu wählen|action_reselect_interface" \
        "Projekt wechseln|action_switch_project" \
        "Umgebungs-Selbsttest|action_selftest" \
        "Logdatei anzeigen|action_show_log"
}

main_menu() {
    while true; do
        clear
        show_header
        hr
        printf '%b\n' "                      ${GREEN}${BOLD}Hauptmenü${NC}"
        hr
        printf '  1) Live Capture\n'
        printf '  2) Analyse gespeicherter Captures\n'
        printf '  3) Dateiverwaltung (Merge, Filter, Info, Historie)\n'
        printf '  4) Einstellungen & Diagnose\n'
        printf '  0) Beenden\n'
        hr
        local choice
        read -rp "Option (0-4): " choice || exit 0
        case "$choice" in
            1) menu_live_capture ;;
            2) menu_analysis ;;
            3) menu_file_management ;;
            4) menu_settings ;;
            0) exit 0 ;;
            *) warn "Ungültige Option."; sleep 1 ;;
        esac
    done
}

# =============================================================================
#  CLI / START
# =============================================================================
usage() {
    cat <<EOF
$SCRIPT_NAME $SCRIPT_VERSION – Capture- und Analyse-Frontend für tshark/dumpcap

Verwendung: $SCRIPT_NAME [Optionen]

Optionen:
  -i, --iface <name>     Capture-Interface vorbelegen
  -p, --project <name>   Projekt vorbelegen/anlegen (unter $ENGAGEMENTS_DIR)
  -y, --yes              Rückfragen mit Standardwerten beantworten
      --no-color         Farbausgabe deaktivieren
      --selftest         Umgebungsprüfung ausführen und beenden
  -h, --help             Diese Hilfe
  -V, --version          Version ausgeben

Hinweis: Einsatz ausschließlich in eigenen Laborumgebungen oder mit
schriftlicher Beauftragung. Captures und Reports werden mit Modus 0600
unterhalb von $ENGAGEMENTS_DIR abgelegt.
EOF
}

parse_args() {
    local arg_iface="" arg_project="" selftest_only=0
    while (( $# )); do
        case "$1" in
            -i|--iface)   [[ -n "${2:-}" ]] || die "--iface benötigt ein Argument"; arg_iface="$2"; shift 2 ;;
            -p|--project) [[ -n "${2:-}" ]] || die "--project benötigt ein Argument"; arg_project="$2"; shift 2 ;;
            -y|--yes)     ASSUME_YES=1; shift ;;
            --no-color)   NO_COLOR=1; shift ;;
            --selftest)   selftest_only=1; shift ;;
            -h|--help)    setup_colors; usage; exit 0 ;;
            -V|--version) printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
            --)           shift; break ;;
            *)            setup_colors; usage >&2; die "Unbekannte Option: $1" ;;
        esac
    done
    PRESET_IFACE="$arg_iface"; PRESET_PROJECT="$arg_project"; SELFTEST_ONLY="$selftest_only"
}

main() {
    parse_args "$@"
    setup_colors

    mkdir -p -m 700 "$STATE_DIR" "$CONF_DIR" "$ENGAGEMENTS_DIR"
    : >>"$LOGFILE"; chmod 600 "$LOGFILE"
    : >>"$HISTORY_FILE"; chmod 600 "$HISTORY_FILE"
    rotate_log
    log INFO "Start $SCRIPT_NAME $SCRIPT_VERSION (user=$(id -un))"

    TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/wspt.XXXXXXXX")"
    chmod 700 "$TMP_ROOT"

    refuse_root
    require_tools tshark dumpcap || die "Grundvoraussetzungen fehlen (Paket 'tshark' installieren)."

    if (( SELFTEST_ONLY )); then action_selftest; exit 0; fi

    clear
    printf '%b' "${BOLD}${CYAN}"
    cat <<'BANNER'
╔══════════════════════════════════════════════════════════════╗
║                  WIRESHARK POWER TOOL                        ║
║   Live Capture · Analyse · Credential-Suche · Export         ║
╚══════════════════════════════════════════════════════════════╝
BANNER
    printf '%b\n' "${NC}"
    msg "${YELLOW}Nur in eigener Lab-Umgebung oder mit schriftlicher Beauftragung einsetzen.${NC}"
    msg "${CYAN}Alle Artefakte werden protokolliert in: $LOGFILE${NC}"
    printf '\n'

    determine_privileges

    if [[ -n "${PRESET_IFACE:-}" ]]; then
        if interface_exists "$PRESET_IFACE"; then
            IFACE="$PRESET_IFACE"; config_set iface "$IFACE"; ok "Interface: $IFACE"
        else
            die "Unbekanntes Capture-Interface: $PRESET_IFACE"
        fi
    else
        select_interface || warn "Kein Interface gesetzt – wird bei Bedarf erneut abgefragt."
    fi

    if [[ -n "${PRESET_PROJECT:-}" ]]; then
        set_project_paths "$(sanitize_name "$PRESET_PROJECT")"
    else
        select_project
    fi

    main_menu
}

main "$@"
