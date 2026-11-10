<div align="center">

# 🛰️ Network Recon Suite

### Netzwerk-Reconnaissance & Traffic-Analyse — aktiv und passiv in einer Suite

*Zwei komplementäre, menügeführte Bash-Frameworks: das eine findet und vermisst die Angriffsfläche, das andere liest und analysiert den Verkehr darauf. Gemeinsam decken sie die Netzwerk-Ebene eines Engagements ab — projektorientiert, reproduzierbar, mit automatischem Reporting und durchgehend safe-by-design.*

<br>

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-4682B4?style=for-the-badge&logo=nmap&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)

![Tools](https://img.shields.io/badge/Tools-2-blue?style=flat-square)
![Ansatz](https://img.shields.io/badge/Ansatz-aktiv%20%2B%20passiv-informational?style=flat-square)
![Fokus](https://img.shields.io/badge/Fokus-Recon%20%7C%20Forensik%20%7C%20Reporting-orange?style=flat-square)
![Engineering](https://img.shields.io/badge/Engineering-safe%20by%20design-success?style=flat-square)

</div>

---

## 📖 Über dieses Repository

Im Engagement-Alltag gehören zwei Dinge untrennbar zusammen: die **aktive Aufklärung** einer Umgebung (welche Hosts, Ports, Dienste und Versionen existieren?) und die **passive Analyse** des Verkehrs darauf (was läuft über die Leitung, und was verrät es?). Die **Network Recon Suite** bündelt genau diese beiden Disziplinen in zwei menügeführten Bash-Frameworks, die dieselbe Projektstruktur, dieselbe Engineering-Basis und dieselbe saubere Dokumentation teilen.

Statt loser Einzelbefehle, die man sich kaum merkt, führt die Suite durch einen **wiederholbaren, nachvollziehbaren Ablauf** — mit eigener Ablage je Engagement (`recon/ exploit/ loot/ report/`), Historie und automatisiertem Reporting. Beide Werkzeuge verlangen vor dem ersten aktiven Schritt eine **ausdrückliche Autorisierung** und sind durchgehend auf Betriebssicherheit ausgelegt (strikte Eingabevalidierung, Least Privilege, kontrolliertes Cleanup).

Dieses Repository ist Teil meines Portfolios und gibt Einblick in meinen Arbeits- und Programmierstil; der Code steht **nicht** unter einer Open-Source-Lizenz (siehe [LICENSE](LICENSE)).

<div align="center">

| Tool | Rolle | Perspektive | Kernnutzen |
|:---|:---|:---|:---|
| 🎯 **Nmap Power Tool** | Reconnaissance & Scanning | **aktiv** | Angriffsfläche entdecken, vermessen, mit Schwachstellen korrelieren |
| 🦈 **Wireshark Power Tool** | Capture & Analyse | **passiv / forensisch** | Verkehr mitschneiden, auswerten, Belege extrahieren |

</div>

---

## 🎯 Nmap Power Tool — *Active Reconnaissance & Scanning*

> **Rolle im Engagement:** Die Augen des Testers. Von „Was ist überhaupt da?" bis „Welche dieser Dienste sind angreifbar?" — strukturiert, reproduzierbar, dokumentiert.

Das **Nmap Power Tool** bündelt den wiederkehrenden Recon-Ablauf — Hosts entdecken, Dienste und Versionen bestimmen, dokumentieren und gegen bekannte Schwachstellen abgleichen — in einem Werkzeug mit sauberer Projektablage und echter Scan-Historie.

### 🔬 Fähigkeiten (aus Pentester-Sicht)

- **Discovery & Scanning:** schneller Host-Discovery (Ping-Sweep), Top-1000-Port-Scan, **Stealth-SYN-Scan** mit Version + OS, aggressiver `-A`-Scan, gezielter **Web-Port-Scan**, Subnetz-Scan, **UDP-Scan** der Top-Ports.
- **Tiefenscans:** vollständiger Portscan (`-p-`) und **NSE-Vulnerability-Scans** (`vuln`/`vulners`) für die ernsthafte Schwachstellenbewertung.
- **Zielsteuerung & Scope:** Einzelziel, ganzes Subnetz, **Ziellisten** (`-iL`) sowie Host-Ausschluss (`--exclude`). Optional erzwingt eine **Scope-Datei** (`--scope`), dass ausschließlich freigegebene Netze/Hosts gescannt werden — Scope-Grenzen werden technisch durchgesetzt, nicht nur dokumentiert.
- **Searchsploit-Korrelation:** erkannte Dienste/Versionen werden automatisch gegen die Exploit-DB abgeglichen — bekannte Schwachstellen werden sofort sichtbar und priorisierbar.
- **Scan-Diff:** vergleicht zwei Läufe und zeigt **neu geöffnete bzw. geschlossene Ports** — ideal für Re-Tests und Veränderungs-Monitoring.
- **HTML-Reporting:** XML-Ergebnisse werden via `xsltproc` in lesbare, kundentaugliche Reports umgewandelt.
- **Kontrolliertes MITM-Modul:** autorisiertes **ARP-Spoofing** auf Basis von `bettercap`, mit sauberem Start/Stopp und Cleanup — für Man-in-the-Middle-Tests innerhalb des Scopes.

---

## 🦈 Wireshark Power Tool — *Traffic Capture, Analyse & Forensik*

> **Rolle im Engagement:** Das Ohr des Testers. Was über die Leitung geht, wird mitgeschnitten, auseinandergenommen und als Beweis gesichert — mit Fokus auf Analyse und Forensik.

Das **Wireshark Power Tool** fasst die vielen kleinen `tshark`-Aufrufe rund um Aufzeichnen, Auswerten und Exportieren in einem Menü zusammen — mit automatischer Projektablage und Capture-Historie. Das Capturing läuft **privilegiengetrennt über `dumpcap`** (idealerweise via Gruppe `wireshark` + `CAP_NET_RAW`), nicht als root.

### 🔬 Fähigkeiten (aus Pentester-Sicht)

- **Live Capture:** vollständiger Mitschnitt oder gezielte **BPF-Filter** (Web, DNS, ARP, klassische Klartext-Protokolle wie FTP/Telnet/HTTP/POP3/IMAP), **zeitlich begrenzte** Aufzeichnung, **Ringpuffer** für Langzeit-Monitoring, Bluetooth-Capture und direkter Start der Wireshark-GUI.
- **Analyse gespeicherter Captures:** Protokoll-Hierarchie, **Conversations/Endpoints**, **TCP/UDP-Stream-Following** zur Rekonstruktion ganzer Sitzungen.
- **TLS-/SNI-Analyse:** Extraktion der ClientHello-Hostnamen und Zertifikatsdetails — macht sichtbar, welche Dienste die Clients tatsächlich ansprechen.
- **Beweissicherung:** **HTTP-Objekt-Extraktion** (Dateien direkt aus dem Traffic ziehen) und **Klartext-Credential-Suche** in unverschlüsselten Protokollen (read-only) — belegt reale Schwächen.
- **ARP-Spoofing-Erkennung:** findet IPs, denen mehrere MAC-Adressen zugeordnet sind — ein klarer Indikator für aktive MITM-Angriffe im Segment.
- **WLAN-Bezug:** SSID-/MAC-Übersicht aus dem Capture sowie **Entschlüsselung bekannter WPA-Captures** (`airdecap-ng`) für die Weiteranalyse.
- **Dateiverwaltung & Export:** Captures zusammenführen (`mergecap`), per Anzeigefilter speichern, `capinfos`, **CSV-Export** zur Weiterverarbeitung in Berichten — plus eingebauter **Selbsttest** (`--selftest`) zur Umgebungsprüfung.

---

## 🔗 Warum als Suite?

Die beiden Tools greifen ineinander wie aktive und passive Aufklärung im realen Test:

```
Nmap Power Tool  ──▶  findet Hosts, Ports, Dienste, Schwachstellen
       │
       ▼
Wireshark Power Tool  ──▶  schneidet den Verkehr dieser Dienste mit,
                           analysiert ihn und sichert Beweise
```

Beide schreiben in **dieselbe Engagement-Projektstruktur**, teilen Historie und Logging und liefern Ergebnisse, die direkt in den Prüfbericht einfließen. Ein typischer Ablauf: erst die Angriffsfläche mit dem **Nmap Power Tool** kartieren, dann mit dem **Wireshark Power Tool** den Verkehr der interessanten Dienste belauschen, TLS-SNI und Klartext-Daten auswerten und ARP-Anomalien verifizieren.

---

## 🔒 Safe by Design — gemeinsame Engineering-Basis

| Prinzip | Umsetzung |
|:---|:---|
| **Nur autorisiert** | Vor dem ersten aktiven Schritt steht ein Autorisierungs-Gate; aktive Module (Scanning, MITM, Live-Capture) laufen ausschließlich mit schriftlicher Freigabe bzw. im eigenen Lab. |
| **Scope-Durchsetzung** | Optionale Scope-Datei beim Scanner — freigegebene Netze/Hosts werden technisch erzwungen, nicht nur notiert. |
| **Saubere Architektur** | Dispatch-Tabellen-Menüs (`"Label\|funktion"`) statt verschachtelter `if`-Kaskaden. |
| **Technische Härtung** | `set -uo pipefail`, zentrales Fehler-/Logging-Modell mit Rotation, `trap`-basiertes Cleanup (auch bei `Ctrl+C`/Abbruch). |
| **Robustheit** | strikte Ziel-/Interface-/Eingabe-Validierung gegen Command- und Option-Injection vor jedem Tool-Aufruf. |
| **Least Privilege** | `sudo` nur dort, wo technisch nötig; Capturing privilegiengetrennt über `dumpcap`, keine GUI als root. |
| **Vertrauliche Ablage** | Captures und Reports werden mit Modus `0600` unterhalb von `~/engagements` gespeichert. |
| **Projektorientiert** | je Engagement eine eigene Ablage (`recon/ exploit/ loot/ report/`) mit Historie und automatischem Reporting. |

---

## ⚙️ Voraussetzungen

**Nmap Power Tool:** `nmap` · `xsltproc` (HTML-Reports) · `searchsploit`/`exploitdb` (Korrelation) · `bettercap` (nur MITM-Modul) · `libnotify-bin` (optional, Desktop-Benachrichtigung)

**Wireshark Power Tool:** `tshark`/`wireshark` inkl. `dumpcap`, `mergecap`, `capinfos` · `aircrack-ng` (`airdecap-ng`, nur WPA-Entschlüsselung) · `libnotify-bin` (optional)

Entwickelt und getestet unter **Kali Linux** (Bash ≥ 4). Für unprivilegiertes Capturing: Mitgliedschaft in der Gruppe `wireshark` + `CAP_NET_RAW` auf `dumpcap`.

---

## ▶️ Nutzung

```bash
chmod +x Nmap_PowerTool_pato_v2.0.sh Wireshark_PowerTool_pato_v.2.0.sh
```

### Nmap Power Tool

```bash
./Nmap_PowerTool_pato_v2.0.sh [Optionen]

  -s, --scope DATEI         Scope-Datei (erlaubte Netze/Hosts, eine pro Zeile)
  -y, --assume-authorized   Autorisierung nicht-interaktiv bestätigen (wird protokolliert)
  -h, --help                Diese Hilfe
```

Beispiel mit erzwungenem Scope:

```bash
./Nmap_PowerTool_pato_v2.0.sh --scope scope.txt
```

### Wireshark Power Tool

```bash
./Wireshark_PowerTool_pato_v.2.0.sh [Optionen]

  -i, --iface <name>     Capture-Interface vorbelegen
  -p, --project <name>   Projekt vorbelegen/anlegen (unter ~/engagements)
  -y, --yes              Rückfragen mit Standardwerten beantworten
      --no-color         Farbausgabe deaktivieren
      --selftest         Umgebungsprüfung ausführen und beenden
  -h, --help             Diese Hilfe
  -V, --version          Version ausgeben
```

Umgebung vor dem ersten Einsatz prüfen:

```bash
./Wireshark_PowerTool_pato_v.2.0.sh --selftest
```

Beide Werkzeuge sind menügeführt und fragen Interface/Ziel und Projekt ab, bevor es losgeht. Engagement-Daten landen standardmäßig unter `~/engagements/<projekt>/` und sind per `.gitignore` vom Repository ausgenommen.

---

## ⚠️ Rechtlicher Hinweis / Disclaimer

> Diese Werkzeuge — insbesondere die aktiven Module (Scanning, ARP-/MITM, Live-Capture) — sind **ausschließlich für autorisierte Sicherheitsüberprüfungen** bestimmt: im **eigenen Labor** oder mit **ausdrücklicher schriftlicher Freigabe** des Eigentümers der Zielsysteme.
>
> Unbefugtes Scannen sowie das Umleiten oder Mitschneiden fremden Netzwerkverkehrs ist in Deutschland u. a. nach **§§ 202a, 202b, 202c und 303b StGB** strafbar. Die Nutzung erfolgt auf eigene Verantwortung; der Autor übernimmt keine Haftung für Missbrauch.

---

## 👤 Autor

**Patrick May** · angehender Junior Penetration Tester (NRW, Deutschland)
Fachinformatiker für Systemintegration (IHK) · CompTIA Network+ & Security+

[LinkedIn](https://www.linkedin.com/in/patrick-may-664867367) · GitHub: [@Pato81](https://github.com/Pato81)

---

## 📄 Lizenz

Der Code steht **nicht** unter einer Open-Source-Lizenz — siehe [LICENSE](LICENSE).

<div align="center">

<sub>Teil meines Portfolios als angehender Junior Penetration Tester — Fokus auf saubere Engineering-Praxis, Methodik und verantwortungsvollen Umgang mit offensiven Werkzeugen.</sub>

</div>
