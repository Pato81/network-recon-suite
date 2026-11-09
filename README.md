<div align="center">

# 🛰️ Network Powertools

### Netzwerk-Reconnaissance & Traffic-Analyse — aktiv und passiv in einer Suite

*Zwei komplementäre Bash-Frameworks: das eine findet und vermisst die Angriffsfläche, das andere liest und analysiert den Verkehr darauf. Gemeinsam decken sie die Netzwerk-Ebene eines Engagements ab — menügeführt, projektorientiert, mit automatischem Reporting.*

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

Im Engagement-Alltag gehören zwei Dinge untrennbar zusammen: die **aktive Aufklärung** einer Umgebung (welche Hosts, Ports, Dienste und Versionen existieren?) und die **passive Analyse** des Verkehrs darauf (was läuft über die Leitung, und was verrät es?). **Network Powertools** bündelt genau diese beiden Disziplinen in zwei menügeführten Bash-Frameworks, die dieselbe Projektstruktur, dieselbe Engineering-Basis und dieselbe saubere Dokumentation teilen.

Statt loser Einzelbefehle, die man sich kaum merkt, führt die Suite durch einen **wiederholbaren, nachvollziehbaren Ablauf** — mit eigener Ablage je Engagement (`recon/ exploit/ loot/ report/`), Historie und automatisiertem Reporting. Dieses Repository ist Teil meines Portfolios und gibt Einblick in meinen Arbeits- und Programmierstil; der Code steht **nicht** unter einer Open-Source-Lizenz (siehe [LICENSE](LICENSE)).

<div align="center">

| Tool | Rolle | Perspektive | Kernnutzen |
|:---|:---|:---|:---|
| 🎯 **nmap-powertool** | Reconnaissance & Scanning | **aktiv** | Angriffsfläche entdecken, vermessen, mit Schwachstellen korrelieren |
| 🦈 **wireshark-powertool** | Capture & Analyse | **passiv / forensisch** | Verkehr mitschneiden, auswerten, Belege extrahieren |

</div>

---

## 🎯 nmap-powertool — *Active Reconnaissance & Scanning*

> **Rolle im Engagement:** Die Augen des Testers. Von „Was ist überhaupt da?" bis „Welche dieser Dienste sind angreifbar?" — strukturiert, reproduzierbar, dokumentiert.

`nmap-powertool` bündelt den wiederkehrenden Recon-Ablauf — Hosts entdecken, Dienste und Versionen bestimmen, dokumentieren und gegen bekannte Schwachstellen abgleichen — in einem Werkzeug mit sauberer Projektablage und Scan-Historie.

### 🔬 Fähigkeiten (aus Pentester-Sicht)

- **Discovery & Scanning:** schneller Host-Discovery (Ping-Sweep), Top-1000-Port-Scan, **Stealth-SYN-Scan** mit Version + OS, aggressiver `-A`-Scan, gezielter **Web-Port-Scan**, Subnetz-Scan, **UDP-Scan** der Top-Ports.
- **Tiefenscans:** vollständiger Portscan (`-p-`) und **NSE-Vulnerability-Scans** (`vuln`/`vulners`) für die ernsthafte Schwachstellenbewertung.
- **Zielsteuerung:** Einzelziel, ganzes Subnetz, **Ziellisten** (`-iL`) sowie Host-Ausschluss (`--exclude`) — Scope-Grenzen sauber abbildbar.
- **Searchsploit-Korrelation:** erkannte Dienste/Versionen werden automatisch gegen die Exploit-DB abgeglichen — bekannte Schwachstellen werden sofort sichtbar und priorisierbar.
- **Scan-Diff:** vergleicht zwei Läufe und zeigt **neu geöffnete bzw. geschlossene Ports** — ideal für Re-Tests und Veränderungs-Monitoring.
- **HTML-Reporting:** XML-Ergebnisse werden via `xsltproc` in lesbare, kundentaugliche Reports umgewandelt.
- **Kontrolliertes MITM-Modul:** autorisiertes **ARP-Spoofing** auf Basis von `bettercap`, mit sauberem Start/Stopp und Cleanup — für Man-in-the-Middle-Tests innerhalb des Scopes.

---

## 🦈 wireshark-powertool — *Traffic Capture, Analyse & Forensik*

> **Rolle im Engagement:** Das Ohr des Testers. Was über die Leitung geht, wird mitgeschnitten, auseinandergenommen und als Beweis gesichert — mit Fokus auf Analyse und Forensik.

`wireshark-powertool` fasst die vielen kleinen `tshark`-Aufrufe rund um Aufzeichnen, Auswerten und Exportieren in einem Menü zusammen — mit automatischer Projektablage und Capture-Historie.

### 🔬 Fähigkeiten (aus Pentester-Sicht)

- **Live Capture:** vollständiger Mitschnitt oder gezielte **BPF-Filter** (Web, DNS, ARP, klassische Klartext-Protokolle wie FTP/Telnet/HTTP/POP3/IMAP), **zeitlich begrenzte** Aufzeichnung, **Ringpuffer** für Langzeit-Monitoring, Bluetooth-Capture und direkter Start der Wireshark-GUI.
- **Analyse gespeicherter Captures:** Protokoll-Hierarchie, **Conversations/Endpoints**, **TCP/UDP-Stream-Following** zur Rekonstruktion ganzer Sitzungen.
- **TLS-/SNI-Analyse:** Extraktion der ClientHello-Hostnamen und Zertifikatsdetails — macht sichtbar, welche Dienste die Clients tatsächlich ansprechen.
- **Beweissicherung:** **HTTP-Objekt-Extraktion** (Dateien direkt aus dem Traffic ziehen) und **Klartext-Credential-Suche** in unverschlüsselten Protokollen (read-only) — belegt reale Schwächen.
- **ARP-Spoofing-Erkennung:** findet IPs, denen mehrere MAC-Adressen zugeordnet sind — ein klarer Indikator für aktive MITM-Angriffe im Segment.
- **WLAN-Bezug:** SSID-/MAC-Übersicht aus dem Capture sowie **Entschlüsselung bekannter WPA-Captures** (airdecap-ng) für die Weiteranalyse.
- **Dateiverwaltung & Export:** Captures zusammenführen (`mergecap`), per Anzeigefilter speichern, `capinfos`, **CSV-Export** zur Weiterverarbeitung in Berichten.

---

## 🔗 Warum als Suite?

Die beiden Tools greifen ineinander wie aktive und passive Aufklärung im realen Test:

```
nmap-powertool  ──▶  findet Hosts, Ports, Dienste, Schwachstellen
       │
       ▼
wireshark-powertool  ──▶  schneidet den Verkehr dieser Dienste mit,
                          analysiert ihn und sichert Beweise
```

Beide schreiben in **dieselbe Engagement-Projektstruktur**, teilen Historie und Logging und liefern Ergebnisse, die direkt in den Prüfbericht einfließen. Ein typischer Ablauf: erst die Angriffsfläche mit `nmap-powertool` kartieren, dann mit `wireshark-powertool` den Verkehr der interessanten Dienste belauschen, TLS-SNI und Klartext-Daten auswerten und ARP-Anomalien verifizieren.

---

## 🔒 Safe by Design — gemeinsame Engineering-Basis

| Prinzip | Umsetzung |
|:---|:---|
| **Nur autorisiert** | Aktive Module (Scanning, MITM, Live-Capture) ausschließlich mit schriftlicher Freigabe bzw. im eigenen Lab. |
| **Saubere Architektur** | Dispatch-Tabellen-Menüs (`"Label\|funktion"`) statt verschachtelter `if`-Kaskaden. |
| **Technische Härtung** | `set -uo pipefail`, zentrales Fehler-/Logging-Modell mit Rotation, `trap`-basiertes Cleanup. |
| **Robustheit** | strikte Ziel-/Interface-/Eingabe-Validierung gegen Command-Injection vor jedem Tool-Aufruf. |
| **Least Privilege** | `sudo` wird nur dort angefordert, wo technisch nötig (z. B. Live-Capture), nicht pauschal. |
| **Projektorientiert** | je Engagement eine eigene Ablage (`recon/ exploit/ loot/ report/`) mit Historie und automatischem Reporting. |

---

## ⚙️ Voraussetzungen

**nmap-powertool:** `nmap` · `xsltproc` (HTML-Reports) · `searchsploit`/`exploitdb` · `bettercap` (nur MITM-Modul) · `libnotify-bin` (optional)

**wireshark-powertool:** `tshark`/`wireshark` (inkl. `mergecap`, `capinfos`) · `aircrack-ng` (`airdecap-ng`, nur WPA-Entschlüsselung) · `libnotify-bin` (optional)

Getestet unter **Kali Linux**.

## ▶️ Nutzung

```bash
chmod +x nmap-powertool.sh wireshark-powertool.sh

./nmap-powertool.sh        # Recon, Scanning, Reporting
./wireshark-powertool.sh   # Capture, Analyse, Forensik
```

Beide Werkzeuge sind menügeführt und fragen Interface/Ziel und Projekt ab, bevor es losgeht.

---

## ⚠️ Rechtlicher Hinweis / Disclaimer

> Diese Werkzeuge — insbesondere die aktiven Module (Scanning, ARP-/MITM, Live-Capture) — sind **ausschließlich für autorisierte Sicherheitsüberprüfungen** bestimmt: im **eigenen Labor** oder mit **ausdrücklicher schriftlicher Freigabe** des Eigentümers der Zielsysteme.
>
> Unbefugtes Scannen, das Umleiten oder Mitschneiden fremden Netzwerkverkehrs ist in Deutschland u. a. nach **§§ 202a, 202b, 202c und 303b StGB** strafbar. Die Nutzung erfolgt auf eigene Verantwortung; der Autor übernimmt keine Haftung für Missbrauch.

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
