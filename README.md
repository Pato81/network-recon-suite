# nmap-powertool

Ein interaktives Bash-Framework, das `nmap`-gestützte Netzwerk-Recon und Reporting
für autorisierte Penetrationstests strukturiert und wiederholbar macht.

> ⚠️ **Nur für autorisierte Tests.** Dieses Werkzeug – insbesondere das aktive
> MITM-/ARP-Modul – darf ausschließlich gegen Systeme eingesetzt werden, für die
> eine ausdrückliche schriftliche Freigabe vorliegt. Unbefugtes Scannen oder das
> Umleiten fremden Netzwerkverkehrs ist in Deutschland u. a. nach §§ 202a ff.
> und § 303b StGB strafbar. Die Nutzung erfolgt auf eigene Verantwortung.

---

## Warum dieses Tool?

Im Engagement-Alltag wiederholen sich dieselben Schritte: Hosts entdecken,
Dienste und Versionen bestimmen, Ergebnisse dokumentieren und mit bekannten
Schwachstellen abgleichen. `nmap-powertool` bündelt diesen Ablauf in einem
menügeführten Werkzeug – mit sauberer Projektablage, Scan-Historie und
automatisiertem Reporting, statt loser Einzelbefehle.

## Funktionen

- **Discovery & Scanning** – Host-Discovery, Standard-, Stealth-, Aggressive-,
  Web- und UDP-Scans, Subnetz-Scans sowie Scans über Ziellisten (`-iL`) mit
  optionalem Host-Ausschluss (`--exclude`).
- **Tiefenscans** – vollständiger Portscan (`-p-`) und NSE-Vulnerability-Scans.
- **Projekt-Struktur** – jedes Engagement bekommt eine eigene Ablage
  (`recon/ exploit/ loot/ report/`), Ergebnisse landen automatisch am richtigen Ort.
- **Scan-Historie** – alle Läufe werden protokolliert und bleiben reproduzierbar.
- **Searchsploit-Korrelation** – erkannte Dienste/Versionen werden automatisch
  gegen die Exploit-DB abgeglichen, um bekannte Schwachstellen sichtbar zu machen.
- **Scan-Diff** – vergleicht zwei Scans und zeigt neu geöffnete bzw. geschlossene Ports.
- **HTML-Reporting** – XML-Ergebnisse werden über `xsltproc` in lesbare Reports umgewandelt.
- **Aktives MITM-Modul** – kontrolliertes ARP-Spoofing auf Basis von `bettercap`
  für autorisierte Man-in-the-Middle-Tests, mit sauberem Start/Stopp und Cleanup.
- **Komfort** – automatische Netzwerkerkennung, Desktop-Benachrichtigungen,
  sauberes Aufräumen per `trap`, strikte Eingabe-Validierung gegen Command-Injection.

## Voraussetzungen

- `nmap`
- `xsltproc` (HTML-Reports)
- `searchsploit` / `exploitdb` (Exploit-Korrelation)
- `bettercap` (nur für das aktive MITM-Modul)
- `libnotify-bin` (`notify-send`, optional für Desktop-Hinweise)

Getestet unter Kali Linux.

## Nutzung

```bash
chmod +x nmap-powertool.sh
./nmap-powertool.sh
```

Das Menü führt durch Zielwahl, Scan-Typ, Tiefenscans und Reporting.

## Technik-Highlights

- Dispatch-Tabellen-Menüs statt verschachtelter `if`-Kaskaden
- `set -uo pipefail`, zentrales Fehlermodell, `trap`-basiertes Cleanup
- Robuste Ziel-/Eingabevalidierung vor jedem `nmap`-Aufruf

---

## Hinweis zu diesem Repository

Dieses Repository ist Teil meines Portfolios als angehender Junior Penetration
Tester und dient der Einsicht in meinen Arbeits- und Programmierstil. Der Code
steht **nicht** unter einer Open-Source-Lizenz – siehe [LICENSE](LICENSE).

**Patrick May** · [LinkedIn](https://www.linkedin.com/in/patrick-may-664867367) · p.may.1981@web.de
