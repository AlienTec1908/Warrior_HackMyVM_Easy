# Warrior - HackMyVM (Easy)
 
![Warrior.png](Warrior.png)

## Übersicht

*   **VM:** Warrior
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Warrior)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 9. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Warrior_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Warrior"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), auf dem eine `robots.txt` auf mehrere interessante Pfade hinwies, darunter `/internal.php`. Diese Datei enthielt eine Nachricht für einen Benutzer "bro" und eine MAC-Adress-basierte Zugriffsbeschränkung. Durch Spoofing der eigenen MAC-Adresse (auf `00:00:00:00:00:AF` oder ähnlich) und erneuten Aufruf von `/internal.php` wurde das Passwort `Zurviv0r1` für den Benutzer `bro` im Quellcode der Seite gefunden. Dies ermöglichte den SSH-Login als `bro`. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Die Privilegieneskalation zu Root erfolgte durch Ausnutzung einer unsicheren `sudo`-Regel: `bro` durfte `/usr/bin/task` als `root` ohne Passwort ausführen. Durch den Befehl `/usr/sbin/sudo /usr/bin/task execute /bin/sh` wurde eine Root-Shell erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `curl` (impliziert) / Web Browser
*   `ifconfig`
*   `ssh`
*   `ls`
*   `cat`
*   `find`
*   `sudo` (mit absolutem Pfad)
*   `task` (Taskwarrior, via `sudo`)
*   `id`
*   `pwd`
*   `cd`
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Warrior" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Information Gathering:**
    *   IP-Findung mit `arp-scan` (`192.168.2.107`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 8.4p1) und 80 (HTTP - Nginx 1.18.0).
    *   Nmap-Skript `http-robots.txt` offenbarte interessante "Disallowed"-Einträge, darunter `/internal.php`, `/user.txt`, `/secret.txt`.
    *   Untersuchung der gefundenen Dateien:
        *   `/user.txt` enthielt "loco".
        *   `/secret.txt` enthielt "0123456789ABCDEF".
        *   `/internal.php` zeigte eine Nachricht für "bro" und eine MAC-Adress-Bedingung (`00:00:00:00:00:a?`) für Passwortzugriff.

2.  **Initial Access (MAC Spoofing & SSH als `bro`):**
    *   Spoofing der MAC-Adresse des Angreifer-Systems auf ein passendes Muster (z.B. `00:00:00:00:00:AF`) mittels `ifconfig` (oder direkt in den VM-Einstellungen).
    *   Erneuter Aufruf von `http://192.168.2.107/internal.php` (nach MAC-Spoofing) zeigte "Good!!!!!".
    *   Im Quellcode (HTML-Kommentar) dieser Seite wurde das Passwort `Zurviv0r1` für den Benutzer `bro` gefunden.
    *   Erfolgreicher SSH-Login als `bro` mit dem Passwort `Zurviv0r1` (`ssh bro@warrior.vm`).
    *   User-Flag `LcHHbXGHMVhCpQHvqDen` in `/home/bro/user.txt` gelesen.

3.  **Privilege Escalation (von `bro` zu `root` via `sudo task`):**
    *   `sudo -l` (mit vollem Pfad `/usr/sbin/sudo -l`, da `sudo` nicht im PATH war) als `bro` zeigte: `(root) NOPASSWD: /usr/bin/task`.
    *   Ausnutzung dieser Regel durch Ausführen von `/usr/sbin/sudo /usr/bin/task execute /bin/sh`.
    *   Erlangung einer Root-Shell.
    *   Root-Flag `HPiGHMVcDNLlXbHLydMv` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Informationslecks in `robots.txt`:** Enthüllte Pfade zu sensiblen Dateien und Skripten.
*   **Unsichere Zugriffskontrolle (MAC-Adress-Filterung):** Eine serverseitige Prüfung basierte auf der leicht zu fälschenden MAC-Adresse des Clients.
*   **Passwort im HTML-Kommentar:** Ein Passwort wurde im Quellcode einer Webseite gespeichert.
*   **Unsichere `sudo`-Konfiguration (`task`):** Die Erlaubnis, `/usr/bin/task` (Taskwarrior) als `root` ohne Passwort auszuführen, ermöglichte durch die `execute`-Option die Ausführung beliebiger Befehle und somit die Erlangung von Root-Rechten.

## Flags

*   **User Flag (`/home/bro/user.txt`):** `LcHHbXGHMVhCpQHvqDen`
*   **Root Flag (`/root/root.txt`):** `HPiGHMVcDNLlXbHLydMv`

## Tags

`HackMyVM`, `Warrior`, `Easy`, `robots.txt`, `MAC Spoofing`, `Password in HTML`, `SSH`, `sudo Exploitation`, `task`, `Taskwarrior`, `Privilege Escalation`, `Linux`, `Web`
