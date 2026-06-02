# evebox-local

## Co to je
Webový prohlížeč Suricata událostí. EveBox 0.25.0 sleduje (tail) soubor
`/var/log/suricata/eve.json`, ukládá události do vlastní SQLite databáze a nabízí UI pro
procházení a filtrování alertů. Praktický „inbox" pro to, co Suricata najde.

## Závislosti
- **[suricata-wan](../suricata-wan/README.md)** — zdroj událostí (`eve.json`).
  Unit má `After=`/`Wants=suricata-wan.service`.
- **Datastore:** vlastní SQLite v `/var/lib/evebox/` (`events.sqlite`, `config.sqlite`).
- **GeoIP:** `/usr/share/GeoIP/` (symlink na `/var/lib/GeoIP/`).

## Nasazení
- Unit: `/etc/systemd/system/evebox-local.service`, `Type=simple`, `Restart=always`.
- `ExecStart`:
  ```
  evebox server -D /var/lib/evebox --datastore sqlite \
    --input /var/log/suricata/eve.json --host 0.0.0.0 --port 5636 --no-auth --no-tls
  ```
- Stock `evebox.service` je **vypnutý** — používá se jen tahle `-local` varianta.

## Přístup
- **Web UI:** http://192.168.50.36:5636 (bind `0.0.0.0:5636`).
- ⚠️ **Bez autentizace a bez TLS** (`--no-auth --no-tls`) — spoléhá na to, že port je
  dostupný jen z LAN. Ven ho nevystavovat. Viz Poznámky.

## Zálohy
- `events.sqlite` (~1,6 GB) **zálohovat netřeba** — po smazání se naplní znovu z `eve.json`.
- Pokud chceš, zazálohuj jen unit soubor.

## Známé problémy / poznámky
- ⚠️ UI je **otevřené bez hesla** — drž ho jen v LAN, nikdy nereverzproxovat ven bez auth.
- Stejná omezení detekce jako u Suricaty (aplikační vrstva skoro nealertuje) — viz
  ADR [0001](../../decisions/0001-pasivni-ids-tzsp-mirror.md).
- `events.sqlite` umí narůst (teď ~1,6 GB) — když dojde místo, lze ho smazat a nechat
  EveBox naplnit znovu (viz [runbook.md](runbook.md)).
