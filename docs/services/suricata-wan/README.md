# suricata-wan

## Co to je
**IDS** (intrusion detection) nad WAN provozem. Suricata 7.0.3 poslouchá na rozhraní
`dummy0` (kam [tzsp-replay](../tzsp-replay/README.md) přehrává zrcadlený provoz z MikroTiku),
vyhodnocuje pravidla a zapisuje události do `/var/log/suricata/eve.json`. Ten pak čtou
[EveBox](../evebox-local/README.md) i [NetWatch dashboard](../admin-dashboard/README.md).

## Závislosti
- **`dummy0`** + **[tzsp-replay](../tzsp-replay/README.md)** — unit má
  `Requires=` i `After=tzsp-replay.service` a v `ExecStartPre` čeká, až je `dummy0` UP.
- **Pravidla:** `/var/lib/suricata/rules/suricata.rules` (~47 tisíc pravidel, ET ruleset).
- **GeoIP:** databáze z `geoipupdate` (týdenní timer) v `/var/lib/GeoIP/`.
- **Konzumenti:** EveBox a dashboard čtou výsledný `eve.json`; dashboard navíc mluví se
  Suricatou přes command socket `/var/run/suricata-command.socket`
  (práva řeší `suricata-socket-perms.path`).

## Nasazení
- Unit: `/etc/systemd/system/suricata-wan.service`, **běží jako root**, `Restart=always`.
- `ExecStart`: `/usr/bin/suricata -i dummy0 -c /etc/suricata/suricata.yaml`.
- `ExecStartPre` nahodí `dummy0` a počká (až 10×1 s), než je UP — jinak by Suricata spadla.
- Konfigurace: `/etc/suricata/suricata.yaml`. **Klíčová hodnota `HOME_NET`** (viz Poznámky).
- Stock `suricata.service` z `/usr/lib/...` je **vypnutý** — používá se jen tahle `-wan` varianta.

## Přístup
- Žádné webové UI. Výstup se konzumuje přes `eve.json` a přes
  [EveBox :5636](../evebox-local/README.md).
- Command socket: `/var/run/suricata-command.socket` (root:root 660, čte ho `netwatch`
  díky `suricata-socket-perms`).

## Zálohy
- Zálohuj `/etc/suricata/suricata.yaml` (hlavně kvůli laděnému `HOME_NET`) a unit soubor.
- `eve.json` se rotuje (logrotate, 30 dní) — historie alertů je primárně v EveBoxu.

## Známé problémy / poznámky
- ⚠️ **HOME_NET past** — kritické, viz [runbook.md](runbook.md). `HOME_NET` **musí**
  obsahovat WAN CGNAT blok `203.0.113.0/25`, jinak ET pravidla `$EXTERNAL_NET → $HOME_NET`
  tiše přestanou alertovat. Aktuální hodnota:
  `[192.168.20.0/24,192.168.30.0/24,192.168.40.0/24,192.168.50.0/24,203.0.113.0/25]`.
- ⚠️ **Aplikační detekce (http/dns/tls/ssh) skoro nefunguje** kvůli `tcpreplay --topspeed`
  (rozbitá TCP reassembly). Fungují bezstavové protokoly a signaturové alerty. Viz
  ADR [0001](../../decisions/0001-pasivni-ids-tzsp-mirror.md).
- Část alertů jsou artefakty přehrávání (chyby checksumů), ne reálné nálezy.
- **Aktualizace pravidel (od 2026-06-01):** ET Open ruleset přes `suricata-update` běží
  **týdně** — `suricata-update.timer` (neděle ~04:30) → `suricata-update.service` (oneshot:
  update + live `suricatasc -c reload-rules`, bez výpadku). Předtím se pravidla
  **neaktualizovala automaticky** (byla z ledna → ~47k); po prvním běhu ~50k načtených, 0 chyb.
  Ruční update: `sudo suricata-update && sudo suricatasc -c reload-rules`. Kontrola počtu
  načtených: `sudo suricatasc -c ruleset-stats`.
