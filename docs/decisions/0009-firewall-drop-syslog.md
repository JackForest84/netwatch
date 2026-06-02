# ADR 0009 — Kompletní záznam firewall dropů přes remote syslog

- **Stav:** přijato (server hotový; MikroTik: `log=yes` na drop pravidlech hotovo, čeká na `netwatch` logging action — viz níže)
- **Datum:** 2026-06-01
- **Týká se služeb:** [admin-dashboard](../services/admin-dashboard/README.md) (NetWatch), MikroTik

## Kontext
Panel „Výsledek" párował IDS detekce (Suricata) s firewall dropy přes IP a vycházelo
~87 % — zbylých ~13 % detekovaných IP nemělo **zalogovaný** drop, takže o nich nešlo s
jistotou říct, čím skončily. Pro monitoring nástroj nedostatečné. Dvě příčiny (z reálných
pravidel):
1. **Blocklist/scanner dropy logují potichu** — pravidla na adresové listy `wan-scanner-block`,
   `bf-block`, `port-scanners` zahazují **bez `log=yes`**. Přesně tyhle IP Suricata hlásí jako
   blocklist radiaci → detekováno, ale žádný log. Jádro těch 13 %.
2. **Ztrátový sběr** — dashboard tahal `/rest/log` (posledních 50 řádků) jednou za 30 s; pod
   náporem se kruhový buffer routeru přepíše dřív, než ho stihneme přečíst.

(Bezpečnostně to **není** díra: ven 0 služeb, default policy zahodí vše nevyžádané. Je to čistě
mezera v *měření*.)

## Rozhodnutí
- **MikroTik posílá firewall log přes remote syslog** (UDP) na monitorovací server
  `192.168.50.36:5514` — push v reálném čase místo ztrátového pollingu.
- **Blocklist/scanner dropy se logují** stejným prefixem `IN_DENY_WAN ` jako catch-all
  (`LOG deny input from WAN`), takže každé zahození WAN vstupu má jeden log řádek.
- **Nový kolektor `firewall_syslog.py`** (vlákno v dashboardu, bind `udp/5514`, parser sdílený
  s `firewall_log._parse_entry`) ukládá **100 %** řádků do `store.db` (`firewall_drops`) živě.
  Dokud syslog teče (`recent()`), starý REST-poll v `firewall_log` **stojí** → žádné dvojí počítání.
- `/api/outcome` vrací `capture: syslog|poll`; UI vysvětlivku podle toho přepíná.

### Příkazy na MikroTiku (aplikuje majitel — firewall = citlivé)
`log=yes log-prefix="IN_DENY_WAN "` na 3 blocklist drop pravidlech (scanners/BF/port-scanner)
je již nastaveno. Zbývá:
```
# odstranit mrtvý Wazuh (.34 nikdy neběžel, 12 pravidel posílalo do prázdna)
/system logging remove [find action="wazuh"]
/system logging action remove [find name="wazuh"]
# firewall dropy → NetWatch syslog na .36
/system logging action add name=netwatch target=remote remote=192.168.50.36 remote-port=5514
/system logging add topics=firewall action=netwatch
# držet default /log print čistý (firewall jen na netwatch, ne do memory bufferu)
/system logging set [find where topics="info" and action="memory"] topics="info,!firewall"
```
Rollback netwatch: `/system logging remove [find action=netwatch]` +
`/system logging action remove [find name=netwatch]` (+ `log=no` na ta 3 pravidla).

**Integrace s lokálním loggingem (viz [runbook](../runbooks/mikrotik-wan-logging.md)):** firewall
(`firewall,info`) se drží MIMO `wanmem`/`wandisk` (filtrují interface/error/warning); `!firewall`
ho vyřadí i z default memory bufferu. Wazuh (remote → 192.168.50.34) byl potvrzeně mrtvý →
odstraněn; soulad s ADR 0005.

## Důsledky
**Dobré:**
- Detekováno ↔ Zahozeno se srovná na ~100 %; o každé IP lze říct, že byla zahozena (a kterým prefixem).
- Žádná ztráta pod náporem (push, ne poll). Server-side firewall neaktivní (`ufw` off, INPUT ACCEPT) → port projde.

**Cena / pozor:**
- Objem logu je nízký (~0,5–1 řádek/s dle counterů), `firewall_drops` drží 30denní retence.
- Syslog je UDP/plaintext — OK na interní LAN (`.1` → `.36`).
- `/api/outcome` páruje detekce (v okně) proti dropům za **≥24 h** (ne stejné úzké okno):
  Suricata (zrcadlo) a firewall logují tutéž IP v různých momentech, takže same-window
  průnik uměle snižoval shodu (ověřeno: nepárované IP v 1h jsou *všechny* v 24h dropech).
  Po opravě: 1h ≈ 100 %, 6h ≈ 96 %; 24h dožene ~100 %, jak odejdou data z poll éry.
- Zbytek pod 100 % = detekce reálně **nezahozené** (ICMP přijaté pravidlem „accept ICMP",
  established/related, replay artefakty), **ne průnik** (`reached` = 0 zůstává klíčové číslo dopadu).
