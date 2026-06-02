# Runbook — MikroTik: WAN logging + monitoring

Finální stav lokálního logování a monitoringu WAN na hAP ax³ (primární WAN `ether5` DHCP
`203.0.113.10/25`, gw `.1`, distance 1; záloha `lte1` distance 2), doplněný o remote syslog
firewall dropů do NetWatch (viz [ADR 0009](../decisions/0009-firewall-drop-syslog.md)).

## Logging actions
- `wanmem` (RAM) — rychlý troubleshooting: `/log print where buffer=wanmem`
- `wandisk` (USB) — delší historie: `/file print where name~"usb1/logs/wanlog"`
- `netwatch` (remote → `192.168.50.36:5514`) — **jen firewall dropy** pro bezpečnostní dashboard
- built-in `memory` / `echo` — default buffer
- ~~`wazuh` (remote → `192.168.50.34`)~~ — **odstraněno 2026-06-01** (Wazuh nikdy neběžel, .34 je mrtvá → 12 pravidel posílalo do prázdna)

## Topics (lokálně wanmem/wandisk)
Ponechat **interface, error, warning** (warning nese i Netwatch události). Vyřazeno
`dhcp`/`ppp`/`pppoe`/`route` (šum nebo se nepoužívá — `dhcp` míchá WAN klienta a LAN server).

## Firewall dropy → NetWatch (ADR 0009)
Pravidla `input` „silent drop WAN scanners / BF / Port Scanner" + catch-all `LOG deny input
from WAN` logují prefixem `IN_DENY_WAN`; rule `topics=firewall → netwatch` je posílá syslogem na
`.36`, kde je kolektor `firewall_syslog.py` ukládá živě. Drží se **mimo** `wanmem`/`wandisk`
(ty filtrují interface/error/warning). Aby firewall nešpinil ani default `/log print`, je z
default memory rule vyloučen (`topics=info,!firewall`).

## Příkazy — cílový stav
```
# 1) odstranit mrtvý Wazuh (.34 neběží)
/system logging remove [find action="wazuh"]
/system logging action remove [find name="wazuh"]

# 2) firewall dropy → NetWatch dashboard (.36)
/system logging action add name=netwatch target=remote remote=192.168.50.36 remote-port=5514
/system logging add topics=firewall action=netwatch

# 3) udržet default /log print čistý (firewall jen na netwatch)
/system logging set [find where topics="info" and action="memory"] topics="info,!firewall"
```
Pravidla `log=yes log-prefix="IN_DENY_WAN "` na input drop pravidlech (scanners/BF/port-scanner)
už nastavena.

## Netwatch sondy (výpadky WAN)
`wan-gw 203.0.113.1`, `wan-cf 1.1.1.1`, `wan-google 8.8.8.8` (interval 30s) → `:log warning`
při up/down. Interpretace: gw down + oba veřejné cíle down → problém na primární WAN; gw up +
cíle neodpovídají → dál v síti ISP / internetu.

## Kontroly
- `/log print follow where topics~"(interface|warning|error)"` — relevantní WAN události
- Dashboard „Výsledek": `capture` se přepne na `syslog` a Detekováno ↔ Zahozeno se srovná na ~100 %
