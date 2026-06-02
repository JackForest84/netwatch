# ADR 0007 — Per-device internet přes NetFlow (MikroTik Traffic-Flow → vlastní kolektor)

- **Stav:** přijato
- **Datum:** 2026-06-01
- **Týká se služeb:** [admin-dashboard](../services/admin-dashboard/README.md) (NetWatch), MikroTik

## Kontext
Per-device internet (kdo kolik stáhl/nahrál) nešel z ntopng — na `ens18` v přepínané síti
vidí jen server + router (viz ADR 0003). Jediné místo, které vidí **všechna zařízení**, je
router. Majitel proto zapnul na MikroTiku Traffic-Flow.

## Rozhodnutí
- **MikroTik:** `Traffic-Flow` (NetFlow v9) na `interfaces=bridge,ether5`, target
  `dst-address=192.168.50.36 port=2055 version=9`.
- **Vlastní kolektor** `netflow_collector.py` (vlákno v dashboardu, bind `udp/2055`):
  parsuje NetFlow v9 (šablony + data) a atribuuje per-zařízení (IPv4, LAN `192.168.0.0/16`):
  - `src` = zařízení, `dst` = internet → **upload** (záznam z bridge, pre-NAT).
  - **postNAT-dst (pole 226) = zařízení → download** — download vstupuje na ether5 jako
    `dst=WAN-IP`, ale pole 226 nese **skutečnou IP zařízení**. ← klíčový trik kvůli NATu.
  - Každých 60 s flush delty do `store.db` (tabulka `device_inet`, 30denní retence).
- **Endpoint `/api/device-inet`** (top zařízení za období, jména z inventáře) + panel
  **„🏆 Provoz po zařízeních · internet"** (nahradil odebranou „neměřeno" hlášku).
- Ověřeno na živých datech: `notebook ↓137 MB`, `telefon ↓18 MB`, `IoT-čidlo`… reálná
  pojmenovaná zařízení s down/up.

Při té příležitosti: **WAN a VPN provoz sjednoceny do jedné karty „Provoz"** s filtrem
WAN/VPN + jednou historií (místo dvou samostatných karet).

## Důsledky
**Dobré:**
- Konečně **reálný per-device internet** s down/up a jmény — co ntopng v tomto zapojení
  nikdy neuměl. Atribuce funguje i přes NAT (pole 226). Lehké, bez nProbe/placených nástrojů.
- Kolektor běží jako vlákno v dashboardu (jako ostatní), restart služby = restart kolektoru.

**Cena / pozor:**
- **IPv4 only** (LAN `192.168/16`). IPv6 per-device zatím neatribuujeme.
- Kolektor drží `udp/2055` (běží pod `netwatch`; systemd hardening to dovolí, `AF_INET`).
- Data jsou delty po 60 s → první data ~1 min po startu.
- Vyžaduje zapnutý MikroTik Traffic-Flow s targetem na `.36:2055`.
- Standalone testovací parser: `~/nfcollect_test.py`. Záloha: `~/nw-netflow-backup-<ts>/`.
