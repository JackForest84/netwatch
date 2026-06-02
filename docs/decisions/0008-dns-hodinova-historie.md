# ADR 0008 — DNS hodinová historie + časový filtr Bezpečnosti/DNS

- **Stav:** přijato
- **Datum:** 2026-06-01
- **Týká se služeb:** [admin-dashboard](../services/admin-dashboard/README.md) (NetWatch), AdGuard Home

## Kontext
Záložky Bezpečnost a DNS měly napevno okno „24h". Chtěli jsme stejný **časový filtr**
(1h/6h/24h/7d/30d) jako na Přehledu.
- Bezpečnostní agregace (alerty, donuty, země, útočníci) se počítají z SQLite → stačí je
  parametrizovat `hours`.
- DNS je jiný případ: AdGuard přes `/control/stats` vrací **jen jedno pevné okno** — skalár
  `num_dns_queries` je klouzavý součet za nastavený interval, nedá se odečítat mezi vzorky.
  Libovolný rozsah by tedy nešel. ALE stejný endpoint vrací i **hodinová pole**
  (`dns_queries[]`, `blocked_filtering[]`, `time_units=hours`, délka 24).

## Rozhodnutí
- **Bezpečnost:** `alert_summary_from_store(hours=)` parametrizováno; nový endpoint
  `/api/security-summary?hours=` a `hours` doplněno do `/api/outcome`, `/api/recent-alerts`,
  `/api/wall-of-shame`. Donuty/headline/země/útočníci **vyňaty z `renderOverview` do
  `renderSecurityAlerts()`** řízeného vlastním `refreshSecurity()` — jinak by je 5s refresh
  přehledu přepisoval zpět na 24h. Záložka má vlastní řádek period-chipů.
- **DNS = vlastní hodinová historie:** démon `_dns_history_sampler()` (vlákno, každých 5 min,
  **bez extra HTTP** — čte poll-cache `adguard_client`) skládá hodinová pole do nové tabulky
  **`dns_history(ts_hour, instance, queries, blocked)`** přes `INSERT OR REPLACE`. AdGuard si
  pamatuje jen posledních 24 h; my si necháváme i ty starší → `/api/dns-history?period=` pak
  **sečte libovolné okno dopředu**. Hodinové buckety do 48 h, denní nad 48 h. 30denní retence.
  UI poctivě hlásí „historie zatím od …", když období přesahuje nasbíraná data.

## Důsledky
**Dobré:**
- Konzistentní časový filtr napříč Přehled / Bezpečnost / DNS.
- DNS historie je **trustworthy** (vlastní per-hodina buckety, ne klouzavý skalár) a nezávislá
  na konfiguraci AdGuardu. Žádná zátěž navíc na AdGuard (čteme už nasbíraný poll-cache).

**Cena / pozor:**
- **DNS 7d/30d se naplní až dopředu** (po startu máme jen posledních 24 h z AdGuardu).
- `dns_history` ~48 řádků/h (2 instance × 24 přepisovaných buckety) — drženo retencí 30 d.
- Top domény/klienti zůstávají za aktuální 24h okno AdGuardu (per-doménovou historii neukládáme).

Při té příležitosti (UI 2026-06-01): mini-mapa překlopena na **šířku** (landscape, Internet
vlevo → klienti vpravo, vedle globusu); karta WAN dostala **Ø/den + odhad na měsíc + denní graf**
(`wan_daily` v `/api/internet-usage`); „Co se právě teď děje" má **fullscreen živě**
s klikatelnými IP; panel Výsledek přejmenován z „zablokováno firewallem" na **„potvrzeno
zahozeno"** s vysvětlivkou (sub-100 % = mezera v logování, ne průnik; reálný dopad =
„prošlo na službu" = 0).
