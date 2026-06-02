# ADR 0004 — Klasifikace alertů podle záměru (signal vs blocklist radiation)

- **Stav:** přijato
- **Datum:** 2026-06-01
- **Týká se služeb:** [admin-dashboard](../services/admin-dashboard/README.md) (NetWatch)

## Kontext
Dashboard ukazoval ~2630 „Vážných" (severity 2) alertů za 24h a 0 kritických. Externí
review to označil za „alert fatigue / generátor šumu". Reálná data ale ukazují něco jiného —
rozpad za 24h:

| počet | co to je |
|---|---|
| 2431 | ET DROP / Spamhaus / CINS / Dshield → zásahy z **threat-intel blocklistů** (reputace) |
| 154 | ET SCAN → **skeny portů** (MySQL/PostgreSQL/MSSQL …) |
| 61 | ICMP / decode → protokolové anomálie / artefakty |
| 34 | info / recon |

Tedy **ne false-positives, ale internetová „background radiation"** na WAN IP. Suricata to
detekuje správně — problém byl jen v PREZENTACI: generická ET kategorie „Misc Attack" (2438)
signál schovala.

## Rozhodnutí
Klasifikovat alerty podle **záměru** (`classify_intent` v `app.py`) místo spoléhání na ET
classtype:

- Kbelíky: **blocklist** (reputace) · **scan** (skeny) · **attack** (exploit/malware) ·
  **recon** (info) · **anomaly** (protokol/artefakty) · **other**.
- Donut „Kategorie alertů" → **„Záměr alertů"** (sémantické barvy + ikony, čistá boční legenda).
- **Headline strip:** „X k řešení (skeny+exploity) · Y blocklist radiation · Z anomálie".
- Recent-alerty dostaly barevný **odznak záměru**.
- Vystaveno přes `/api/overview` (`alerts.top_intents`, `alerts.intent_headline`) a
  `/api/recent-alerts` (pole `intent`).

Při té příležitosti UX opravy z review:
- **Vypnuté vestavěné Chart.js legendy** obou donutů — zdroj překryvu i slitého
  „KritickáVážnáMéně vážná". Zůstávají čisté boční legendy (`#cat-legend`, `#sev-legend`).
- **Firewall tabulka vede blokující pravidla** (drop/reject nahoře) + souhrn 🛑/✅, místo
  řazení podle objemu (accept).

## Důsledky
**Dobré:**
- Z „2630 vážných = šum" je **„154 k řešení · 2431 očekávaná blocklist radiation"** — příběh,
  ne slabina. Defuse-uje hlavní výtku review a ukazuje detection-engineering nadhled.
- Klasifikace je heuristika nad textem signatury (žádná změna Suricaty ani DB schématu),
  takže bez rizika a snadno rozšiřitelná o další vzory.

**Cena / pozor:**
- Heuristika podle klíčových slov — nové rulesety může být potřeba doplnit do `classify_intent`.
  Rostoucí kbelík **„other"** je signál, že nějaký vzor chybí.
- `top_categories` v API zůstává (zpětná kompatibilita), ale UI ho už nepoužívá.
- Záloha původních souborů: `~/nw-alerts-backup-<timestamp>/`.
