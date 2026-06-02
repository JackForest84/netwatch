# ADR 0006 — Topologie: kurátorovaná hierarchie místo auto-discovery

- **Stav:** přijato
- **Datum:** 2026-06-01
- **Týká se služeb:** [admin-dashboard](../services/admin-dashboard/README.md) (NetWatch), záložka Mapa

## Kontext
Topologie se generovala auto-discovery z UniFi/MikroTiku a házela všechna zařízení
**naplocho pod MikroTik** (chaotický force-graf). Nereflektovala reálnou hierarchii a neuměla
zachytit fakta, která z API nezjistí: LTE záloha, WiFi 7, 2.5G, monitorovací cluster node
`.30` přímo na MikroTik portu 3, a který switch je hlavní vs koncový.

## Rozhodnutí
Topologii definovat jako **explicitní hierarchii potvrzenou majitelem**, obohacenou o živá
data (stav zařízení, počty klientů, dotazy DNS, spojení MikroTiku):

```
🌐 Internet
   🛡️ MikroTik hAP ax³   [📶 LTE záloha · 2.5G]
      ├ 🛡️🌐 DNS ×2 · AdGuard (.11 / .21)   ← veškerý DNS sem; pod ní visí celá LAN
      │     └ 🔀 Hlavní switch (USW Flex 2.5G 8 PoE)   „z kterého vše běží"
      │          ├ 🔀 Koncový switch (USW Flex 2.5G 5)
      │          └ 📶 3× AP · WiFi 7 · PoE (Obývák/Pracovna/Patro) + počty klientů
      └ 🖥️ Monitoring · cluster .30 (MikroTik port 3, přímo · stav z ARP)
```

- Render změněn z **force-grafu na deterministický strom shora dolů** (`d3.tree`, zaoblené
  karty, ikony, odznaky, stavové barvy) — přehlednější a hlavně předvídatelný.
- Hlavní switch = ten s „PoE" / „8" v názvu; zbytek = koncový. Heuristika nad živými UniFi názvy.
- Backend `/api/topology` přepsán z plochých linků na striktní strom (jeden rodič na uzel).
- **DNS ×2 zařazeno jako vrstva** přímo pod MikroTik a **celá LAN visí pod ní** —
  vizuálně „veškerý provoz přes DNS". Je to **logický/DNS-flow pohled** (AdGuard je fyzicky
  host, ale MikroTik na něj DNS vynucuje); proto **jeden uzel ×2** (.11+.21), ne dvě
  samostatné krabice — ve stromu nejdou oba „in-path" (uzel má jednoho rodiče).
- **Render v2 (2026-06-01):** detail i náhled jsou **kulaté levitující bublinky** —
  force-simulace s `forceY` na úroveň ve stromu (= top-down hierarchie + levitace + drag),
  **stejný styl v obou** (náhled se po usazení zmrazí). Přidána **logická čárkovaná šipka
  DNS → Monitoring** (monitoring používá DNS, kreslí se PŘÍMO na DNS, ne přes switch).
  Per-device „neměřeno" karta **odebrána na přání majitele** (princip z ADR 0003 platí dál —
  per-device čeká na Traffic-Flow).

## Důsledky
**Dobré:**
- Mapa konečně dává smysl (skutečná hierarchie) a je atraktivní (čisté karty + barvy + odznaky).
- Strom je **deterministický** (žádný jitter force-simulace) → spolehlivý vzhled i bez ladění.
- Živá data zůstávají (stav, klienti, DNS/spojení).

**Cena / pozor:**
- Klasifikace hlavní/koncový switch je heuristika podle názvu — při změně HW ověř.
- DNS ×2 je jeden uzel „×2" (ne dva samostatné) — lze rozdělit, když budeš chtít.
- Monitoring `.30` a štítky (LTE / WiFi 7 / 2.5G / port 3) jsou zadané podle majitele,
  ne auto-zjištěné.
- Mini-topologie (náhled na Přehledu) si ponechává force layout; hlavní Mapa je strom.
- Vizuál finálně ověřit v prohlížeči (viz browser-QA prompt). Záloha: `~/nw-topo-backup-<ts>/`.
