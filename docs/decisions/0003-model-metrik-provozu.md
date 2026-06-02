# ADR 0003 — Měříme jen to, čemu lze věřit (model metrik provozu)

- **Stav:** přijato
- **Datum:** 2026-06-01
- **Týká se služeb:** [admin-dashboard](../services/admin-dashboard/README.md) (NetWatch)

## Kontext
Dashboard míchal **tři zdroje** provozních dat, které měří různé věci na různých místech sítě:

| Zdroj | Měří | Problém |
|---|---|---|
| MikroTik interface countery | provoz na portech routeru | ✅ autoritativní |
| ntopng na `ens18` | provoz, který projde serverovou NIC | v přepínané síti vidí jen **server + router**, ne ostatní zařízení |
| UniFi per-client | WiFi klienty | jen WiFi, vlastní countery |

Čísla se proto nikdy nesečetla. Naměřeno (30 dní):
- **WAN ether5:** ↓ ~92 / ↑ ~15 GiB — důvěryhodné.
- **„LAN":** ↓ 14 / ↑ 192 GiB — `↑192` je skoro **2× WAN download**, protože se sčítal
  `bridge` + `ether1-4` + `vlany` (dvojí/trojí počítání); navíc `rx/tx` je z **pohledu
  routeru** (obrácené vůči zařízení) a míchá internet s interním provozem.
- **„Spotřeba zařízení":** v žebříčku byl TOP `192.168.50.36` (**server**) a `router.lan`
  (**router**) — měřila se monitorovací instalace, ne zařízení. Reálná zařízení ~0.

**Princip (zadání):** co nelze změřit téměř se 100% jistotou, **neměříme** — nepřesné číslo
je horší než žádné a v prezentaci tě potopí.

## Rozhodnutí
- **Ukazujeme jen autoritativní countery z routeru:** **WAN (ether5)** a **VPN (wireguard)**.
  Směr je jednoznačný jen na WAN hraně: `↓` = z internetu, `↑` = do internetu.
- Nový endpoint **`/api/internet-usage`**: WAN+VPN za **tento měsíc / minulý měsíc / 24h /
  7d / 30d** (sčítání pozitivních delt, odolné vůči resetu counteru; měsíc v lokálním čase).
- **Odstraněno z UI:** karta „LAN download/upload" (fake směr + dvojí počítání),
  „Spotřeba zařízení · tento měsíc" a „Top talkers · per zařízení" (z ntopng = server+router).
  Endpointy `/api/monthly-traffic` a `/api/talkers` zůstaly v kódu, ale UI je už nevolá.
- **Per-device záměrně nezobrazujeme** — místo toho poctivá karta vysvětlující proč.
- **ntopng zůstává** na to, na co je dobrý (live „teď", bezpečnost, geolokace), ne na objem
  per-device.

## Důsledky
**Dobré:**
- Vše na obrazovce je **obhajitelné a sedí** — WAN je jediný zdroj pravdy, nic se nepřekrývá.
- Prezentace bez slabin: *„měříme jen router-grade countery; per-device záměrně vynecháno,
  dokud nebude flow-grade zdroj"* je silnější tvrzení než falešný žebříček.

**Cena / co příště:**
- Per-device zatím chybí. Reálně se zapne přes **MikroTik Traffic-Flow** (export toků
  z routeru → kolektor) → doplní se per-device žebříček. Je to jediná chybějící věc a
  vyžaduje malou změnu na routeru (dnes `traffic-flow enabled=false`, bez targetu).
- `/api/monthly-traffic` a `/api/talkers` jsou teď „mrtvé" endpointy (ponechané, nevyužité).
- Záloha původních souborů před změnou: `~/nw-metrics-backup-<timestamp>/`
  (rollback = vrátit `app.py`, `store.py`, `templates/index.html` a restart služby).
