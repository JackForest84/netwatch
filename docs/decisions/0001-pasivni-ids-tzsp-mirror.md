# ADR 0001 — Pasivní IDS přes TZSP zrcadlo do `dummy0`

- **Stav:** přijato
- **Datum:** 2026-05 (zpětně zdokumentováno)
- **Týká se služeb:** [tzsp-replay](../services/tzsp-replay/README.md),
  [suricata-wan](../services/suricata-wan/README.md)

> Tenhle ADR je **reálný příklad** i **šablona**. Pro nové rozhodnutí zkopíruj soubor jako
> `0002-nazev.md` a vyplň stejné tři sekce. Kostra je úplně dole.

---

## Kontext

Chtěl jsem vidět do provozu domácí sítě (IDS alerty + analýza toků) na WAN hraně, ale:

- MikroTik je hlavní brána a **nechci do datové cesty pouštět IDS inline** — kdyby Suricata
  spadla nebo zahltila CPU, neměla by shodit internet pro celou domácnost.
- Server `mikrotiktraffic` je samostatný malý stroj (3 vCPU, 4–6 GB RAM), ne router.
- MikroTik umí **zrcadlit provoz přes TZSP** (Token Zero-copy Sniffer Protocol) na cizí IP.
- Suricata i ntopng umí číst z rozhraní, ale ne přímo z TZSP streamu.

## Rozhodnutí

Postavit **pasivní side-car**, který stojí mimo datovou cestu:

1. MikroTik zrcadlí WAN provoz přes **TZSP** na server (UDP 37008).
2. Na serveru `tzsp2pcap` rozbalí TZSP a `tcpreplay-edit --topspeed` ho **přehraje do
   virtuálního rozhraní `dummy0`** (vytvořené přes `systemd-networkd`). To dělá
   služba [tzsp-replay](../services/tzsp-replay/README.md).
3. **Suricata** ([suricata-wan](../services/suricata-wan/README.md)) poslouchá na `dummy0`
   jako IDS a píše alerty do `eve.json`.
4. **ntopng** analyzuje toky na živém `ens18` (ne na dummy0).
5. **EveBox** + vlastní **NetWatch** dashboard čtou výsledky.

Stock systemd unity (`suricata.service`, `ntopng.service`, `evebox.service`) jsou
**vypnuté** a místo nich běží vlastní `-wan` / `-local` varianty s tímhle zapojením.

## Důsledky

**Dobré:**
- IDS je úplně mimo datovou cestu — pád Suricaty/serveru neovlivní konektivitu domácnosti.
- Server vidí WAN provoz, aniž by jím procházel.
- Lze libovolně restartovat, ladit pravidla a experimentovat bez rizika výpadku sítě.

**Špatné / na co si dát pozor:**
- ⚠️ **Detekce aplikační vrstvy (http/dns/tls/ssh) skoro nefunguje.** `tcpreplay`
  přehrává pakety v dávkách `--topspeed`, což rozbíjí TCP stream reassembly — většina toků
  má `app_proto=failed/null`. Spolehlivě fungují jen bezstavové protokoly (ntp, sip, dhcp)
  a signaturové alerty. **Není to regrese**, je to vlastnost tohohle zapojení.
- ⚠️ **`HOME_NET` past:** protože je to zrcadlo *WAN* provozu, většina útoků míří na veřejnou
  WAN IP (CGNAT `203.0.113.10`), ne na LAN. `HOME_NET` proto **musí obsahovat
  `203.0.113.0/25`**, jinak ET pravidla `$EXTERNAL_NET → $HOME_NET` tiše přestanou
  alertovat. Detail v [suricata-wan/runbook.md](../services/suricata-wan/runbook.md).
- Hodně „alertů" jsou artefakty přehrávání (chyby UDP checksumů), ne reálné nálezy.
- Závislostní řetězec: `dummy0` → `tzsp-replay` → `suricata-wan`. Pořadí restartu je nutné
  dodržet (viz [runbooks/restart-sluzby.md](../runbooks/restart-sluzby.md)).

---

## Šablona pro další ADR (zkopíruj a vyplň)

```markdown
# ADR 000X — <Krátký název rozhodnutí>

- **Stav:** návrh | přijato | nahrazeno ADR-000Y
- **Datum:** RRRR-MM-DD
- **Týká se služeb:** <odkazy>

## Kontext
Jaký problém řeším? Jaká byla omezení a alternativy?

## Rozhodnutí
Co jsem se rozhodl udělat a jak konkrétně.

## Důsledky
Co tím získávám (dobré) a co mě to stojí / na co si dát pozor (špatné).
```
