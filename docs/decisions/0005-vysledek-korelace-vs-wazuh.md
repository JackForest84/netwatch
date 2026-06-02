# ADR 0005 — Výsledek místo dojmu: korelace IDS ↔ firewall (a proč ne Wazuh)

- **Stav:** přijato
- **Datum:** 2026-06-01
- **Týká se služeb:** [admin-dashboard](../services/admin-dashboard/README.md) (NetWatch)

## Kontext
Dashboard ukazoval, KDO klepe (IDS detekce na zrcadle WAN), ale ne **výsledek** — jestli se
něco dostalo dovnitř. To je klasická slabina, na kterou by SOC senior ukázal: 1400+
„útočníků" denně bez kontextu *implikuje* dopad, který tam není.

Reálná data (24h):
- **1438** distinct útočníků (IDS), 2690 alertů.
- 7964 firewall dropů; **1250 z 1438 útočníků (87 %) firewall přímo zahodil**.
- Vystavený povrch (ověřeno na routeru): **0 aktivních inbound port-forwardů** (Minecraft
  `dst-nat` vypnutý, force-DNS scoped na `192.168.30.0/24`, API `8728` jen z LAN). Jediná
  ingress = **WireGuard VPN** (udp/16551), kryptograficky tichá.
- Top blokované porty: telnet 23, https 443, ssh 22, VNC 5900, SMB 445 — klasické skeny, drop.

**Otázka „přidat Wazuh?":** Wazuh = host/endpoint viditelnost (auth, FIM, vuln, malware *na
strojích*). Pro „výsledek WAN skenů" je k ničemu — skeny jsou zahozené na perimetru a na host
nikdy nedorazí, agent by z nich neviděl nic. Na tomhle boxu (6 GB RAM, už plný Suricatou +
ntopng + EveBoxem) by indexer (OpenSearch, 2–4 GB) navíc bolel.

## Rozhodnutí
**Nepřidávat Wazuh.** Místo toho **zkorelovat to, co už máme**:

- Nový endpoint **`/api/outcome`**: detekováno (IDS) → zablokováno (firewall) → prošlo na
  službu (= počet aktivních inbound port-forwardů). Plus top blokované porty a expozice.
- **Vystavený povrch živě z routeru** — `mikrotik_client` nově tahá `/ip/firewall/nat` a
  filtruje aktivní WAN `dst-nat` (zůstane pravdivé, i kdyby se něco vystavilo).
- **Panel „Výsledek · 24h"** nahoře v záložce Bezpečnost (3 čísla + porty + expozice).
- **Odznak „🛑 zahozeno firewallem"** u útočníků (join `alerts.src_ip` ↔ `firewall_drops`).

Wazuh zůstává jako **samostatný budoucí projekt** (host vrstva, na vlastní VM, zaměřený na
reálnou ingress: server, VPN, reverse-proxy) — ne jako lepidlo na otázku, kterou firewall
už zodpověděl.

## Důsledky
**Dobré:**
- Dashboard přestal *implikovat* dopad a začal ho *dokazovat*: „1438 detekováno → 87 %
  potvrzeno zahozeno → 0 prošlo na službu, jediná ingress je zamčená VPN".
- Senior-proof: přesně ta korelace, kterou by zkušený analytik chtěl vidět. Bez nových
  těžkých závislostí (Wazuh/SIEM).
- „Výsledek" je pravdivý a self-updating (port-forwardy živě z routeru).

**Cena / pozor:**
- `reached` = počet aktivních inbound port-forwardů (vystavené služby), **ne** „úspěšné
  průniky". VPN se chrání kryptograficky sama; její auth-výsledky NetWatch zatím nesleduje —
  to by byl právě ten Wazuh-like host krok.
- Korelace přes shodu `src_ip` ve 24h okně — heuristika, ne per-paketové párování (princip,
  ne přesnost — odchylky neřešíme).
- Záloha původních souborů: `~/nw-outcome-backup-<timestamp>/`.
