# tzsp-replay

## Co to je
Vstupní bod celého monitoringu. MikroTik zrcadlí WAN provoz přes **TZSP** na tento server
(UDP **37008**). Služba `tzsp-replay` ho rozbalí a přehraje do virtuálního rozhraní
`dummy0`, kde si ho pak čte Suricata. Bez téhle služby nemá IDS co analyzovat.

Řetězec: `MikroTik (TZSP) → tzsp2pcap -f → tcpreplay-edit → dummy0 → suricata-wan`.

Proč zrovna takhle, viz ADR [0001](../../decisions/0001-pasivni-ids-tzsp-mirror.md).

## Závislosti
- **`dummy0`** — virtuální rozhraní vytvořené přes `systemd-networkd`
  (`/etc/systemd/network/10-dummy0.netdev` + `10-dummy0.network`).
- **`tzsp2pcap`** (`/usr/local/sbin/tzsp2pcap`) — rozbalí TZSP na pcap stream.
- **`tcpreplay-edit`** (`/usr/bin/`) — přehraje pakety do `dummy0`.
- **MikroTik** musí mít nastavené TZSP zrcadlení na `192.168.50.36:37008`.
  **TODO: doplnit** přesnou konfiguraci sniffer/mirror na routeru (je na MikroTiku, ne tady).
- **Konzument:** [suricata-wan](../suricata-wan/README.md) (závisí na téhle službě).

## Nasazení
- Unit: `/etc/systemd/system/tzsp-replay.service`, `Type=simple`, **běží jako root**,
  `Restart=always`.
- `ExecStart` nahodí `dummy0` a spustí rouru:
  ```
  ip link set dummy0 up
  tzsp2pcap -f | tcpreplay-edit --topspeed --mtu=1500 --mtu-trunc -i dummy0 -
  ```
- Žádný build, žádné závislosti přes pip — jen systémové binárky.

## Přístup
- **Poslouchá:** UDP `0.0.0.0:37008` (příjem TZSP).
- Žádné webové UI, žádné přihlášení — je to jen datová roura.

## Zálohy
- Žádná data. Zálohuj jen **unit soubor** a `/etc/systemd/network/10-dummy0.*`
  (viz [obnova-ze-zalohy.md](../../runbooks/obnova-ze-zalohy.md)).

## Známé problémy / poznámky
- ⚠️ `--topspeed` přehrávání **rozbíjí TCP stream reassembly** → Suricata nevidí dobře
  aplikační vrstvu (http/dns/tls). To je vlastnost, ne chyba — detail v ADR 0001.
- Hodně paketů má chybné checksumy (artefakt přehrávání) → část Suricata alertů jsou
  falešné pozitivy tohoto typu.
- Když je `dummy0` down, Suricata se nerozjede. `tzsp-replay` proto rozhraní nahazuje sám.
