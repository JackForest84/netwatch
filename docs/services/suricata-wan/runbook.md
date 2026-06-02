# Runbook — suricata-wan

## Provozní úkony

### Logy
```bash
journalctl -u suricata-wan -n 80 --no-pager
sudo tail -f /var/log/suricata/suricata.log      # interní log Suricaty
sudo tail -f /var/log/suricata/eve.json          # živý proud událostí (JSON)
sudo tail -f /var/log/suricata/fast.log          # stručné alerty
```

### Restart / reload pravidel
```bash
sudo systemctl restart suricata-wan              # plný restart
sudo systemctl reload suricata-wan               # reload pravidel (kill -HUP) bez výpadku
sudo suricata-update && sudo systemctl reload suricata-wan   # stáhnout nová pravidla a reload
```

### Kontrola, že Suricata reálně detekuje
```bash
# počty paketů a alertů ze statistik:
sudo grep -E 'decoder.pkts|detect.alert' /var/log/suricata/stats.log | tail -4
# nebo přes command socket:
sudo suricatasc -c "iface-stat dummy0"
```

## Časté problémy

### ⚠️ Alerty jsou NULA, ale pakety/flows přibývají → HOME_NET past
Protože je to zrcadlo **WAN** provozu, útoky míří na veřejnou WAN IP, ne na LAN.
Když ISP přes DHCP změní CGNAT blok, přestanou ET pravidla `$EXTERNAL_NET → $HOME_NET` alertovat.

```bash
# 1) jaká je teď WAN IP? (na MikroTiku, rozhraní ether5 — TODO: doplnit jak zjistit)
# 2) co má Suricata v HOME_NET?
sudo grep -E '^\s*HOME_NET:' /etc/suricata/suricata.yaml
# 3) musí obsahovat aktuální WAN /25 blok (teď 203.0.113.0/25). Pokud ne, oprav a:
sudo systemctl reload suricata-wan
# 4) ověř, že detect.alert zase roste:
sudo grep 'detect.alert' /var/log/suricata/stats.log | tail -2
```

### Ostatní

| Příznak | Příčina | Řešení |
|---|---|---|
| Služba spadne hned po startu | `dummy0` nebyl UP | ověř [tzsp-replay](../tzsp-replay/runbook.md), pak restart |
| „dummy0 not ready" v logu | `tzsp-replay` neběží | `sudo systemctl restart tzsp-replay`, pak `suricata-wan` |
| Spousta UDP checksum alertů | artefakt přehrávání | normální pro tenhle setup, ignoruj (viz ADR 0001) |
| Dashboard nevidí Suricatu | špatná práva socketu | ověř `suricata-socket-perms.path`, viz [../admin-dashboard/runbook.md](../admin-dashboard/runbook.md) |
| Chyba v `suricata.yaml` | překlep v configu | `sudo suricata -T -c /etc/suricata/suricata.yaml` (test configu) |

## Pokud to nepomůže (eskalace)
- Otestuj konfiguraci: `sudo suricata -T -c /etc/suricata/suricata.yaml`.
- Pořadí restartu: `tzsp-replay` → `suricata-wan` (viz
  [../../runbooks/restart-sluzby.md](../../runbooks/restart-sluzby.md)).
- Když pakety nepřibývají vůbec, problém je výš — v [tzsp-replay](../tzsp-replay/runbook.md)
  nebo na MikroTiku, ne v Suricatě.
