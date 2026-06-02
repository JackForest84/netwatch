# Runbook — tzsp-replay

## Provozní úkony

### Logy
```bash
journalctl -u tzsp-replay -n 80 --no-pager
journalctl -u tzsp-replay -f                 # živě
```

### Restart
```bash
sudo systemctl restart tzsp-replay
systemctl status tzsp-replay
```
Po restartu téhle služby restartuj i `suricata-wan` (čte z `dummy0`).

### Ověření, že do dummy0 reálně teče provoz
```bash
ip -o link show dummy0                        # má být state UP nebo UNKNOWN
sudo tcpdump -ni dummy0 -c 20                 # mělo by se sypat pár desítek paketů
ip -s link show dummy0                        # RX/TX čítače rostou?
```

### Ověření příjmu TZSP z MikroTiku
```bash
sudo tcpdump -ni ens18 udp port 37008 -c 10   # přicházejí TZSP pakety od routeru?
```

## Časté problémy

| Příznak | Příčina | Řešení |
|---|---|---|
| `dummy0` neexistuje | nenačetl se modul/networkd | `sudo systemctl restart systemd-networkd`, ověř `/etc/systemd/network/10-dummy0.*` |
| `tcpdump -ni dummy0` mlčí, ale na ens18 UDP 37008 teče | spadlá roura `tzsp2pcap`/`tcpreplay` | `sudo systemctl restart tzsp-replay`, koukni do `journalctl -u tzsp-replay` |
| Ani na `ens18` nepřichází UDP 37008 | MikroTik nezrcadlí / špatná cílová IP | zkontroluj sniffer/mirror na MikroTiku (**TODO: doplnit postup**) |
| Suricata nealertuje, flows ale běží | nejde o tuhle službu | viz [../suricata-wan/runbook.md](../suricata-wan/runbook.md) („HOME_NET past") |

## Pokud to nepomůže (eskalace)
- Restartuj celý vstup: `systemd-networkd` → `tzsp-replay` → `suricata-wan`
  (viz [../../runbooks/restart-sluzby.md](../../runbooks/restart-sluzby.md)).
- Pokud TZSP nechodí ani na `ens18`, problém je **na MikroTiku** nebo v síti mezi
  routerem a serverem, ne na tomhle stroji.
