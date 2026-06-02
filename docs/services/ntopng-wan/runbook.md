# Runbook — ntopng-wan

## Provozní úkony

### Logy
```bash
journalctl -u ntopng-wan -n 80 --no-pager
journalctl -u ntopng-wan -f
```

### Restart
```bash
sudo systemctl restart ntopng-wan
systemctl status ntopng-wan
curl -sI http://192.168.50.36:3000 | head -1     # odpovídá web UI?
```
Pokud restartuješ redis, restartuj poté i ntopng.

### Kontrola
```bash
sudo ss -tulpn | grep -E ':3000|:37007'          # poslouchá?
redis-cli ping                                    # backing store žije? (PONG)
```

## Časté problémy

| Příznak | Příčina | Řešení |
|---|---|---|
| Web :3000 neodpovídá | služba spadla / redis nejede | `systemctl status ntopng-wan redis-server`, restart obojího |
| UI běží, ale prázdné grafy | neteče provoz na `ens18` | ověř `sudo tcpdump -ni ens18 -c 10` |
| „connection refused" na redis | redis down nebo plný | viz [../redis/runbook.md](../redis/runbook.md) |
| Dashboard nevidí ntopng data | špatné heslo v `ntopng.cred` nebo jiné REST | viz [../admin-dashboard/runbook.md](../admin-dashboard/runbook.md) |
| Chybí geolokace | neaktuální GeoIP | `sudo geoipupdate` + restart ntopng |

## Pokud to nepomůže (eskalace)
- Test konfigurace: dočasně spusť ručně `sudo /usr/sbin/ntopng /etc/ntopng/ntopng.conf`
  a sleduj výpis.
- Když je problém v redisu, řeš nejdřív [redis](../redis/runbook.md) — ntopng na něm závisí.
