# Runbook — redis

## Provozní úkony

### Logy
```bash
journalctl -u redis-server -n 60 --no-pager
```

### Restart
```bash
sudo systemctl restart redis-server
redis-cli ping                                   # PONG = žije
sudo systemctl restart ntopng-wan               # ntopng po restartu redisu nahodit znovu
```

### Kontrola stavu / paměti
```bash
redis-cli info memory | grep -E 'used_memory_human|maxmemory_human'
redis-cli info clients | grep connected_clients
redis-cli dbsize                                 # počet klíčů
```

## Časté problémy

| Příznak | Příčina | Řešení |
|---|---|---|
| `redis-cli ping` neodpovídá | služba spadla | `systemctl status redis-server`, restart |
| ntopng hlásí „connection refused" | redis down | restart redisu, pak ntopng |
| `used_memory` u stropu 512 MB | normální (allkeys-lru) | nic — redis zahazuje nejstarší klíče sám |
| Connection refused z jiného stroje | bind je jen localhost | tak je to schválně; ven se redis nevystavuje |

## Pokud to nepomůže (eskalace)
- Vyprázdnění (krajní řešení, ntopng si data dopočítá): `redis-cli flushall` a restart ntopng.
- Ověř konfiguraci: `sudo grep -E '^(bind|port|maxmemory)' /etc/redis/redis.conf`.
