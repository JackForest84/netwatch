# Runbook — admin-dashboard (NetWatch)

## Provozní úkony

### Logy
```bash
journalctl -u admin-dashboard -n 100 --no-pager
journalctl -u admin-dashboard -f
```

### Restart (i po změně kódu)
```bash
sudo systemctl restart admin-dashboard
systemctl status admin-dashboard
curl -sk https://192.168.50.36:8889/api/health      # rychlý self-check
```

### Zdraví a stav integrací
```bash
curl -sk https://192.168.50.36:8889/api/health | python3 -m json.tool
```
V odpovědi sleduj `db_mb`/`wal_mb` (růst DB), `rss_mb` (paměť), `threads` a stav
jednotlivých integrací (`mikrotik`/`unifi`/`ntopng`/`adguard` = true/false) a
`last_alert_age`.

### Databáze
```bash
sudo ls -la /var/lib/admin-dashboard/                # store.db (+ -wal/-shm)
# velikost / WAL je vidět i v /api/health (db_mb, wal_mb)
```

## Časté problémy

| Příznak | Příčina | Řešení |
|---|---|---|
| Web :8889 neodpovídá | služba spadla | `systemctl status admin-dashboard`, `journalctl -u admin-dashboard -n 50` |
| Služba padá hned po startu se SIGSYS | někdo přidal `~@resources` do `SystemCallFilter` | odeber ho z unitu, `daemon-reload`, restart |
| `/api/health`: `suricata` část mlčí / chyba socketu | špatná práva `suricata-command.socket` | viz [Suricata socket](#suricata-socket-práva) níže |
| Integrace `mikrotik/unifi/ntopng/adguard` = false | špatné creds nebo nedostupný cíl | ověř cred soubor v `/etc/admin-dashboard/` a dostupnost cíle (`curl`) |
| Web jde lokálně, ne přes `monitoring.example.com` | problém na externí proxy | dashboard běží správně; řeš proxy (mimo tento server) |
| 429 při přihlášení | brute-force lockout na `/login` (10 chyb/5 min) | počkej 5 min, nebo restartuj službu (vynuluje zámky) |
| Po přihlášení nenabízí Proton Pass uložení | starý Basic Auth v cache prohlížeče | zavři záložku/okno a otevři znovu `/login` |
| Chci se odhlásit | — | otevři `/logout` (smaže session cookie) |
| Prohlížeč varuje na cert | self-signed na :8889 | normální; přes `monitoring.example.com` jde důvěryhodný cert z proxy |

### Suricata socket práva
Dashboard (`netwatch`) čte `/var/run/suricata-command.socket`. Po restartu Suricaty socket
vznikne znovu jako `root:root` a práva opraví `suricata-socket-perms.path`. Když to selže:
```bash
systemctl status suricata-socket-perms.path
sudo ls -la /var/run/suricata-command.socket          # má být grupa netwatch, mode 660
sudo systemctl restart suricata-socket-perms.path      # znovu nahodí watcher
# ruční náprava:
sudo chgrp netwatch /var/run/suricata-command.socket && sudo chmod 660 /var/run/suricata-command.socket
```

## Pokud to nepomůže (eskalace)
1. Spusť uvicorn ručně pro plný traceback:
   ```bash
   sudo -u netwatch bash -c 'cd /opt/admin-dashboard && python3 -m uvicorn app:app --host 127.0.0.1 --port 8899'
   ```
2. Jednotlivé integrace ladí jejich klientské moduly v `/opt/admin-dashboard/`
   (`mikrotik_client.py`, `unifi_client.py`, `ntopng_client.py`, `adguard_client.py`).
3. Závislé služby (Suricata/ntopng) řeš nejdřív v jejich runboocích — dashboard je jen
   konzumuje.
