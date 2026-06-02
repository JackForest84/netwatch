# Runbook — ntfy

## Provozní úkony

### Logy
```bash
journalctl -u ntfy -n 80 --no-pager
journalctl -u ntfy -f
```

### Restart
```bash
sudo systemctl restart ntfy
curl -sI http://192.168.50.36:8090 | head -1
```

### Test publikování notifikace
```bash
# přes přihlášeného uživatele (heslo viz /etc/admin-dashboard/ntfy-admin.pass):
curl -u admin:'<HESLO>' -d "test z runbooku" http://192.168.50.36:8090/mikrotiktraffic-info
```

### Správa uživatelů a oprávnění
```bash
sudo ntfy user list
sudo ntfy user add admin                 # interaktivně zadá heslo
sudo ntfy access admin 'mikrotiktraffic-*' rw
```

## Časté problémy

| Příznak | Příčina | Řešení |
|---|---|---|
| Notifikace nechodí | služba spadla / špatné heslo | `systemctl status ntfy`, ověř publish curlem výše |
| `403 Forbidden` při publish | `deny-all` + chybí přístup uživatele | `sudo ntfy access <user> <topic> rw` |
| Dashboard nehlásí nic do ntfy | špatné heslo v `ntfy-admin.pass` | sjednoť heslo v ntfy i v `/etc/admin-dashboard/ntfy-admin.pass` |
| Zmizeli uživatelé | smazaný `/var/cache/ntfy/user.db` | obnovit ze zálohy nebo vytvořit znovu (`ntfy user add`) |

## Pokud to nepomůže (eskalace)
- Ověř, že port `:8090` poslouchá: `sudo ss -tulpn | grep 8090`.
- Zkontroluj konfiguraci: `sudo ntfy serve --help` a hodnoty v `/etc/ntfy/server.yml`.
- ntfy je nezávislé na zbytku stacku — když nejede, nesouvisí to se Suricatou/ntopng.
