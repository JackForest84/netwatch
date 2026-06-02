# Runbook — evebox-local

## Provozní úkony

### Logy
```bash
journalctl -u evebox-local -n 80 --no-pager
journalctl -u evebox-local -f
```

### Restart
```bash
sudo systemctl restart evebox-local
curl -sI http://192.168.50.36:5636 | head -1     # odpovídá UI?
```

### Kontrola napojení na Suricatu
```bash
sudo ls -la /var/log/suricata/eve.json           # roste velikost?
sudo ls -la /var/lib/evebox/                      # events.sqlite, config.sqlite, bookmark
```
EveBox si pamatuje pozici v `eve.json` přes `*.bookmark` v `/var/lib/evebox/`.

## Časté problémy

| Příznak | Příčina | Řešení |
|---|---|---|
| UI :5636 neodpovídá | služba spadla | `systemctl status evebox-local`, restart |
| UI běží, ale žádné nové události | Suricata nepíše / nealertuje | viz [../suricata-wan/runbook.md](../suricata-wan/runbook.md) (HOME_NET past) |
| Dochází místo na disku | `events.sqlite` narostl | viz níže „Reset datastoru" |
| Po restartu chybí staré události | poškozený bookmark | EveBox dočte znovu od začátku `eve.json` |

### Reset datastoru (když events.sqlite nabobtná)
```bash
sudo systemctl stop evebox-local
sudo rm -f /var/lib/evebox/events.sqlite*         # smaž jen events, ne config.sqlite
sudo systemctl start evebox-local                 # naplní se znovu z eve.json
```

## Pokud to nepomůže (eskalace)
- Ověř, že `eve.json` reálně roste — pokud ne, problém je v Suricatě, ne v EveBoxu.
- Zkontroluj volné místo: `df -h /`. EveBox `events.sqlite` bývá největší žrout místa.
