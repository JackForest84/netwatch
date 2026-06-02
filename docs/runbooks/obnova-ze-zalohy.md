# Runbook — Obnova ze zálohy

> ⚠️ **DŮLEŽITÉ — aktuální stav:** Na serveru **neběží žádná automatická záloha aplikačních
> dat.** Existuje jen jednorázový `/root/audit-backup-20260528-*` (ruční, ze security auditu)
> a systémové `/var/backups/alternatives.*` (dpkg, ne uživatelská data). Než bude co
> „obnovovat ze zálohy", je potřeba zálohování nejdřív zavést — viz
> [Co je potřeba zálohovat](#co-je-potřeba-zálohovat) a **TODO** níže.

## Kdy použít (příznaky)
- Poškozená/smazaná databáze dashboardu (`store.db`) nebo EveBoxu (`events.sqlite`).
- Rozbitá konfigurace služby a chceš se vrátit k poslednímu funkčnímu stavu.
- Migrace na nový stroj / reinstalace serveru.

## Co je potřeba zálohovat
Tohle jsou data, jejichž ztráta bolí (kód dashboardu je v `/opt/admin-dashboard`, ale
**není** ve vlastním gitu — viz TODO):

| Co | Cesta | Proč |
|---|---|---|
| Konfigurace + tajnosti dashboardu | `/etc/admin-dashboard/` | API klíče, hesla, TLS cert — nedají se „odvodit". |
| Databáze dashboardu | `/var/lib/admin-dashboard/store.db` | 30 dní alertů, zařízení, snapshotů. |
| Kód dashboardu | `/opt/admin-dashboard/` | vlastní aplikace NetWatch (~1700 LOC). |
| systemd unity | `/etc/systemd/system/*-wan.service`, `tzsp-replay.service`, `evebox-local.service`, `admin-dashboard.service`, `suricata-socket-perms.*` | vlastní zapojení celého stacku. |
| Konfigurace IDS/monitoru | `/etc/suricata/suricata.yaml`, `/etc/ntopng/ntopng.conf`, `/etc/redis/redis.conf`, `/etc/ntfy/server.yml`, `/etc/GeoIP.conf` | netriviální nastavení (HOME_NET apod.). |
| Síť pro dummy0 | `/etc/systemd/network/10-dummy0.*` | bez toho nejde IDS side-car. |

EveBox `events.sqlite` (~1,6 GB) **zálohovat netřeba** — naplní se znovu z `eve.json`.

## Postup (obnova konkrétní části)

### A) Obnova databáze dashboardu ze zálohy
```bash
sudo systemctl stop admin-dashboard
sudo cp -a /cesta/k/zaloze/store.db /var/lib/admin-dashboard/store.db
sudo rm -f /var/lib/admin-dashboard/store.db-wal /var/lib/admin-dashboard/store.db-shm
sudo chown netwatch:netwatch /var/lib/admin-dashboard/store.db
sudo systemctl start admin-dashboard
curl -sk https://192.168.50.36:8889/api/health     # ověření
```

### B) Obnova konfigurace / unitů
```bash
# příklad: vrácení suricata.yaml
sudo cp -a /cesta/k/zaloze/suricata.yaml /etc/suricata/suricata.yaml
sudo systemctl restart suricata-wan

# příklad: vrácení systemd unitu
sudo cp -a /cesta/k/zaloze/admin-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart admin-dashboard
```

### C) Obnova tajností `/etc/admin-dashboard/`
```bash
sudo cp -a /cesta/k/zaloze/etc-admin-dashboard/. /etc/admin-dashboard/
sudo chown -R netwatch:netwatch /etc/admin-dashboard
sudo chmod 600 /etc/admin-dashboard/*.key /etc/admin-dashboard/*.cred \
               /etc/admin-dashboard/*.pass /etc/admin-dashboard/*.json /etc/admin-dashboard/cert.key
sudo systemctl restart admin-dashboard
```

### D) Reinstalace na čistém stroji (DR)
1. Ubuntu 24.04, nainstaluj balíčky: `suricata`, `ntopng`, `redis-server`, `evebox`,
   `ntfy`, `tzsp2pcap`, `tcpreplay`, `python3`, `python3-uvicorn` + Python závislosti
   dashboardu (`fastapi`, `uvicorn`, `starlette`, `psutil`, `requests`, `urllib3`,
   `maxminddb`). **TODO: doplnit přesný seznam — chybí `requirements.txt`.**
2. Obnov `/etc/systemd/network/10-dummy0.*`, `daemon-reload`, nahoď `dummy0`.
3. Obnov konfigurace, unity a tajnosti (kroky B + C).
4. Obnov `/opt/admin-dashboard/` a `store.db` (krok A).
5. `systemctl enable --now` v pořadí dle [restart-sluzby.md](restart-sluzby.md).
6. Na MikroTiku ověř/nastav TZSP zrcadlení na novou IP serveru
   (**TODO: doplnit konfiguraci sniffer/mirror na routeru**).

## Pokud to nepomůže (eskalace)
- DB je poškozená i v záloze → `sqlite3 store.db ".recover" | sqlite3 store-new.db`.
- Nejsou žádné zálohy → smiř se se ztrátou historie; konfigurace lze zrekonstruovat z
  této dokumentace a z paměti, data alertů ne.

---

## TODO — zavést zálohování (zatím neexistuje)
- [ ] Naplánovat pravidelnou zálohu: `store.db` (přes `sqlite3 .backup`, kvůli WAL),
      `/etc/admin-dashboard/`, vlastní systemd unity, `/etc/{suricata,ntopng,redis,ntfy}`,
      `/etc/systemd/network/10-dummy0.*`, `/opt/admin-dashboard/`.
- [ ] Ukládat zálohy **mimo tento server** (jiný stroj / NAS).
- [ ] Zvážit verzování `/opt/admin-dashboard/` v gitu.
- [ ] Tento postup obnovy **otestovat nanečisto** (zatím netestováno).
