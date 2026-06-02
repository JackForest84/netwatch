# redis

## Co to je
In-memory key-value úložiště. Slouží jako **backing store pro [ntopng](../ntopng-wan/README.md)**
— ntopng si do něj ukládá živá počítadla a flows. Není to obecná aplikační cache pro nic
jiného; existuje kvůli ntopng.

## Závislosti
- Samostatný démon, nepotřebuje ostatní části stacku.
- **Konzument:** ntopng (`ntopng-wan.service` má `After=`/`Wants=redis-server.service`).

## Nasazení
- Unit: standardní balíčkový `redis-server.service` (`/usr/lib/systemd/system/`).
- Konfigurace: `/etc/redis/redis.conf`, klíčové hodnoty:
  - `bind 127.0.0.1 -::1` → **jen localhost** (ven nedostupné)
  - `port 6379`
  - `maxmemory 512mb`, `maxmemory-policy allkeys-lru` (při zaplnění zahazuje nejstarší klíče)
- redis 7.0.15.

## Přístup
- **Jen localhost:** `127.0.0.1:6379` (+ `::1`). Žádné heslo, spoléhá na localhost-only bind.
- CLI: `redis-cli` (např. `redis-cli ping` → `PONG`).

## Zálohy
- **Není potřeba zálohovat** — obsahuje jen přepočitatelná data ntopng. Po smazání/restartu
  se naplní znovu z živého provozu.
- Zazálohuj nanejvýš `/etc/redis/redis.conf`, pokud bys měnil nastavení.

## Známé problémy / poznámky
- Když redis nejede, **ntopng se chová divně nebo nenaběhne** — řeš redis jako první.
- `allkeys-lru` + 512 MB strop znamená, že redis nikdy nepřeteče RAM, ale při náporu může
  zahazovat starší klíče (pro ntopng v pořádku).
- Bind je schválně jen localhost — **nikdy ho neotevírej do LAN/WAN** bez hesla.
