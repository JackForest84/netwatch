# ntopng-wan

## Co to je
Analýza síťových toků (flow monitoring) s webovým UI. ntopng 5.2.1 sleduje provoz na
**živém** rozhraní `ens18` (pozor: **ne** `dummy0`), ukazuje top talkery, protokoly,
geolokaci a historii. Dashboard NetWatch z něj navíc tahá data přes REST API.

## Závislosti
- **[redis](../redis/README.md)** — ntopng si do něj ukládá živá počítadla/flows.
  Unit má `After=`/`Wants=redis-server.service`.
- **GeoIP** databáze v `/usr/share/ntopng/httpdocs/geoip/` (symlink na `/var/lib/GeoIP/`,
  plněno `geoipupdate` timerem).
- **Konzument:** [admin-dashboard](../admin-dashboard/README.md) volá ntopng REST API
  (`http://127.0.0.1:3000`, uživatel `admin`).

## Nasazení
- Unit: `/etc/systemd/system/ntopng-wan.service`, **běží jako root**, `Restart=always`.
- `ExecStart`: `/usr/sbin/ntopng /etc/ntopng/ntopng.conf`.
- Konfigurace `/etc/ntopng/ntopng.conf`: `-i=ens18`, web na portu `3000`,
  PID `/var/run/ntopng.pid`, data v `/var/lib/ntopng/`.
- Stock `ntopng.service` je **vypnutý** — používá se jen tahle `-wan` varianta.

## Přístup
- **Web UI:** http://192.168.50.36:3000 (bind `0.0.0.0:3000`).
- **Login:** uživatel `admin`, heslo viz `/etc/admin-dashboard/ntopng.cred` (`<HESLO>`).
  Default po čisté instalaci bývá `admin`/`admin` — pokud platí, **změň ho**.
- Naslouchá i UDP 37007 (interní ntopng).

## Zálohy
- Konfiguraci `/etc/ntopng/ntopng.conf` + unit. Data v `/var/lib/ntopng/` jsou převážně
  přepočitatelná z živého provozu — kritická nejsou.

## Známé problémy / poznámky
- ntopng analyzuje `ens18` (živá LAN), kdežto Suricata `dummy0` (přehrané WAN zrcadlo) —
  jsou to **dva různé pohledy**, nepleť si je.
- Při startu závisí na redisu; když redis nejede, ntopng se chová divně nebo nenaběhne.
- Heslo do ntopng drží i dashboard v `ntopng.cred` — při změně hesla aktualizuj **obojí**.
