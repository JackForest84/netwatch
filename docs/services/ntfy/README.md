# ntfy

## Co to je
Self-hosted push-notifikační server (ntfy 2.23.0). Dashboard NetWatch do něj posílá
bezpečnostní a informační notifikace, které pak chodí na telefon/desktop přes ntfy klienta.
Náhrada za veřejné ntfy.sh, ať data zůstanou doma.

## Závislosti
- Samostatná služba, nepotřebuje ostatní části stacku.
- **Producent zpráv:** [admin-dashboard](../admin-dashboard/README.md) publikuje do témat
  `mikrotiktraffic-security` a `mikrotiktraffic-info` (uživatel `admin`,
  heslo `/etc/admin-dashboard/ntfy-admin.pass`).

## Nasazení
- Unit: standardní balíčkový `ntfy.service` (`User=ntfy`), `ExecStart=/usr/bin/ntfy serve`,
  `Restart=on-failure`, `CAP_NET_BIND_SERVICE`.
- Konfigurace: `/etc/ntfy/server.yml` (server) + `/etc/ntfy/client.yml` (klient/publish).
- Klíčové volby `server.yml` (netajné):
  - `base-url: http://192.168.50.36:8090`, `listen-http: ":8090"`
  - `auth-default-access: deny-all` → odběr témat **vyžaduje přihlášení**
  - `auth-file: /var/cache/ntfy/user.db` (uživatelé a ACL)
  - `cache-file: /var/cache/ntfy/cache.db`, `cache-duration: 168h` (7 dní historie)
  - `enable-signup: false` (žádná veřejná registrace)

## Přístup
- **Web/API:** http://192.168.50.36:8090 (bind `*:8090`).
- **Auth:** `deny-all` by default — uživatelé se spravují přes `ntfy user` /
  `ntfy access` (CLI). Hesla uživatelů jsou v `/etc/admin-dashboard/ntfy-admin.pass`
  a `ntfy-user.pass` (`<HESLO>`).

## Zálohy
- `/etc/ntfy/server.yml` + `client.yml` (konfigurace).
- `/var/cache/ntfy/user.db` (uživatelé/ACL) — bez něj se musí účty vytvořit znovu.
- `cache.db` (historie zpráv) je krátkodobá, zálohovat netřeba.

## Známé problémy / poznámky
- Data jsou v `/var/cache/` — pozor, `cache` adresáře někdy čistí systémová údržba;
  `user.db` je tu ale záměrně a maže se jen ručně.
- `base-url` je nastavená na interní IP — pro doručování přes internet by se musela změnit
  a vyřešit reverzní proxy (zatím není potřeba).
