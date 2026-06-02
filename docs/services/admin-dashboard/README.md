# admin-dashboard (NetWatch)

## Co to je
Vlastní webový dashboard **NetWatch** — sjednocený pohled na domácí síť a bezpečnost.
FastAPI + Jinja2 + Tailwind, běží přes uvicorn na **HTTPS :8889**. Má 7 záložek
(Přehled, Bezpečnost, Síť, DNS, Zařízení, Mapa, Služby) a agreguje data z Suricaty,
ntopng, MikroTiku, UniFi, AdGuardu a threat-intel služeb. Je reverzně proxovaný na
veřejné `https://monitoring.example.com/`.

Kód: `/opt/admin-dashboard/` (`app.py` ~1700 LOC + klientské moduly). **Není ve vlastním
gitu** — viz Poznámky.

## Závislosti
**Běží jako uživatel `netwatch`** (uid 994), ne root.

- **Python (systémové balíčky, žádný venv):** `fastapi`, `uvicorn`, `starlette`, `psutil`,
  `requests`, `urllib3`, `maxminddb`, `itsdangerous`. ⚠️ **Není `requirements.txt`** — viz Poznámky.
- **Perzistence:** SQLite `/var/lib/admin-dashboard/store.db` (WAL, 30denní retence).
- **Integrace** (konfigurace v `/opt/admin-dashboard/config.py`, tajnosti v
  `/etc/admin-dashboard/*`):
  | Integrace | Cíl | Tajnost (soubor, jen název) |
  |---|---|---|
  | Suricata | `/var/run/suricata-command.socket` | — (práva přes `suricata-socket-perms.path`) |
  | ntopng REST | `http://127.0.0.1:3000` (uživatel `admin`) | `ntopng.cred` |
  | MikroTik REST | `https://192.168.50.1` (uživatel `dashboard`) | `mikrotik.cred` |
  | UniFi Integration API | `https://192.168.50.55:11443` | `unifi.key` |
  | UniFi legacy (cookie) | `https://192.168.50.55:11443` | `unifi.user`, `unifi.pass` |
  | AdGuard Home ×2 | instance `.11` a `.21` | `adguard.json` |
  | VirusTotal | API | `vt.key` |
  | AbuseIPDB | API | `abuseipdb.key` |
  | ntfy push | `http://127.0.0.1:8090` (uživatel `admin`) | `ntfy-admin.pass` |
- **`suricata-socket-perms.path`** — systemd path-watcher, který po (re)startu Suricaty
  nastaví práva socketu tak, aby na něj `netwatch` dosáhl (chgrp `netwatch`, chmod 660).

## Nasazení
- Unit: `/etc/systemd/system/admin-dashboard.service`, **`User=netwatch`**, `Restart=always`,
  `WorkingDirectory=/opt/admin-dashboard`.
- Spuštění:
  ```
  python3 -m uvicorn app:app --host 0.0.0.0 --port 8889 \
    --ssl-keyfile /etc/admin-dashboard/cert.key \
    --ssl-certfile /etc/admin-dashboard/cert.pem \
    --proxy-headers --forwarded-allow-ips=*
  ```
- **systemd hardening** (silný): `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`,
  `ReadWritePaths=/var/lib/admin-dashboard`, `SystemCallFilter=@system-service`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`.
  ⚠️ **Do `SystemCallFilter` NEpřidávej `~@resources`** — zabilo by to (SIGSYS) Python
  subproces `suricatasc`. `AF_NETLINK` je potřeba pro psutil čítače.
- **Frontend:** Tailwind se kompiluje **lokálně** do `static/app.css` (CDN odstraněno).
  Rebuild: `tailwindcss -i input.css -o static/app.css --minify`.
- **Změna kódu = restart:** po úpravě v `/opt/admin-dashboard/` udělej
  `sudo systemctl restart admin-dashboard`.

## Přístup
- **Lokálně:** https://192.168.50.36:8889 (self-signed cert, 10 let — prohlížeč varuje).
- **Z internetu:** https://monitoring.example.com (přes externí reverzní proxy — viz Poznámky).
- **Přihlášení:** formulář na `/login` (uživatel `admin`, heslo v
  `/etc/admin-dashboard/dashboard.cred`, `<HESLO>`). Po přihlášení se nastaví podepsaná
  **session cookie** `nw_session` (HttpOnly, Secure, SameSite=Lax, platnost 30 dní),
  odhlášení přes `/logout`. Formulář má správné `autocomplete` atributy → **Proton Pass
  nabídne uložení i autofill**. Podpisový klíč: `/etc/admin-dashboard/session.key` (mode 600).
  Per-IP ochrana proti brute-force (10 chyb / 5 min → 429). Nepřihlášený požadavek →
  redirect na `/login`, `/api/*` vrací `401`. Změna z Basic Auth: viz ADR
  [0002](../../decisions/0002-prihlaseni-formularem.md).
- **Zdraví:** `curl -sk https://192.168.50.36:8889/api/health` → JSON s `db_mb`, `wal_mb`,
  `threads`, `rss_mb`, stavem integrací a stářím posledního alertu.

## Zálohy
**Kritické — zálohovat!** (tajnosti a kód se nedají „odvodit"):
`/etc/admin-dashboard/` (klíče, hesla, cert) · `/var/lib/admin-dashboard/store.db` ·
`/opt/admin-dashboard/` (kód) · unit soubor. Postup: [obnova-ze-zalohy.md](../../runbooks/obnova-ze-zalohy.md).

## Známé problémy / poznámky
- **Per-device internet (od 2026-06):** reálný per-device internetový provoz z **NetFlow v9**
  (MikroTik Traffic-Flow → `netflow_collector.py`, vlákno na **udp/2055** → `store.db`
  tabulka `device_inet` → `/api/device-inet` → panel „🏆 Provoz po zařízeních" se jmény).
  Download i upload atribuovaný i přes NAT (pole 226). IPv4 only. Panel má **filtr období**
  (1h…boot, společný s kartou Provoz). Jména zařízení z **katalogu** `inventory._NAME_OVERRIDES`
  (IP→název, ~65 položek od majitele; **hesla se neukládají**). WAN+VPN provoz sjednocen
  do jedné karty „Provoz" s filtrem. Detail: ADR
  [0007](../../decisions/0007-per-device-netflow.md).
- **Topologie (od 2026-06):** záložka Mapa ukazuje **kurátorovanou hierarchii** (potvrzenou
  majitelem, ADR [0006](../../decisions/0006-topologie-hierarchie.md)), ne auto-discovery
  „naplocho": Internet → MikroTik (LTE záloha · 2.5G) → {DNS ×2, Monitoring .30 (port 3),
  hlavní switch 8 PoE} → {3× AP WiFi 7, koncový switch 5}. Render = deterministický strom
  shora dolů (`d3.tree`, karty + odznaky + stavové barvy).
- **Výsledek / dopad (od 2026-06):** panel „Výsledek" koreluje IDS detekce s firewall
  verdiktem (`/api/outcome`): detekováno → **potvrzeno zahozeno** → prošlo na službu (0 — žádný
  aktivní port-forward; jediná ingress = VPN). Pozor na výklad „≈87 %": je to **překryv s firewall
  logem** (kolik detekovaných IP umíme dohledat i v dropech), **ne „úspěšnost blokování"**; zbytek
  je mezera v logování (MikroTik loguje jen `log=yes` pravidla + `/log` se při náporu přepisuje),
  **ne průnik** — reálný dopad je „prošlo na službu" = 0. Vystavený povrch se tahá živě z MikroTiku
  (`/ip/firewall/nat`). Záměrně **bez Wazuhu** (host vrstva = samostatný projekt). Detail:
  ADR [0005](../../decisions/0005-vysledek-korelace-vs-wazuh.md).
- **Časový filtr Bezpečnosti + DNS (od 2026-06):** obě záložky mají vlastní řádek period-chipů
  (1h/6h/24h/7d/30d). Bezpečnost: `/api/security-summary?hours=` + `hours` v outcome / recent-alerts /
  wall-of-shame. DNS: vlastní **hodinová historie** vzorkovaná z AdGuardu (vlákno `_dns_history_sampler`,
  bez extra HTTP) do tabulky `dns_history` → `/api/dns-history` — AdGuard API umí jen pevné okno, tak
  si historii sbíráme sami **dopředu**. Detail: ADR [0008](../../decisions/0008-dns-hodinova-historie.md).
- **Kompletní záznam dropů (od 2026-06):** firewall dropy se sbírají přes **remote syslog**
  (MikroTik → `udp/5514` → `firewall_syslog.py`, vlákno), ne ztrátovým pollingem `/rest/log`;
  blocklist/scanner dropy se nově logují (prefix `IN_DENY_WAN`). Tím se Detekováno ↔ Zahozeno
  v „Výsledku" srovná na ~100 % (o každé IP lze říct, čím skončila). Vyžaduje pár příkazů na
  MikroTiku (v ADR). Detail: ADR [0009](../../decisions/0009-firewall-drop-syslog.md).
- **Klasifikace alertů (od 2026-06):** alerty se třídí podle **záměru** (`classify_intent`):
  blocklist/reputace · skeny · exploit · průzkum · anomálie. Donut „Záměr alertů" + headline
  „k řešení vs blocklist radiation" oddělí reálný signál od internetové radiace (většina
  objemu jsou očekávané zásahy z Dshield/Spamhaus/CINS, ne false-positives). Detail a obhajoba:
  ADR [0004](../../decisions/0004-klasifikace-alertu.md).
- **Metriky provozu (od 2026-06):** ukazujeme jen **WAN (ether5)** a **VPN** countery
  z routeru — jediná čísla o objemu, kterým lze věřit (endpoint `/api/internet-usage`,
  tento/minulý měsíc + 24h/7d/30d). Per-device a „LAN download/upload" jsou **záměrně
  vynechané** (nešly spolehlivě změřit: ntopng na `ens18` vidí jen server+router, MikroTik
  per-IP/Traffic-Flow je vypnutý). Detail a obhajoba: ADR
  [0003](../../decisions/0003-model-metrik-provozu.md). Reálný per-device = zapnout
  MikroTik Traffic-Flow.
- **Kód není ve vlastním gitu.** TODO: zvážit `git init` v `/opt/admin-dashboard/`.
- **Chybí `requirements.txt`.** TODO: vygenerovat (`pip freeze`) — jinak je obnova na čistém
  stroji hádání verzí.
- **Reverzní proxy je externí** (na tomto serveru nic na 80/443). TODO: doplnit, kde
  `monitoring.example.com` proxy/tunel běží — viz [inventory.md](../../inventory.md).
- Pozadí běží v ~5–6 vláknech (persist alertů/zařízení, enrichment VT/Abuse, parser
  firewall logu, notify pravidla, traffic snapshoty). Stav viz `/api/health`.
- Dědí omezení detekce aplikační vrstvy ze Suricaty (ADR [0001](../../decisions/0001-pasivni-ids-tzsp-mirror.md)).
