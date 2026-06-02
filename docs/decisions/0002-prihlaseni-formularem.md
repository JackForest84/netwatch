# ADR 0002 — Přihlášení do NetWatch formulářem místo HTTP Basic Auth

- **Stav:** přijato
- **Datum:** 2026-06-01
- **Týká se služeb:** [admin-dashboard](../services/admin-dashboard/README.md)

## Kontext
Dashboard NetWatch používal **HTTP Basic Auth** (`BasicAuthMiddleware`). Basic Auth je
nativní popup prohlížeče, ne formulář — správci hesel (konkrétně **Proton Pass**) ho neumí
spolehlivě vyplnit a hlavně **nikdy nenabídnou „uložit heslo"**. Důsledek: heslo se psalo
ručně, což vedlo k překlepům a opakovaně i k aktivaci brute-force zámku (`auth lockout`
v logu, 429 na 5 minut — viz reálné výskyty z `192.168.50.103`).

## Rozhodnutí
Nahradit Basic Auth **formulářovým přihlášením se session cookie**:

- Routy `GET/POST /login` a `GET /logout`; šablona `templates/login.html` s poli
  `autocomplete="username"` a `autocomplete="current-password"`.
- Po úspěšném přihlášení se nastaví podepsaná cookie `nw_session`
  (`itsdangerous.URLSafeTimedSerializer`) s atributy **HttpOnly, Secure, SameSite=Lax**
  a platností **30 dní**. Podpisový klíč: `/etc/admin-dashboard/session.key`
  (mode 600, vlastník `netwatch`).
- `AuthMiddleware` nahradila `BasicAuthMiddleware`: bez platné cookie → redirect na
  `/login`, u `/api/*` vrací `401`. Veřejné cesty: `/login`, `/logout`, `/static/*`,
  `/favicon.ico`.
- **Zachováno:** stejné jméno/heslo (`dashboard.cred`), per-IP brute-force lockout
  (nově se počítá až na `POST /login`, ne na každý nepřihlášený požadavek) a všechny
  bezpečnostní hlavičky.

## Důsledky
**Dobré:**
- Proton Pass nabídne uložení i autofill → konec ručního psaní a náhodných zámků.
- Čistší chování: prohlížení odhlášeným uživatelem už se nepočítá jako neúspěšný pokus.
- Plná kontrola nad cookie (HttpOnly/Secure/SameSite, expirace).

**Špatné / na co si dát pozor:**
- Přibyla závislost `itsdangerous` (byla už nainstalovaná jako součást Starlette).
- Nový tajný soubor `session.key` — zálohovat a při migraci obnovit (bez něj se existující
  session zneplatní; přihlášení ale funguje dál). Viz
  [obnova-ze-zalohy.md](../runbooks/obnova-ze-zalohy.md).
- `/static/*` je nově přístupná i nepřihlášeně (jen CSS a `hero.png`, nic citlivého).
- Po nasazení může prohlížeč držet starý Basic Auth v cache — řeší zavření záložky/okna.
- Záloha původního `app.py`+`config.py` před změnou: `~/nw-auth-backup/` (rollback = vrátit
  oba soubory a restartovat službu).
