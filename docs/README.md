# Dokumentace serveru `mikrotiktraffic`

Kanonická, verzovaná pravda o tom, jak je tento self-hosted server nasazený a co dělat,
když něco spadne. Tahle složka je samostatný **git repozitář** a zároveň **Obsidian vault**.

> **Co to je za server:** domácí síťový monitoring / IDS side-car. Zrcadlí provoz
> z MikroTiku (TZSP) a analyzuje ho přes Suricata + ntopng + EveBox, plus vlastní
> dashboard **NetWatch**. Detaily viz [inventory.md](inventory.md) a
> [decisions/0001-pasivni-ids-tzsp-mirror.md](decisions/0001-pasivni-ids-tzsp-mirror.md).

---

## Jak je to uspořádané

```
dokumentace/
├── README.md            ← tenhle rozcestník
├── inventory.md         ← přehledová tabulka: služba | host | port | URL | poznámka + síť
├── decisions/           ← ADR = proč jsem něco udělal takhle (architektonická rozhodnutí)
│   └── 0001-…           ← reálný příklad + šablona pro další
├── runbooks/            ← obecné postupy napříč službami
│   ├── restart-sluzby.md
│   └── obnova-ze-zalohy.md
└── services/            ← jedna složka na každou běžící službu
    └── <sluzba>/
        ├── README.md    ← Co to je · Závislosti · Nasazení · Přístup · Zálohy · Poznámky
        └── runbook.md   ← provozní úkony: logy, restart, časté problémy
```

### Kde začít, když…
- **…chci přehled, co kde běží** → [inventory.md](inventory.md)
- **…něco spadlo a chci to nahodit** → [runbooks/restart-sluzby.md](runbooks/restart-sluzby.md)
- **…potřebuju obnovit data** → [runbooks/obnova-ze-zalohy.md](runbooks/obnova-ze-zalohy.md)
- **…řeším konkrétní službu** → `services/<sluzba>/` (README = co to je, runbook = jak to provozovat)
- **…chci vědět, proč je to postavené takhle** → [decisions/](decisions/)

---

## Jak repo používat

- **Prohlížení:** otevři složku `dokumentace/` jako vault v **Obsidianu**. Všechny odkazy
  jsou **relativní** (`../../runbooks/…`), takže fungují i mimo Obsidian (GitHub, editor, `cat`).
- **Čistý Markdown** — žádné Obsidian-only pluginy nejsou potřeba. Wiki-linky `[[…]]` se
  záměrně nepoužívají, aby dokumentace zůstala přenositelná.
- **Editace:** prostě uprav `.md` soubor a commitni (viz [Git](#git-pracovní-postup) níže).

### Kdy aktualizovat
Dokumentaci ber jako součást změny, ne jako úklid „někdy potom":

| Když uděláš tohle… | …aktualizuj tohle |
|---|---|
| přidáš/odebereš službu | `inventory.md` + nová složka v `services/` |
| změníš port / URL / binding | `inventory.md` + `services/<sluzba>/README.md` |
| změníš způsob nasazení nebo konfiguraci | `services/<sluzba>/README.md` (sekce Nasazení) |
| narazíš na nový problém a vyřešíš ho | `services/<sluzba>/runbook.md` (sekce Časté problémy) |
| uděláš zásadní rozhodnutí (proč takhle) | nový `decisions/000X-…md` |

---

## Bezpečnost — POVINNÉ

- **Žádná reálná hesla, tokeny ani klíče v žádném souboru.** Používej zástupné hodnoty:
  `<HESLO>`, `<TOKEN>`, `<API_KLIC>`. Skutečné tajnosti žijí jen na serveru v
  `/etc/admin-dashboard/*` (mode 600) a v konfiguracích služeb — **ne tady**.
- `.gitignore` blokuje `.env`, `*.key`, `*.pem`, `*.cred`, `*.pass`, `id_rsa*`, `secrets/` —
  i kdyby se sem omylem dostaly.
- Interní LAN IP, doména a porty **v dokumentaci jsou** schválně (nejsou veřejně směrovatelné
  a jsou nutné k provozu). Pokud bys repo někdy sdílel ven, projdi ho znovu.

---

## Git — pracovní postup

Tohle je **samostatný** repo (`git init` jen v `dokumentace/`, ne celý server).
Git identita je lokální a neutrální: `Docs <noreply@example.com>`.

```bash
# na serveru, ve složce ~/dokumentace
git add -A
git commit -m "docs: <co jsem změnil>"
```

Stažení na PC a otevření v Obsidianu je popsané na konci tohohle souboru —
viz též hlavní instrukce v chatu. Rychlý odkaz:

```bash
git clone jakub@192.168.50.36:dokumentace ~/Obsidian/dokumentace
```
