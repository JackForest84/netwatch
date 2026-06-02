# Runbook — Restart služeb

Jak bezpečně restartovat jednu službu nebo celý monitorovací stack, s ohledem na pořadí
závislostí.

## Kdy použít (příznaky)
- Web UI nějaké služby neodpovídá (ntopng :3000, EveBox :5636, dashboard :8889, ntfy :8090).
- Dashboard hlásí, že integrace nebo data nejedou.
- Po změně konfigurace (`suricata.yaml`, `ntopng.conf`, kód dashboardu).
- Alerty/flows přestaly přibývat, ale server jako takový běží.

## Postup

### 1) Nejdřív zjisti stav a podívej se do logu
```bash
systemctl status admin-dashboard suricata-wan ntopng-wan evebox-local tzsp-replay ntfy redis-server
journalctl -u <sluzba> -n 50 --no-pager       # poslední řádky logu konkrétní služby
```

### 2) Restart jedné služby
```bash
sudo systemctl restart <sluzba>
systemctl status <sluzba>                       # ověř, že je 'active (running)'
```
Názvy unitů: `tzsp-replay`, `suricata-wan`, `ntopng-wan`, `evebox-local`,
`admin-dashboard`, `ntfy`, `redis-server`.

### 3) Restart celého stacku — DODRŽ POŘADÍ
Závislosti: `dummy0` → `tzsp-replay` → `suricata-wan` → `evebox-local`;
`redis-server` → `ntopng-wan`; `admin-dashboard` konzumuje všechno, jde poslední.

```bash
sudo systemctl restart redis-server
sudo systemctl restart tzsp-replay      # nahodí dummy0 a přehrávání TZSP
sleep 3
sudo systemctl restart suricata-wan     # čeká, až je dummy0 UP (má to v ExecStartPre)
sudo systemctl restart ntopng-wan
sudo systemctl restart evebox-local
sudo systemctl restart ntfy
sudo systemctl restart admin-dashboard  # poslední — závisí na ostatních
```

### 4) Ověření, že stack zase žije
```bash
# přibývají Suricata události?
sudo tail -f /var/log/suricata/eve.json          # Ctrl-C pro konec

# poslouchají porty?
sudo ss -tulpn | grep -E ':3000|:5636|:8889|:8090|:6379|:37008'

# zdraví dashboardu (souhrn integrací, RSS, DB)
curl -sk https://192.168.50.36:8889/api/health
```

## Pokud to nepomůže (eskalace)
1. **Konkrétní služba** padá hned po startu → otevři její runbook v
   `../services/<sluzba>/runbook.md`, tam jsou specifické chyby.
2. **`suricata-wan` se nerozjede** → skoro vždy je problém v `dummy0` nebo `tzsp-replay`.
   Ověř `ip -o link show dummy0` (má být `UP`/`UNKNOWN`) a `systemctl status tzsp-replay`.
3. **Dashboard běží, ale data ne** → jde o integrace, ne o systemd. Viz
   [../services/admin-dashboard/runbook.md](../services/admin-dashboard/runbook.md).
4. **Alerty jsou nula, flows běží** → podezření na `HOME_NET`, viz
   [../services/suricata-wan/runbook.md](../services/suricata-wan/runbook.md).
5. Když je rozbité i `systemctl`/boot → konzole VM (Proxmox/hypervizor) a `journalctl -b`.
