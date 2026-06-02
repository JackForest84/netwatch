"""Cross-source device inventory.

Merges:
  - MikroTik DHCP leases (hostname, IP, MAC, last-seen, dynamic/static)
  - MikroTik ARP table (active flag)
  - UniFi clients (connection method, AP/switch uplink)
  - UniFi devices (so APs/switches show up too)

Keyed by MAC address (normalized to upper-case with colons).
"""

from __future__ import annotations
from typing import Any


def _norm_mac(mac: str | None) -> str:
    if not mac:
        return ""
    return mac.upper().replace("-", ":")


def _norm_oui(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").lower()[:6]


# Manual display-name overrides keyed by IP — wins over DHCP/UniFi hostname.
# Owner-supplied device catalog (2026-06). Pozn.: sloupce Username/Password ZÁMĚRNĚ neukládáme.
_NAME_OVERRIDES: dict[str, str] = {
    # Owner-supplied IP -> display-name catalog (wins over DHCP/UniFi hostname).
    # SANITIZED for public repo — fill in YOUR devices. Display names only, no creds.
    "192.168.1.1":  "Gateway / Router",
    "192.168.1.10": "NAS",
    "192.168.1.20": "Home Assistant",
}

# Friendly overrides for OUIs we want a shorter/clearer name than the IEEE registrant.
_OUI_OVERRIDES = {
    "1c0b8b": "Ubiquiti", "847848": "Ubiquiti", "a89c6c": "Ubiquiti", "6c1ff7": "Ubiquiti",
    "bc2411": "Proxmox VM (QEMU)", "525400": "QEMU/KVM VM",
    "000678": "Denon",
}

# Common vendor-name simplifications applied to IEEE registrant strings.
_VENDOR_SIMPLIFY = [
    ("REALTEK", "Realtek"), ("TP-LINK", "TP-Link"), ("ESPRESSIF", "Espressif (ESP)"),
    ("INTEL", "Intel"), ("SAMSUNG", "Samsung"), ("APPLE", "Apple"), ("GOOGLE", "Google"),
    ("AMAZON", "Amazon"), ("MICROSOFT", "Microsoft"), ("HUAWEI", "Huawei"), ("XIAOMI", "Xiaomi"),
    ("UBIQUITI", "Ubiquiti"), ("MIKROTIK", "MikroTik"), ("ROUTERBOARD", "MikroTik"),
    ("RASPBERRY", "Raspberry Pi"), ("SHENZHEN", "Shenzhen"), ("SONOS", "Sonos"),
    ("TUYA", "Tuya"), ("SONOFF", "Sonoff"), ("AZUREWAVE", "AzureWave"),
]

# IEEE OUI database, loaded once at import. Maps "aabbcc" -> "Vendor".
_IEEE_OUI: dict[str, str] = {}


def _load_ieee_oui() -> None:
    # Prefer the freshly-downloaded list next to the app; fall back to the
    # ieee-data package snapshot (older, ~32k entries).
    import os as _os
    paths = [_os.path.join(_os.path.dirname(__file__), "oui.txt"),
             "/var/lib/ieee-data/oui.txt"]
    path = next((p for p in paths if _os.path.exists(p)), None)
    if not path:
        return
    import re as _re
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" not in line:
                continue
            m = _re.match(r"\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)", line)
            if not m:
                continue
            oui = (m.group(1) + m.group(2) + m.group(3)).lower()
            name = m.group(4).strip()
            # IEEE marks randomized/unregistered blocks as "Private" → treat as soukromá MAC
            if name.lower() == "private":
                _IEEE_OUI[oui] = "soukromá MAC"
                continue
            up = name.upper()
            for needle, nice in _VENDOR_SIMPLIFY:
                if needle in up:
                    name = nice
                    break
            else:
                for suf in [" CO.,LTD.", ",LTD.", ", INC.", " INC.", " LLC", " GMBH",
                            " CORP.", " CORPORATION", " TECHNOLOGIES", " TECHNOLOGY", " ELECTRONICS",
                            " SYSTEMS INC.", " SYSTEMS"]:
                    idx = name.upper().find(suf)
                    if idx > 0:
                        name = name[:idx]
                name = name.strip().title()[:24]
            _IEEE_OUI[oui] = name


_load_ieee_oui()


def _is_locally_administered(mac: str) -> bool:
    """bit 0x02 of the first octet set = randomized/private (locally administered) MAC."""
    h = mac.replace(":", "").replace("-", "")
    if len(h) < 2:
        return False
    try:
        return bool(int(h[1], 16) & 0x2)
    except ValueError:
        return False


def vendor_for(mac: str) -> str:
    if not mac:
        return ""
    oui = _norm_oui(mac)
    if oui in _OUI_OVERRIDES:
        return _OUI_OVERRIDES[oui]
    if oui in _IEEE_OUI:
        return _IEEE_OUI[oui]
    if _is_locally_administered(mac):
        return "soukromá MAC"   # MAC randomization (modern phones, some VMs)
    return ""


def build(mikrotik_snap: dict[str, Any], unifi_snap: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a merged device list, sorted by activity then name."""

    by_mac: dict[str, dict[str, Any]] = {}

    # 1) UniFi infrastructure devices (APs, switches) — these are special
    for d in unifi_snap.get("devices", []):
        mac = _norm_mac(d.get("mac"))
        if not mac:
            continue
        by_mac[mac] = {
            "mac": mac,
            "ip": d.get("ip"),
            "hostname": d.get("name"),
            "vendor": "Ubiquiti",
            "kind": "infra",          # AP or switch
            "infra_model": d.get("model"),
            "infra_state": d.get("state"),
            "infra_version": d.get("version"),
            "infra_uptime": d.get("uptime"),
            "wifi_uplink": None,
            "online": d.get("state") == "ONLINE",
            "source": ["unifi-device"],
            "client_type": None,
            "lease_status": None,
            "last_seen": None,
        }

    # 2) MikroTik DHCP leases
    for l in mikrotik_snap.get("leases", []):
        mac = _norm_mac(l.get("mac"))
        if not mac:
            continue
        entry = by_mac.setdefault(mac, {
            "mac": mac, "kind": "client", "source": [], "online": False,
            "vendor": "", "hostname": "", "ip": None, "infra_state": None,
        })
        entry.setdefault("source", []).append("dhcp")
        entry["ip"] = l.get("ip") or entry.get("ip")
        if not entry.get("hostname"):
            entry["hostname"] = l.get("hostname") or ""
        entry["lease_status"] = l.get("status")
        entry["lease_expires"] = l.get("expires_after")
        entry["last_seen"] = l.get("last_seen")
        entry["dhcp_dynamic"] = l.get("dynamic")
        if l.get("status") == "bound":
            entry["online"] = True

    # 3) MikroTik ARP — quick liveness signal
    arp_macs = {_norm_mac(a.get("mac")): a for a in mikrotik_snap.get("arp", []) if a.get("mac")}
    for mac, a in arp_macs.items():
        entry = by_mac.setdefault(mac, {
            "mac": mac, "kind": "client", "source": [], "online": False,
            "vendor": "", "hostname": "", "ip": a.get("ip"),
        })
        entry.setdefault("source", []).append("arp")
        if not entry.get("ip"):
            entry["ip"] = a.get("ip")
        if a.get("complete"):
            entry["online"] = True
        entry["arp_iface"] = a.get("interface")

    # 4) UniFi clients (overlays WiFi/wired connection info)
    devices_by_id = {d.get("id"): d for d in unifi_snap.get("devices", [])}
    for c in unifi_snap.get("clients", []):
        mac = _norm_mac(c.get("mac"))
        if not mac:
            continue
        entry = by_mac.setdefault(mac, {
            "mac": mac, "kind": "client", "source": [], "online": True,
            "vendor": "", "hostname": "", "ip": c.get("ip"),
        })
        entry.setdefault("source", []).append("unifi-client")
        # UniFi often has nicer client names
        if c.get("name") and (not entry.get("hostname") or entry["hostname"] == ""):
            entry["hostname"] = c["name"]
        if c.get("ip") and not entry.get("ip"):
            entry["ip"] = c["ip"]
        entry["client_type"] = c.get("type")           # WIRED / WIRELESS
        entry["online"] = True
        # Uplink (which AP/switch)
        uid = c.get("uplink_device_id")
        if uid and uid in devices_by_id:
            entry["uplink_name"] = devices_by_id[uid].get("name")
            entry["uplink_model"] = devices_by_id[uid].get("model")
        entry["connected_at"] = c.get("connected_at")

    # 5) Vendor lookup + IP-based name overrides
    for entry in by_mac.values():
        if not entry.get("vendor"):
            entry["vendor"] = vendor_for(entry["mac"])
        # IP-based display name override (wins over DHCP/UniFi hostname)
        ip_override = _NAME_OVERRIDES.get(entry.get("ip", ""))
        if ip_override:
            entry["hostname"] = ip_override
        elif not entry.get("hostname"):
            entry["hostname"] = entry["mac"]

    # Sort: infra first, then online clients (by name), then offline
    devs = list(by_mac.values())
    devs.sort(key=lambda d: (
        d.get("kind") != "infra",
        not d.get("online", False),
        (d.get("hostname") or "").lower(),
    ))
    return devs


def summarize(devices: list[dict[str, Any]]) -> dict[str, Any]:
    online = [d for d in devices if d.get("online")]
    wifi = [d for d in online if d.get("client_type") == "WIRELESS"]
    wired = [d for d in online if d.get("client_type") == "WIRED"]
    infra = [d for d in devices if d.get("kind") == "infra"]
    return {
        "total": len(devices),
        "online": len(online),
        "wifi": len(wifi),
        "wired": len(wired),
        "infra": len(infra),
        "infra_online": len([d for d in infra if d.get("online")]),
    }
