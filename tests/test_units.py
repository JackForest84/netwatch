"""Unit testy čistých funkcí NetWatch — `make test` / pytest.

Testují parsery a klasifikátory bez sítě a bez restartu služby. Import modulů
otevře živou store.db (idempotentní schema), proto pouštět jako uživatel netwatch.
"""
import struct
import sys
import time

sys.path.insert(0, "/opt/admin-dashboard")

from alerts import classify_intent
from geoip import country_to_flag, _is_private
from firewall_log import _parse_entry
from netflow_collector import NetflowCollector
from store import _bucket_start


# ---------- classify_intent (ADR 0004) ----------

def test_intent_blocklist():
    assert classify_intent("ET DROP Dshield Block Listed Source group 1") == "blocklist"
    assert classify_intent("ET CINS Active Threat Intelligence Poor Reputation IP") == "blocklist"

def test_intent_scan():
    assert classify_intent("ET SCAN NMAP -sS window 1024") == "scan"

def test_intent_attack():
    assert classify_intent("ET EXPLOIT Apache log4j RCE attempt") == "attack"
    assert classify_intent("ET MALWARE Win32/Trojan CnC checkin") == "attack"

def test_intent_fallback_category():
    assert classify_intent(None, "Misc Attack") == "blocklist"
    assert classify_intent("something unknown", "") == "other"


# ---------- geoip helpers ----------

def test_country_flag():
    assert country_to_flag("CZ") == "🇨🇿"
    assert country_to_flag(None) == "🌐"
    assert country_to_flag("X") == "🌐"

def test_private_nets():
    assert _is_private("192.168.1.1")
    assert _is_private("203.0.113.7")
    assert not _is_private("8.8.8.8")


# ---------- MikroTik firewall log parser ----------

def test_fw_parse_drop():
    e = {"time": "12:00:00", "topics": "firewall,info",
         "message": "IN_DENY_WAN input: in:ether5 out:(unknown 0), proto TCP (SYN), 1.2.3.4:55555->203.0.113.7:23, len 40"}
    d = _parse_entry(e)
    assert d is not None
    assert d["src_ip"] == "1.2.3.4"
    assert d["dst_port"] == 23
    assert d["proto"] == "TCP"
    assert d["iface_in"] == "ether5"

def test_fw_parse_non_firewall_skipped():
    assert _parse_entry({"time": "1:1:1", "topics": "dhcp,info", "message": "lease granted"}) is None


# ---------- NetFlow v9 parser (golden packet, field 226 = postNAT dst) ----------

def _nf_header(count: int) -> bytes:
    return struct.pack(">HHIIII", 9, count, 1000, int(time.time()), 1, 42)

def _flowset(fsid: int, body: bytes) -> bytes:
    return struct.pack(">HH", fsid, 4 + len(body)) + body

def _template(tid: int, fields: list) -> bytes:
    b = struct.pack(">HH", tid, len(fields))
    for ft, fl in fields:
        b += struct.pack(">HH", ft, fl)
    return b

def _ip(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))

def test_netflow_upload_and_download_attribution():
    c = NetflowCollector()
    fields = [(1, 4), (8, 4), (12, 4), (226, 4)]  # IN_BYTES, SRC, DST, PNAT_DST
    c._parse(_nf_header(1) + _flowset(0, _template(256, fields)))
    assert (42, 256) in c.templates

    # upload: LAN zařízení → internet
    rec_up = struct.pack(">I", 1000) + _ip("192.168.1.100") + _ip("8.8.8.8") + _ip("0.0.0.0")
    # download přes NAT: src=internet, dst=WAN IP, pole 226 = skutečné zařízení
    rec_down = struct.pack(">I", 5000) + _ip("142.250.1.1") + _ip("203.0.113.7") + _ip("192.168.1.100")
    c._parse(_nf_header(2) + _flowset(256, rec_up + rec_down))

    assert c.up.get("192.168.1.100") == 1000
    assert c.down.get("192.168.1.100") == 5000

def test_netflow_garbage_is_ignored():
    c = NetflowCollector()
    c._parse(b"\x00\x01garbage")          # špatná verze
    c._parse(_nf_header(0)[:10])           # useknutá hlavička
    assert not c.up and not c.down


# ---------- lokální denní buckety (audit: UTC půlnoc lhala) ----------

def test_bucket_start_local_midnight():
    lt = time.localtime()
    midnight = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))
    assert _bucket_start(time.time(), 86400) == int(midnight)

def test_bucket_start_hourly_unchanged():
    ts = 1781000000.0
    assert _bucket_start(ts, 3600) == int(ts // 3600) * 3600
