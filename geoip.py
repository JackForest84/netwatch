"""GeoIP lookup (MaxMind GeoLite2) + private-IP helper + country->flag emoji."""
from __future__ import annotations
import logging
import re
from pathlib import Path
from typing import Any
import maxminddb

GEOIP_CITY = Path("/var/lib/GeoIP/GeoLite2-City.mmdb")
GEOIP_COUNTRY = Path("/var/lib/GeoIP/GeoLite2-Country.mmdb")
GEOIP_ASN = Path("/var/lib/GeoIP/GeoLite2-ASN.mmdb")


PRIVATE_NETS = (
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^fe80:"),
    re.compile(r"^::1$"),
)


def _is_private(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_NETS)


class GeoLookup:
    def __init__(self) -> None:
        self.country = self._open(GEOIP_COUNTRY)
        self.city = self._open(GEOIP_CITY)
        self.asn = self._open(GEOIP_ASN)

    def _open(self, path: Path):
        try:
            return maxminddb.open_database(str(path))
        except FileNotFoundError:
            return None
        except Exception:
            logging.getLogger("netwatch").warning("GeoIP DB %s nelze otevřít", path, exc_info=True)
            return None

    def lookup(self, ip: str) -> dict[str, Any]:
        out: dict[str, Any] = {"country": None, "country_code": None, "asn": None, "asn_org": None,
                                "lat": None, "lon": None, "city": None}
        if not ip or _is_private(ip):
            return out
        if self.country:
            try:
                r = self.country.get(ip)
                if r and "country" in r:
                    out["country"] = r["country"]["names"].get("en")
                    out["country_code"] = r["country"]["iso_code"]
            except Exception:
                pass
        if self.city:
            try:
                r = self.city.get(ip)
                if r:
                    loc = r.get("location") or {}
                    out["lat"] = loc.get("latitude")
                    out["lon"] = loc.get("longitude")
                    city = (r.get("city") or {}).get("names", {})
                    out["city"] = city.get("en")
                    if not out.get("country"):
                        out["country"] = (r.get("country") or {}).get("names", {}).get("en")
                        out["country_code"] = (r.get("country") or {}).get("iso_code")
            except Exception:
                pass
        if self.asn:
            try:
                r = self.asn.get(ip)
                if r:
                    out["asn"] = r.get("autonomous_system_number")
                    out["asn_org"] = r.get("autonomous_system_organization")
            except Exception:
                pass
        return out


def country_to_flag(code: str | None) -> str:
    if not code or len(code) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(code[0].upper()) - ord("A")) + chr(0x1F1E6 + ord(code[1].upper()) - ord("A"))


geo = GeoLookup()
