"""AI vysvětlení Suricata signatur — Claude Haiku přes /v1/messages (vlna 3).

Záměrně raw HTTP přes requests: oficiální `anthropic` SDK vyžaduje pydantic v2,
který by rozbil pinned fastapi 0.101 (pydantic v1, viz requirements.txt).
Klíč: /etc/admin-dashboard/anthropic.key (0600). Bez klíče vrací configured=False
a UI tlačítka se nenabízejí. Odpovědi se cachují per signatura (signatury se
masivně opakují → náklady prakticky nulové; Haiku 4.5 = $1/$5 za MTok).
"""
from __future__ import annotations

import logging
import time

import requests

import config
from store import store

log = logging.getLogger("netwatch.ai")

API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-haiku-4-5"

SYSTEM = (
    "Jsi síťový bezpečnostní analytik. Uživatel je domácí IT admin s pasivním "
    "Suricata IDS (čte zrcadlený WAN provoz za NAT). Jeho síť: MikroTik firewall, "
    "ŽÁDNÉ port-forwardy do internetu, jediný ingress je WireGuard VPN. "
    "Vysvětli zadanou IDS signaturu česky, stručně, bez markdownu, ve 3 bodech: "
    "1) CO DETEKUJE: co signatura znamená technicky. "
    "2) VERDIKT: jde v jeho situaci (zavřený perimetr) typicky o plošný internetový "
    "šum/sken, nebo o něco, co má řešit? "
    "3) CO ZKONTROLOVAT: max 2 konkrétní kroky. Celkem do 120 slov."
)


def explain(signature: str, category: str = "") -> dict:
    if not config.ANTHROPIC_API_KEY:
        return {"configured": False,
                "hint": "Vlož Anthropic API klíč do /etc/admin-dashboard/anthropic.key (chmod 600, vlastník netwatch)."}
    key = signature.strip()[:300]
    if not key:
        return {"configured": True, "error": "prázdná signatura"}
    cached = store._query(
        "SELECT explanation, created_at FROM ai_explanations WHERE signature = ?", (key,))
    if cached:
        return {"configured": True, "cached": True,
                "explanation": cached[0]["explanation"], "created_at": cached[0]["created_at"]}
    try:
        r = requests.post(API_URL, timeout=30, headers={
            "x-api-key": config.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }, json={
            "model": MODEL,
            "max_tokens": 700,
            "system": SYSTEM,
            "messages": [{"role": "user",
                          "content": f"Signatura: {key}\nKategorie: {category or '?'}"}],
        })
        if r.status_code == 401:
            return {"configured": True, "error": "Neplatný API klíč (anthropic.key)"}
        if r.status_code == 429:
            return {"configured": True, "error": "Rate limit — zkus to za chvíli"}
        if r.status_code >= 500 or r.status_code == 529:
            return {"configured": True, "error": f"API přetížené ({r.status_code}) — zkus to za chvíli"}
        r.raise_for_status()
        data = r.json()
        text = "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text").strip()
        if not text:
            return {"configured": True, "error": "prázdná odpověď modelu"}
        store._exec(
            "INSERT OR REPLACE INTO ai_explanations (signature, explanation, model, created_at) "
            "VALUES (?,?,?,?)", (key, text, MODEL, time.time()))
        return {"configured": True, "cached": False, "explanation": text}
    except requests.Timeout:
        return {"configured": True, "error": "timeout (30 s)"}
    except Exception as e:
        log.warning("ai explain selhal", exc_info=True)
        return {"configured": True, "error": str(e)[:120]}
