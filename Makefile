# NetWatch — provozní zkratky (DevOps lifecycle)
#   make test     unit testy parserů a klasifikátorů (bez restartu)
#   make deploy   testy → restart služby → selftest (47+ kontrol proti živé app)
#   make selftest jen selftest
#   make logs     posledních 50 řádků žurnálu
#   make status   stav služby + healthz

.PHONY: test deploy selftest restart logs status

test:
	cd /opt/admin-dashboard && sudo -u netwatch python3 -m pytest tests/ -q

restart:
	sudo systemctl restart admin-dashboard

selftest:
	sudo python3 /opt/admin-dashboard/selftest.py

deploy: test restart
	@echo "čekám 25 s na warmup (NetFlow okno, cache)…"
	@sleep 25
	$(MAKE) selftest

logs:
	sudo journalctl -u admin-dashboard -n 50 --no-pager

status:
	systemctl status admin-dashboard --no-pager | head -8
	@curl -sk https://localhost:8889/healthz; echo
