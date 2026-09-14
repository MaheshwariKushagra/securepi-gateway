# SecurePi Gateway
#
# `make test` runs the project's pytest-compatible unittest suite
# (ENHANCEMENT-PLAN.md step 1.1): the DPI addon's rule logic (step 5.9),
# app/correlation.py's six detection signals (positive, negative, dedup
# and regression tests, all against a real temp SQLite DB - see
# tests/fixtures.py), and app/ingest.py's Suricata/AdGuard parsing
# against synthetic eve.json/querylog fixtures. Every test runs off
# synthetic or in-memory data - never against the live gateway's
# database or a real device.
#
# `make deploy` and `make status` (step 0.2) reach the live gateway over
# the management link (192.168.2.0/24 - see session-start.sh and
# GATEWAY-SETUP-RUNBOOK.md). No SSH alias is configured, so the host is
# spelled out here the same way session-start.sh and mac-tunnel.sh do.
#
# `deploy` only ever touches app/ (the console, ingest and correlation
# engine, deployed flat into /opt/securepi - the code uses plain imports
# like `import correlation`, not a package layout, so the destination
# must stay flat, not app/app/). It deliberately does NOT rsync gateway/
# or dpi/:
#   - gateway/hostapd.conf's committed copy has its passphrase redacted
#     (see README "Security and privacy"); overwriting the live file
#     with it would take the AP's real Wi-Fi password out from under
#     every connected device.
#   - gateway/nftables.conf and the DPI components each already have
#     their own careful, manual deploy paths (GATEWAY-SETUP-RUNBOOK.md
#     "Lockout insurance", dpi/deploy-dpi.sh) because a firewall or CA
#     mistake is a lockout or a privacy-scope risk, not just a bug.
# Restart order (ingest, then engine, then web) matches every deploy
# logged in ENHANCEMENT-PLAN.md - ingest owns schema-adjacent state the
# other two read.
#
# Not yet verified against a live run: the gateway was unreachable
# (management link down) when this target was written. Confirm the
# rsync destination and restart order the next time the gateway is up,
# per this step's own exit criterion.

.PHONY: test deploy status

GATEWAY_HOST := maheshwari@192.168.2.5
GATEWAY_APP  := /opt/securepi

test:
	python3 -m unittest discover -s tests -p 'test_*.py' -v

deploy:
	rsync -az --delete --exclude '__pycache__' --exclude '*.pyc' \
		--rsync-path="sudo rsync" \
		app/ $(GATEWAY_HOST):$(GATEWAY_APP)/
	ssh $(GATEWAY_HOST) 'sudo systemctl restart securepi-ingest securepi-engine securepi-web'
	ssh $(GATEWAY_HOST) 'sudo securepi status'

status:
	ssh $(GATEWAY_HOST) 'sudo securepi status'
