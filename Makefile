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
# No --delete: a --dry-run against the live gateway (14 September 2026,
# once it was reachable) showed the obvious destination and no surprises
# in the file set, but also showed --delete would have wiped every
# .bak-*-<step>-<timestamp> file on the gateway - the manual pre-change
# backups this project's own deploy history (ENHANCEMENT-PLAN.md) relies
# on before every step - plus a stray .DS_Store. Deploying here only ever
# adds or updates files that exist in app/; removing a file that's
# actually gone from app/ stays a deliberate, separate, manual step (an
# explicit `ssh ... rm`), the same considered way gateway/ and dpi/ are
# already handled above.
#
# --no-owner --no-group: the same dry-run showed every file would change
# ownership from the gateway's existing root:root (every securepi-*
# service unit has no User=, so it runs as root; there's no "staff" group
# on the gateway anyway) to whatever the Mac's rsync would otherwise send
# across - a quiet, pointless ownership change. `-t` (in `-a`) still keeps
# timestamps in sync, which is all deploy actually needs.

.PHONY: test deploy status

GATEWAY_HOST := maheshwari@192.168.2.5
GATEWAY_APP  := /opt/securepi

test:
	python3 -m unittest discover -s tests -p 'test_*.py' -v

deploy:
	rsync -az --no-owner --no-group --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' \
		--rsync-path="sudo rsync" \
		app/ $(GATEWAY_HOST):$(GATEWAY_APP)/
	ssh $(GATEWAY_HOST) 'sudo systemctl restart securepi-ingest securepi-engine securepi-web'
	ssh $(GATEWAY_HOST) 'sudo securepi status'

status:
	ssh $(GATEWAY_HOST) 'sudo securepi status'
