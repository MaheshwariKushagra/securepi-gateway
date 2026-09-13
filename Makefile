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

.PHONY: test

test:
	python3 -m unittest discover -s tests -p 'test_*.py' -v
