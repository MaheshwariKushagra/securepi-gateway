# SecurePi Gateway
#
# `make test` covers the DPI addon's rule logic (ENHANCEMENT-PLAN.md step
# 5.9's own exit criterion). It is not yet the full project test suite -
# that's Stage 1's F1, not built yet - so this Makefile has exactly one
# real target for now rather than pretending to more coverage than exists.

.PHONY: test

test:
	python3 -m unittest discover -s tests -p 'test_*.py' -v
