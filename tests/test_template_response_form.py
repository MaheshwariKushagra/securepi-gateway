"""CODEBASE_AUDIT / 7.9 finding F17: Starlette 1.x removed the old
`TemplateResponse(name, {"request": request, ...})` form. Every call must
pass the request first, which Starlette 0.29+ (the gateway's 0.31.1
included) accepts, so an Ubuntu upgrade of python3-starlette can't break
the console. FastAPI isn't installed where the tests run, so this reads
the source, as tests/test_resolver_tuning.py does."""
import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TemplateResponseFormTests(unittest.TestCase):
    def test_every_call_passes_the_request_first(self):
        with open(os.path.join(REPO, "app", "webapp.py")) as f:
            src = f.read()
        calls = re.findall(r"TemplateResponse\(([^,]+),", src)
        self.assertGreaterEqual(len(calls), 13)
        self.assertEqual([c for c in calls if c.strip() != "request"], [])


if __name__ == "__main__":
    unittest.main()
