#!/usr/bin/env python3
"""
SecurePi Gateway - fixture tests for dpi/securepi_adfilter.py's strip_ads()
and dpi/adfilter_rules.py's validation logic.

ENHANCEMENT-PLAN.md step 5.9's own exit criterion: "Fixture tests for
strip_ads on synthetic YouTube-shaped JSON: nested fields removed, ad
renderers dropped, content preserved, output still valid JSON." Run via
`make test` from the repo root, or directly:

    python3 -m unittest tests.test_adfilter -v

mitmproxy is only installed inside the gateway's DPI venv, not on a
plain dev machine (confirmed earlier this project only has it there) -
and dpi/securepi_adfilter.py does `from mitmproxy import http` at module
level purely for one line in request() this file's tests never reach.
Rather than require every contributor to install the whole mitmproxy
package just to test a pure JSON-tree function, `mitmproxy` and
`mitmproxy.http` are stubbed out below before the addon module is
imported - the same technique ENHANCEMENT-PLAN.md steps 5.7 and 5.8 used
for their own local smoke tests. This stub is test-only; nothing shipped
to the gateway uses it.
"""

import copy
import json
import os
import sys
import types
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DPI_DIR = os.path.join(REPO_ROOT, "dpi")
sys.path.insert(0, DPI_DIR)

if "mitmproxy" not in sys.modules:
    _fake_mitmproxy = types.ModuleType("mitmproxy")
    _fake_mitmproxy.http = types.ModuleType("mitmproxy.http")
    sys.modules["mitmproxy"] = _fake_mitmproxy
    sys.modules["mitmproxy.http"] = _fake_mitmproxy.http

import securepi_adfilter as addon  # noqa: E402  (path/stub must be set up first)
import adfilter_rules  # noqa: E402


AD_FIELDS = list(adfilter_rules.DEFAULT_RULES["ad_fields"])
AD_RENDERERS = list(adfilter_rules.DEFAULT_RULES["ad_renderers"])


def strip(node, hits=None):
    """Thin wrapper binding strip_ads to the real default rule set, so
    each test case doesn't have to repeat AD_FIELDS/AD_RENDERERS."""
    return addon.strip_ads(node, AD_FIELDS, AD_RENDERERS, hits)


class StripAdsFieldRemovalTests(unittest.TestCase):
    """Ad-scheduling fields (adPlacements and friends) must be removed
    wherever they appear, at any nesting depth - this is specifically
    what the plan's own exit criterion calls "nested fields removed"."""

    def test_top_level_field_removed(self):
        body = {"adPlacements": [{"foo": "bar"}], "videoId": "abc123"}
        removed = strip(body)
        self.assertEqual(removed, 1)
        self.assertNotIn("adPlacements", body)
        self.assertEqual(body["videoId"], "abc123")  # real content preserved

    def test_deeply_nested_field_removed(self):
        # A realistic shape: YouTube nests playerAds several levels down
        # inside the player response, not at the top.
        body = {
            "playabilityStatus": {"status": "OK"},
            "streamingData": {"formats": [{"itag": 18, "url": "https://example/video"}]},
            "playerResponse": {
                "adBreakHeartbeatParams": {"heartbeatMs": 5000},
                "videoDetails": {"title": "Real Video", "lengthSeconds": "120"},
            },
        }
        removed = strip(body)
        self.assertEqual(removed, 1)
        self.assertNotIn("adBreakHeartbeatParams", body["playerResponse"])
        # Real content at every level must survive untouched.
        self.assertEqual(body["playabilityStatus"]["status"], "OK")
        self.assertEqual(body["streamingData"]["formats"][0]["itag"], 18)
        self.assertEqual(body["playerResponse"]["videoDetails"]["title"], "Real Video")

    def test_multiple_ad_fields_at_different_depths_all_removed(self):
        body = {
            "adPlacements": ["x"],
            "nested": {"playerAds": ["y"], "deeper": {"adSlots": ["z"]}},
        }
        removed = strip(body)
        self.assertEqual(removed, 3)
        self.assertEqual(body, {"nested": {"deeper": {}}})

    def test_field_that_is_not_an_ad_field_is_preserved(self):
        body = {"adPlacementsButNotReally": "keep me", "videoId": "abc"}
        removed = strip(body)
        self.assertEqual(removed, 0)
        self.assertEqual(body["adPlacementsButNotReally"], "keep me")


class StripAdsRendererRemovalTests(unittest.TestCase):
    """List entries whose type is an ad renderer must be dropped; every
    other entry in the same list must survive, in order."""

    def test_ad_renderer_entry_dropped_from_feed(self):
        body = {
            "contents": [
                {"videoRenderer": {"title": "Real video 1"}},
                {"adSlotRenderer": {"adId": "12345"}},
                {"videoRenderer": {"title": "Real video 2"}},
            ]
        }
        removed = strip(body)
        self.assertEqual(removed, 1)
        self.assertEqual(len(body["contents"]), 2)
        self.assertEqual(body["contents"][0]["videoRenderer"]["title"], "Real video 1")
        self.assertEqual(body["contents"][1]["videoRenderer"]["title"], "Real video 2")

    def test_multiple_different_ad_renderers_all_dropped(self):
        body = {
            "items": [
                {"compactPromotedVideoRenderer": {}},
                {"videoRenderer": {"title": "keep"}},
                {"displayAdRenderer": {}},
                {"bannerPromoRenderer": {}},
            ]
        }
        removed = strip(body)
        self.assertEqual(removed, 3)
        self.assertEqual(body["items"], [{"videoRenderer": {"title": "keep"}}])

    def test_nested_renderer_list_inside_a_dict_inside_a_list(self):
        # Shaped like a real /browse response: a list of sections, each
        # containing its own nested list of items.
        body = {
            "sections": [
                {"items": [
                    {"videoRenderer": {"title": "A"}},
                    {"adSlotRenderer": {}},
                ]},
                {"items": [
                    {"promotedVideoRenderer": {}},
                    {"videoRenderer": {"title": "B"}},
                ]},
            ]
        }
        removed = strip(body)
        self.assertEqual(removed, 2)
        self.assertEqual(body["sections"][0]["items"], [{"videoRenderer": {"title": "A"}}])
        self.assertEqual(body["sections"][1]["items"], [{"videoRenderer": {"title": "B"}}])


class StripAdsCombinedAndOutputTests(unittest.TestCase):
    """The exit criterion's remaining two claims: content preserved, and
    the output is still valid JSON - checked by round-tripping through
    json.dumps/json.loads, not just by trusting the in-memory object."""

    def test_realistic_mixed_response_content_preserved_and_json_valid(self):
        body = {
            "playabilityStatus": {"status": "OK"},
            "adPlacements": [{"adPlacementRenderer": {}}],
            "videoDetails": {"videoId": "dQw4w9WgXcQ", "title": "Real Video Title"},
            "contents": {
                "twoColumnWatchNextResults": {
                    "results": [
                        {"videoRenderer": {"videoId": "abc", "title": "Up next 1"}},
                        {"compactPromotedItemRenderer": {}},
                        {"videoRenderer": {"videoId": "def", "title": "Up next 2"}},
                    ]
                }
            },
        }
        original_video_count = 2
        removed = strip(body)
        self.assertEqual(removed, 2)  # 1 field + 1 renderer

        # Still valid, round-trippable JSON.
        serialised = json.dumps(body)
        reparsed = json.loads(serialised)
        self.assertEqual(reparsed, body)

        # Real content survived.
        self.assertEqual(reparsed["videoDetails"]["title"], "Real Video Title")
        results = reparsed["contents"]["twoColumnWatchNextResults"]["results"]
        self.assertEqual(len(results), original_video_count)
        self.assertNotIn("adPlacements", reparsed)

    def test_response_with_no_ads_is_left_completely_unchanged(self):
        body = {"videoDetails": {"title": "No ads here"}, "items": [{"videoRenderer": {}}]}
        before = copy.deepcopy(body)
        removed = strip(body)
        self.assertEqual(removed, 0)
        self.assertEqual(body, before)

    def test_hit_counters_increment_per_rule_name(self):
        hits = {"ad_fields": {}, "ad_renderers": {}, "blocked_paths": {}}
        body1 = {"adPlacements": [1]}
        body2 = {"items": [{"adSlotRenderer": {}}, {"adSlotRenderer": {}}]}
        strip(body1, hits)
        strip(body2, hits)
        self.assertEqual(hits["ad_fields"]["adPlacements"], 1)
        self.assertEqual(hits["ad_renderers"]["adSlotRenderer"], 2)
        # A rule that never matched anything must not appear at all -
        # this is exactly what step 5.9's "dead rules" view depends on.
        self.assertNotIn("playerAds", hits["ad_fields"])


class ValidateRulesTests(unittest.TestCase):
    """adfilter_rules.validate_rules() is what refuses a bad console edit
    before it's ever written to disk - it has to be strict."""

    def test_default_rules_are_valid(self):
        adfilter_rules.validate_rules(dict(adfilter_rules.DEFAULT_RULES))

    def test_missing_required_key_rejected(self):
        bad = dict(adfilter_rules.DEFAULT_RULES)
        del bad["ad_fields"]
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(bad)

    def test_non_list_value_rejected(self):
        bad = dict(adfilter_rules.DEFAULT_RULES)
        bad["blocked_paths"] = "/pagead/"  # a string, not a list
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(bad)

    def test_empty_list_rejected(self):
        bad = dict(adfilter_rules.DEFAULT_RULES)
        bad["decrypt_suffixes"] = []
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(bad)

    def test_list_with_non_string_rejected(self):
        bad = dict(adfilter_rules.DEFAULT_RULES)
        bad["ad_renderers"] = ["realRenderer", 123]
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(bad)

    def test_list_with_empty_string_rejected(self):
        bad = dict(adfilter_rules.DEFAULT_RULES)
        bad["ad_fields"] = ["realField", ""]
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(bad)

    def test_not_a_dict_rejected(self):
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(["not", "a", "dict"])

    def test_optional_keys_absent_still_valid(self):
        # A rules file written before step 5.11 has neither optional key
        # at all - must still pass validation, not be treated as broken.
        rules = dict(adfilter_rules.DEFAULT_RULES)
        del rules["cosmetic_injection_enabled"]
        del rules["cosmetic_selectors"]
        adfilter_rules.validate_rules(rules)  # must not raise

    def test_cosmetic_injection_enabled_must_be_bool(self):
        bad = dict(adfilter_rules.DEFAULT_RULES)
        bad["cosmetic_injection_enabled"] = "yes"
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(bad)

    def test_cosmetic_selectors_empty_list_is_valid(self):
        # Unlike the four required categories, an empty cosmetic_selectors
        # list is a deliberate, valid choice (injection with nothing to
        # hide), not an error.
        ok = dict(adfilter_rules.DEFAULT_RULES)
        ok["cosmetic_selectors"] = []
        adfilter_rules.validate_rules(ok)  # must not raise

    def test_cosmetic_selectors_must_be_strings(self):
        bad = dict(adfilter_rules.DEFAULT_RULES)
        bad["cosmetic_selectors"] = ["ytd-display-ad-renderer", 42]
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(bad)

    def test_a_selector_that_ends_the_style_element_is_rejected(self):
        # Audit.md: selectors are pasted into a <style> element on other
        # sites' pages - "</style><script>" would inject a script.
        bad = dict(adfilter_rules.DEFAULT_RULES)
        bad["cosmetic_selectors"] = ["x</style><script>alert(1)</script>"]
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(bad)

    def test_a_selector_that_adds_its_own_css_rules_is_rejected(self):
        for sel in ("a{background:url(//evil)}", "a;b", "@import url(x)", "a/*x*/", "a\\3c"):
            bad = dict(adfilter_rules.DEFAULT_RULES)
            bad["cosmetic_selectors"] = [sel]
            with self.assertRaises(ValueError, msg=sel):
                adfilter_rules.validate_rules(bad)

    def test_ordinary_selectors_including_child_combinators_are_valid(self):
        ok = dict(adfilter_rules.DEFAULT_RULES)
        ok["cosmetic_selectors"] = ["ytd-ad-slot-renderer", "div.ad > span", "[id^='ad-']", "#banner"]
        adfilter_rules.validate_rules(ok)  # must not raise


class ApplyDefaultsTests(unittest.TestCase):
    """apply_defaults() is what lets an adfilter-rules.json written before
    step 5.11 upgrade gracefully - the live gateway's real rules file (no
    cosmetic_* keys at all, at the time this step was written) must load
    successfully with cosmetic injection OFF, not fail or silently turn
    itself on."""

    def test_missing_keys_filled_in_with_safe_defaults(self):
        rules = {k: v for k, v in adfilter_rules.DEFAULT_RULES.items()
                 if k not in ("cosmetic_injection_enabled", "cosmetic_selectors")}
        adfilter_rules.apply_defaults(rules)
        self.assertIs(rules["cosmetic_injection_enabled"], False)
        self.assertTrue(len(rules["cosmetic_selectors"]) > 0)

    def test_existing_choice_is_not_overwritten(self):
        rules = dict(adfilter_rules.DEFAULT_RULES)
        rules["cosmetic_injection_enabled"] = True
        rules["cosmetic_selectors"] = []  # operator deliberately emptied this
        adfilter_rules.apply_defaults(rules)
        self.assertIs(rules["cosmetic_injection_enabled"], True)
        self.assertEqual(rules["cosmetic_selectors"], [])


class CosmeticCssInjectionTests(unittest.TestCase):
    """inject_cosmetic_css() - step 5.11, Path 1."""

    def test_empty_selectors_is_a_no_op(self):
        html = "<html><head></head><body>hi</body></html>"
        new_html, injected = addon.inject_cosmetic_css(html, [])
        self.assertFalse(injected)
        self.assertEqual(new_html, html)

    def test_inserted_before_head_close_when_present(self):
        html = "<html><head><title>t</title></head><body>hi</body></html>"
        new_html, injected = addon.inject_cosmetic_css(html, ["ytd-display-ad-renderer"])
        self.assertTrue(injected)
        self.assertIn("<style>ytd-display-ad-renderer{display:none!important}</style></head>", new_html)
        # Real content is untouched, just relocated around the insertion.
        self.assertIn("<title>t</title>", new_html)
        self.assertIn("<body>hi</body>", new_html)

    def test_multiple_selectors_each_get_their_own_rule(self):
        html = "<html><head></head><body></body></html>"
        new_html, injected = addon.inject_cosmetic_css(html, ["sel-a", "sel-b"])
        self.assertTrue(injected)
        self.assertIn("sel-a{display:none!important}", new_html)
        self.assertIn("sel-b{display:none!important}", new_html)

    def test_falls_back_to_after_body_open_when_no_head_close(self):
        html = "<html><body id=\"x\">hi</body></html>"
        new_html, injected = addon.inject_cosmetic_css(html, ["sel-a"])
        self.assertTrue(injected)
        self.assertTrue(new_html.startswith("<html><body id=\"x\"><style>"))
        self.assertIn("hi</body></html>", new_html)

    def test_falls_back_to_prepend_when_neither_anchor_present(self):
        html = "just some fragment, no head or body tags"
        new_html, injected = addon.inject_cosmetic_css(html, ["sel-a"])
        self.assertTrue(injected)
        self.assertTrue(new_html.startswith("<style>sel-a{display:none!important}</style>"))
        self.assertTrue(new_html.endswith(html))

    def test_output_is_still_well_formed_enough_to_contain_original_bytes(self):
        html = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body><div>Video</div></body></html>"
        new_html, injected = addon.inject_cosmetic_css(html, ["ytd-ad-slot-renderer"])
        self.assertTrue(injected)
        # Nothing from the original document was dropped, only inserted into.
        for fragment in ("<!DOCTYPE html>", "<meta charset=\"utf-8\">", "<div>Video</div>"):
            self.assertIn(fragment, new_html)


class CspLoosenForInlineStyleTests(unittest.TestCase):
    """loosen_csp_for_inline_style() - step 5.11, Path 1."""

    def test_falsy_input_returned_unchanged(self):
        self.assertEqual(addon.loosen_csp_for_inline_style(""), "")
        self.assertIsNone(addon.loosen_csp_for_inline_style(None))

    def test_style_src_gets_unsafe_inline_appended(self):
        csp = "default-src 'self'; style-src 'self' fonts.googleapis.com"
        out = addon.loosen_csp_for_inline_style(csp)
        self.assertIn("style-src 'self' fonts.googleapis.com 'unsafe-inline'", out)
        # default-src is untouched - only the style policy was loosened.
        self.assertIn("default-src 'self'", out)

    def test_already_allows_inline_style_is_unchanged(self):
        csp = "style-src 'self' 'unsafe-inline'"
        out = addon.loosen_csp_for_inline_style(csp)
        self.assertEqual(out, csp)

    def test_no_style_src_adds_a_style_src_copied_from_default_src(self):
        csp = "default-src 'self' example.com; script-src 'self'"
        out = addon.loosen_csp_for_inline_style(csp)
        self.assertIn("style-src 'self' example.com 'unsafe-inline'", out)
        # script-src must NOT be touched - this function only ever loosens
        # style, never script (see its own docstring on why that matters).
        self.assertIn("script-src 'self'", out)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", out)

    def test_default_src_itself_is_never_loosened(self):
        # Audit.md ad-blocking #1: with no script-src, default-src is what
        # governs scripts - adding 'unsafe-inline' to it allowed inline
        # SCRIPTS, not just the injected style.
        csp = "default-src 'self'"
        out = addon.loosen_csp_for_inline_style(csp)
        self.assertIn("default-src 'self';", out + ";")
        self.assertNotIn("default-src 'self' 'unsafe-inline'", out)
        self.assertIn("style-src 'self' 'unsafe-inline'", out)

    def test_default_src_none_is_not_copied_into_the_new_style_src(self):
        out = addon.loosen_csp_for_inline_style("default-src 'none'")
        self.assertIn("default-src 'none'", out)
        self.assertIn("style-src 'unsafe-inline'", out)

    def test_style_src_elem_also_gets_unsafe_inline(self):
        csp = "style-src 'self'; style-src-elem 'self'"
        out = addon.loosen_csp_for_inline_style(csp)
        self.assertIn("style-src-elem 'self' 'unsafe-inline'", out)

    def test_neither_style_src_nor_default_src_present_is_unchanged(self):
        csp = "script-src 'self'; img-src *"
        out = addon.loosen_csp_for_inline_style(csp)
        self.assertEqual(out, csp)

    def test_script_src_is_never_modified_by_this_function(self):
        # The single most important property of this function, given its
        # own docstring's promise: it must be structurally impossible for
        # it to loosen script execution, only style.
        csp = "style-src 'none'; script-src 'self' 'nonce-abc123'"
        out = addon.loosen_csp_for_inline_style(csp)
        self.assertIn("script-src 'self' 'nonce-abc123'", out)


if __name__ == "__main__":
    unittest.main()
