"""Site modules beyond YouTube (ADBLOCK-ENHANCEMENT-PLAN.md B1 second half
and B2): prune operations, streamed JSON, the endpoint / query-name /
never-touch gates, per-device site switches, and the Instagram and
Facebook modules in dpi/adfilter-rules.json.

The JSON shapes below are synthetic, built to the structure captured from
the real feeds on 10 October 2026 (docs/adblock-feasibility.md); no real
content was kept.
"""
import copy
import json
import os
import sys
import types
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "dpi"))

if "mitmproxy" not in sys.modules:
    _fake = types.ModuleType("mitmproxy")
    _fake.http = types.ModuleType("mitmproxy.http")
    sys.modules["mitmproxy"] = _fake
    sys.modules["mitmproxy.http"] = _fake.http

import adfilter_rules  # noqa: E402
import securepi_adfilter as addon  # noqa: E402

SEED = os.path.join(REPO, "dpi", "adfilter-rules.json")


def seed_rules():
    with open(SEED) as f:
        return adfilter_rules.apply_defaults(adfilter_rules.validate_rules(json.load(f)))


def quiet_addon(sites=None):
    a = addon.SecurePiAdFilter()
    a._rules = seed_rules()
    a._ensure_rules_fresh = lambda force=False: None
    a._write_rule_stats = lambda: None
    a.lines = []
    a._log_event = lambda ip, decision, **kw: a.lines.append((decision, kw.get("module"), kw.get("ads_removed")))
    if sites is not None:
        a._sites_for = lambda ip: sites
    return a


class Resp:
    def __init__(self, text, content_type="application/json"):
        self.text = text
        self.headers = {"content-type": content_type}

    def get_text(self):
        return self.text

    def set_text(self, text):
        self.text = text


def flow(host, path, body, query=None, content_type="application/json"):
    headers = {"x-fb-friendly-name": query} if query else {}
    return types.SimpleNamespace(
        request=types.SimpleNamespace(host=host, path=path, headers=headers),
        response=Resp(body, content_type),
        client_conn=types.SimpleNamespace(address=("10.10.0.53", 50000), sni=host),
    )


def ig_feed():
    return {"data": {"xdt_api__v1__feed__timeline__connection": {
        "edges": [
            {"node": {"media": {"code": "organic1"}, "ad": None}, "cursor": "a"},
            {"node": {"ad": {"ad_id": "123", "label": "ad", "items": [{"product_type": "ad"}]}}, "cursor": "b"},
            {"node": {"media": {"code": "organic2"}}, "cursor": "c"},
        ],
        "page_info": {"has_next_page": True}}}, "extensions": {}, "status": "ok"}


def fb_stream(separator="\r\n"):
    docs = [
        {"data": {"viewer": {"news_feed": {"edges": [{"node": {"id": "s1", "th_dat_spo": None}}]}}},
         "extensions": {}},
        {"label": "CometNewsFeed_viewerConnection$stream$CometNewsFeed_viewer_news_feed",
         "path": ["viewer", "news_feed", "edges", 1],
         "data": {"node": {"comet_sections": {"footer": {"story": {"th_dat_spo": {"ad_id": "9"}}}}}},
         "extensions": {}},
        {"label": "CometNewsFeed_viewerConnection$stream$CometNewsFeed_viewer_news_feed",
         "path": ["viewer", "news_feed", "edges", 2],
         "data": {"node": {"id": "s3", "comet_sections": {"footer": {"story": {"th_dat_spo": None}}}}},
         "extensions": {}},
    ]
    return separator.join(json.dumps(d) for d in docs)


class ParseTests(unittest.TestCase):
    def test_single_document(self):
        prefix, docs, sep = addon.parse_json_documents('{"a": 1}')
        self.assertEqual((prefix, docs, sep), ("", [{"a": 1}], None))
        self.assertEqual(addon.serialise_json_documents(prefix, docs, sep), '{"a": 1}')

    def test_streamed_documents_keep_their_separator(self):
        prefix, docs, sep = addon.parse_json_documents(fb_stream())
        self.assertEqual((len(docs), sep), (3, "\r\n"))
        self.assertEqual(addon.serialise_json_documents(prefix, docs, sep).count("\r\n"), 2)

    def test_anti_hijacking_prefix_is_kept(self):
        prefix, docs, sep = addon.parse_json_documents('for (;;);{"a": 1}')
        self.assertEqual(prefix, "for (;;);")
        self.assertTrue(addon.serialise_json_documents(prefix, docs, sep).startswith("for (;;);{"))

    def test_not_json_is_none(self):
        self.assertIsNone(addon.parse_json_documents("<html>hi</html>"))
        self.assertIsNone(addon.parse_json_documents('{"a": 1}\n<oops'))


class PruneTests(unittest.TestCase):
    def test_drop_items_where(self):
        body = ig_feed()
        n = addon.prune(body, [{"op": "drop_items", "list_key": "edges", "where": "node.ad"}])
        edges = body["data"]["xdt_api__v1__feed__timeline__connection"]["edges"]
        self.assertEqual(n, 1)
        self.assertEqual([e["cursor"] for e in edges], ["a", "c"])

    def test_drop_items_contains_key_ignores_null(self):
        body = {"edges": [{"x": {"th_dat_spo": None}}, {"x": {"th_dat_spo": {"ad_id": "1"}}}]}
        n = addon.prune(body, [{"op": "drop_items", "list_key": "edges", "contains_key": "th_dat_spo"}])
        self.assertEqual((n, len(body["edges"])), (1, 1))

    def test_other_lists_are_left_alone(self):
        body = {"items": [{"node": {"ad": {"x": 1}}}]}
        n = addon.prune(body, [{"op": "drop_items", "list_key": "edges", "where": "node.ad"}])
        self.assertEqual((n, len(body["items"])), (0, 1))


class InstagramModuleTests(unittest.TestCase):
    def test_feed_ad_removed_and_logged(self):
        a = quiet_addon()
        f = flow("www.instagram.com", "/graphql/query", json.dumps(ig_feed()),
                 query="PolarisFeedRootPaginationCachedQuery_subscribe")
        a.response(f)
        edges = json.loads(f.response.text)["data"]["xdt_api__v1__feed__timeline__connection"]["edges"]
        self.assertEqual(len(edges), 2)
        self.assertEqual(a.lines, [("ads_stripped", "instagram", 1)])

    def test_inbox_query_is_not_parsed(self):
        a = quiet_addon()
        body = json.dumps(ig_feed())
        f = flow("www.instagram.com", "/graphql/query", body, query="PolarisDirectInboxQuery")
        a.response(f)
        self.assertEqual(f.response.text, body)
        self.assertEqual(a.lines, [])

    def test_never_touch_path(self):
        a = quiet_addon()
        body = json.dumps(ig_feed())
        f = flow("www.instagram.com", "/api/graphql", body, query="PolarisFeedTimelineRootV2Query")
        a.response(f)
        self.assertEqual(f.response.text, body)

    def test_no_query_name_no_rewrite(self):
        a = quiet_addon()
        body = json.dumps(ig_feed())
        f = flow("www.instagram.com", "/graphql/query", body)
        a.response(f)
        self.assertEqual(f.response.text, body)

    def test_story_ads_endpoint_blocked(self):
        orig = getattr(addon.http, "Response", None)
        addon.http.Response = types.SimpleNamespace(make=lambda code: ("response", code))
        try:
            a = quiet_addon()
            f = flow("www.instagram.com", "/ads/igwww_ads_graphql/", "")
            f.response = None
            a.request(f)
            self.assertEqual(f.response, ("response", 204))
            g = flow("www.instagram.com", "/direct/inbox/", "")
            g.response = None
            a.request(g)
            self.assertIsNone(g.response)
        finally:
            if orig is None:
                del addon.http.Response
            else:
                addon.http.Response = orig

    def test_youtube_rules_do_not_apply_to_instagram(self):
        a = quiet_addon()
        body = json.dumps({"data": {"adPlacements": [1]}})
        f = flow("www.instagram.com", "/graphql/query", body, query="PolarisFeedTimelineRootV2Query")
        a.response(f)
        self.assertIn("adPlacements", f.response.text)


def ig_page(extra_block=""):
    feed = json.dumps({"require": [["ScheduledServerJS", {"__bbox": {"result": ig_feed()}}]]},
                      separators=(",", ":"))
    other = '{"require":[["Other",{"text":"</b> not a feed"}]]}'
    return ('<html><head></head><body>'
            '<script type="application/json" nonce="n1" data-content-len="%d" data-sjs>%s</script>'
            '<script type="application/json" nonce="n2" data-content-len="%d" data-sjs>%s</script>%s'
            '</body></html>' % (len(other), other, len(feed), feed, extra_block))


class EmbeddedPageJsonTests(unittest.TestCase):
    """html_json_pages: the first screen of the feed comes inside the page."""

    def test_ad_dropped_and_length_attribute_updated(self):
        ops = [{"op": "drop_items", "list_key": "edges", "where": "node.ad"}]
        new, n = addon.prune_html_json(ig_page(), ops)
        self.assertEqual(n, 1)
        import re
        blocks = re.findall(r'data-content-len="(\d+)" data-sjs>(.*?)</script>', new, re.S)
        for length, content in blocks:
            self.assertEqual(int(length), len(content))
            json.loads(content)
        self.assertNotIn('"ad_id"', new)
        self.assertIn('"organic2"', new)

    def test_unrelated_blocks_untouched(self):
        ops = [{"op": "drop_items", "list_key": "edges", "where": "node.ad"}]
        page = ig_page()
        new, n = addon.prune_html_json(page, ops)
        self.assertIn('{"require":[["Other",{"text":"</b> not a feed"}]]}', new)

    def test_rewritten_json_cannot_end_the_script(self):
        # The page escapes "<" in its JSON; the decoded value holds "</script>".
        body = {"edges": [{"node": {"ad": {"x": 1}}}, {"node": {"t": "</script><script>alert(1)</script>"}}]}
        content = json.dumps(body).replace("<", "\\u003c")
        page = '<script type="application/json" data-content-len="%d">%s</script>' % (len(content), content)
        new, n = addon.prune_html_json(page, [{"op": "drop_items", "list_key": "edges", "where": "node.ad"}])
        self.assertEqual(n, 1)
        self.assertEqual(new.count("</script>"), 1)

    def test_module_page_is_pruned_through_response(self):
        a = quiet_addon()
        f = flow("www.instagram.com", "/", ig_page(), content_type="text/html; charset=utf-8")
        a.response(f)
        self.assertNotIn('"ad_id"', f.response.text)
        self.assertEqual(a.lines, [("ads_stripped", "instagram", 1)])

    def test_other_pages_are_not_pruned(self):
        a = quiet_addon()
        page = ig_page()
        f = flow("www.instagram.com", "/explore/", page, content_type="text/html")
        a.response(f)
        self.assertEqual(f.response.text, page)


class FacebookModuleTests(unittest.TestCase):
    def test_sponsored_chunk_dropped_organic_kept(self):
        a = quiet_addon()
        f = flow("www.facebook.com", "/api/graphql/", fb_stream(), query="CometNewsFeedPaginationQuery",
                 content_type="text/html; charset=utf-8")
        a.response(f)
        prefix, docs, sep = addon.parse_json_documents(f.response.text)
        self.assertEqual(sep, "\r\n")
        self.assertEqual(len(docs), 2)
        self.assertNotIn("ad_id", f.response.text)
        self.assertIn('"s3"', f.response.text)
        self.assertEqual(a.lines, [("ads_stripped", "facebook", 1)])

    def test_messages_query_is_not_parsed(self):
        a = quiet_addon()
        body = fb_stream()
        f = flow("www.facebook.com", "/api/graphql/", body, query="MWQuickPromotionThreadlistBannerQuery")
        a.response(f)
        self.assertEqual(f.response.text, body)
        self.assertEqual(a.lines, [])


class SiteSwitchTests(unittest.TestCase):
    """B2: a site is decrypted only for a device that has it switched on."""

    def hello(self, a, sni, ip="10.10.0.53"):
        data = types.SimpleNamespace(client_hello=types.SimpleNamespace(sni=sni),
                                     context=types.SimpleNamespace(client=types.SimpleNamespace(peername=(ip, 1))))
        a.tls_clienthello(data)
        return not getattr(data, "ignore_connection", False)

    def test_default_is_youtube_only(self):
        a = quiet_addon()
        a._site_map, a._site_map_mtime = {}, None
        addon.SITE_MAP_PATH, orig = "/nonexistent/device-sites.json", addon.SITE_MAP_PATH
        try:
            self.assertTrue(self.hello(a, "m.youtube.com"))
            self.assertFalse(self.hello(a, "www.instagram.com"))
            self.assertFalse(self.hello(a, "www.facebook.com"))
        finally:
            addon.SITE_MAP_PATH = orig
        self.assertIn(("passthrough", "instagram", None), a.lines)

    def test_switched_on_site_is_decrypted(self):
        a = quiet_addon(sites=["youtube", "instagram"])
        self.assertTrue(self.hello(a, "www.instagram.com"))
        self.assertFalse(self.hello(a, "www.facebook.com"))

    def test_live_message_hosts_never_decrypted(self):
        a = quiet_addon(sites=["youtube", "instagram", "facebook"])
        for host in ("edge-chat.instagram.com", "gateway.instagram.com", "gateway.facebook.com",
                     "edge-chat.facebook.com", "instagram.com", "facebook.com", "static.cdninstagram.com"):
            self.assertFalse(self.hello(a, host), host)

    def test_site_map_file_is_read_per_device(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"10.10.0.53": ["youtube", "facebook"]}, f)
        orig = addon.SITE_MAP_PATH
        addon.SITE_MAP_PATH = f.name
        try:
            a = quiet_addon()
            self.assertTrue(self.hello(a, "www.facebook.com", ip="10.10.0.53"))
            self.assertFalse(self.hello(a, "www.facebook.com", ip="10.10.0.50"))
        finally:
            addon.SITE_MAP_PATH = orig
            os.remove(f.name)

    def test_carve_out_beats_a_wider_decrypt_suffix(self):
        rules = seed_rules()
        rules["modules"]["instagram"]["decrypt_suffixes"] = ["instagram.com"]
        self.assertIsNone(adfilter_rules.module_for_host(rules, "edge-chat.instagram.com")[0])
        self.assertEqual(adfilter_rules.module_for_host(rules, "www.instagram.com")[0], "instagram")


class ModuleValidationTests(unittest.TestCase):
    def module(self, **kw):
        m = {"decrypt_suffixes": ["example.org"], "prune": [{"op": "drop_documents", "contains_key": "x"}]}
        m.update(kw)
        return m

    def rules_with(self, module):
        rules = adfilter_rules.default_rules()
        rules["modules"]["site"] = module
        return rules

    def test_seed_modules_are_valid(self):
        rules = seed_rules()
        self.assertEqual(sorted(rules["modules"]), ["facebook", "instagram", "youtube"])

    def test_other_site_may_omit_youtube_keys(self):
        adfilter_rules.validate_rules(self.rules_with(self.module()))

    def test_a_module_must_remove_something(self):
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(self.rules_with({"decrypt_suffixes": ["example.org"]}))

    def test_youtube_is_still_strict(self):
        rules = adfilter_rules.default_rules()
        rules["modules"]["youtube"]["ad_fields"] = []
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(rules)

    def test_bad_prune_ops_rejected(self):
        for op in ({"op": "delete_everything"},
                   {"op": "drop_items", "list_key": "edges"},
                   {"op": "drop_items", "list_key": "edges", "where": "a", "contains_key": "b"},
                   {"op": "drop_documents"},
                   {"op": "drop_documents", "contains_key": "x", "extra": "y"},
                   {"op": "drop_items", "list_key": "", "where": "a"}):
            with self.assertRaises(ValueError, msg=op):
                adfilter_rules.validate_rules(self.rules_with(self.module(prune=[op])))

    def test_list_keys_must_be_strings(self):
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(self.rules_with(self.module(query_names=[1])))

    def test_other_sites_get_no_youtube_cosmetic_selectors(self):
        rules = adfilter_rules.apply_defaults(adfilter_rules.validate_rules(self.rules_with(self.module())))
        self.assertEqual(rules["modules"]["site"]["cosmetic_selectors"], [])
        self.assertTrue(rules["modules"]["youtube"]["cosmetic_selectors"])


if __name__ == "__main__":
    unittest.main()
