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


def quiet_addon(sites="all"):
    """A real addon on the seed rules, with disk writes switched off.
    `sites`: "all" switches every site on for the test device (most tests
    are about what the rules do), a list switches on just those, and None
    leaves the real site-map loader in place (SiteSwitchTests)."""
    a = addon.SecurePiAdFilter()
    a._rules = seed_rules()
    a._ensure_rules_fresh = lambda force=False: None
    a._write_rule_stats = lambda: None
    a.lines = []
    a._log_event = lambda ip, decision, **kw: a.lines.append((decision, kw.get("module"), kw.get("ads_removed")))
    if sites == "all":
        a._sites_for = lambda ip: sorted(a._rules["modules"])
    elif sites is not None:
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

    def with_map(self, content):
        """Point the addon's SITE_MAP_PATH at a temporary file holding
        `content` (a string, written as-is), or at a missing file if None.
        Returns a function that puts the real path back."""
        import tempfile
        orig = addon.SITE_MAP_PATH
        d = tempfile.mkdtemp()
        path = os.path.join(d, "device-sites.json")
        if content is not None:
            with open(path, "w") as f:
                f.write(content)
        addon.SITE_MAP_PATH = path

        def restore():
            addon.SITE_MAP_PATH = orig
        self.addCleanup(restore)
        return path

    def assert_nothing_decrypted(self, a, ip="10.10.0.53"):
        for host in ("m.youtube.com", "www.youtube.com", "www.instagram.com", "www.facebook.com"):
            self.assertFalse(self.hello(a, host, ip=ip), host)

    # Audit10Oct C1: unknown scope used to mean "YouTube only", which
    # decrypted YouTube for a device enrolled only for Instagram whenever
    # the map was lost. Every kind of unknown now means no inspection.

    def test_missing_map_means_no_inspection(self):
        self.with_map(None)
        a = quiet_addon(sites=None)
        self.assert_nothing_decrypted(a)
        self.assertIn(("passthrough", "youtube", None), a.lines)

    def test_corrupt_map_means_no_inspection(self):
        self.with_map('{"10.10.0.53": ["youtube"')
        self.assert_nothing_decrypted(quiet_addon(sites=None))

    def test_device_absent_from_the_map_is_not_inspected(self):
        self.with_map(json.dumps({"10.10.0.99": ["youtube", "instagram"]}))
        self.assert_nothing_decrypted(quiet_addon(sites=None))

    def test_empty_entry_means_no_inspection(self):
        self.with_map(json.dumps({"10.10.0.53": []}))
        self.assert_nothing_decrypted(quiet_addon(sites=None))

    def test_instagram_only_device_never_gets_youtube_decrypted(self):
        self.with_map(json.dumps({"10.10.0.53": ["instagram"]}))
        a = quiet_addon(sites=None)
        self.assertTrue(self.hello(a, "www.instagram.com"))
        self.assertFalse(self.hello(a, "m.youtube.com"))

    def test_a_revoked_site_is_not_rewritten_on_an_already_open_connection(self):
        # The connection was decrypted while YouTube was on; then YouTube
        # is switched off. Even if closing the connection failed, the next
        # response on it must pass through untouched and unlogged.
        path = self.with_map(json.dumps({"10.10.0.53": ["youtube"]}))
        a = quiet_addon(sites=None)
        body = json.dumps({"adPlacements": [1], "contents": []})
        f1 = flow("www.youtube.com", "/youtubei/v1/player", body)
        a.response(f1)
        self.assertNotIn("adPlacements", f1.response.text)
        with open(path, "w") as f:
            json.dump({"10.10.0.53": ["instagram"]}, f)
        os.utime(path, (1, 1))   # a different mtime, so the addon re-reads it
        a.lines.clear()
        f2 = flow("www.youtube.com", "/youtubei/v1/player", body)
        a.response(f2)
        self.assertEqual(f2.response.text, body)
        self.assertEqual(a.lines, [])
        self.assertIn("/pagead/", a._rules["modules"]["youtube"]["blocked_paths"])
        f3 = flow("www.youtube.com", "/pagead/1", "")
        a.request(f3)
        self.assertEqual(a.blocked_urls, 0)

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
            a = quiet_addon(sites=None)
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


class EditorMergeTests(unittest.TestCase):
    """Audit10Oct H10: the console's rule editor rebuilt the module from the
    six fields it shows, dropping every other field - passthrough carve-
    outs, never-touch paths, endpoint limits, prune operations."""

    def test_fields_the_editor_doesnt_show_are_kept(self):
        current = seed_rules()["modules"]["instagram"]
        new = adfilter_rules.edited_module(current, {"ad_fields": ["x"], "cosmetic_selectors": None})
        self.assertEqual(new["ad_fields"], ["x"])
        for key in ("passthrough_suffixes", "never_touch_paths", "json_endpoints", "prune", "query_names"):
            self.assertEqual(new[key], current[key], key)
        self.assertEqual(new["cosmetic_selectors"], current["cosmetic_selectors"])   # None = leave alone
        self.assertIsNot(new["prune"], current["prune"])                             # a copy, not shared

    def test_changing_decrypt_suffixes_needs_confirmation(self):
        old = {"decrypt_suffixes": ["youtube.com"], "passthrough_suffixes": []}
        new = dict(old, decrypt_suffixes=["youtube.com", "example.org"])
        self.assertTrue(adfilter_rules.needs_scope_confirmation(old, new))

    def test_removing_a_passthrough_carve_out_needs_confirmation(self):
        old = {"decrypt_suffixes": ["instagram.com"], "passthrough_suffixes": ["edge-chat.instagram.com"]}
        new = dict(old, passthrough_suffixes=[])
        self.assertTrue(adfilter_rules.needs_scope_confirmation(old, new))

    def test_adding_a_carve_out_or_editing_ad_fields_needs_none(self):
        old = {"decrypt_suffixes": ["instagram.com"], "passthrough_suffixes": [], "ad_fields": []}
        self.assertFalse(adfilter_rules.needs_scope_confirmation(
            old, dict(old, passthrough_suffixes=["chat.instagram.com"], ad_fields=["a"])))


class OverlapValidationTests(unittest.TestCase):
    """Audit10Oct M7: a suffix in one module that covers another module's
    suffix made the owner of a host depend on dict order."""

    def rules_with(self, a, b):
        rules = seed_rules()
        rules["modules"] = {"one": dict(rules["modules"]["youtube"], decrypt_suffixes=a),
                            "two": dict(rules["modules"]["youtube"], decrypt_suffixes=b)}
        return rules

    def test_a_parent_and_child_suffix_in_different_modules_is_refused(self):
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(self.rules_with(["example.com"], ["ads.example.com"]))
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(self.rules_with(["ads.example.com"], ["example.com"]))

    def test_look_alike_names_are_not_overlaps(self):
        adfilter_rules.validate_rules(self.rules_with(["example.com"], ["notexample.com"]))

    def test_the_seed_rules_have_no_overlap(self):
        self.assertIsNotNone(seed_rules())


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


def hello(ciphers, ext_types, alpn=(b"h2", b"http/1.1"), sni="www.youtube.com"):
    return types.SimpleNamespace(cipher_suites=list(ciphers), extensions=[(t, b"") for t in ext_types],
                                 alpn_protocols=list(alpn), sni=sni)


CHROME = ([0x1301, 0x1302, 0x1303, 0xc02b], [0, 10, 11, 13, 16, 23, 35, 43, 45, 51, 65281])
APP = ([0x1301, 0x1302, 0xc02f], [0, 10, 13, 16, 43, 45, 51])


class ClientFingerprintTests(unittest.TestCase):
    """F4: the pin bypass is keyed on the kind of client as well."""

    def test_order_grease_and_padding_do_not_change_it(self):
        a = addon.client_fingerprint(hello(*CHROME))
        shuffled = addon.client_fingerprint(hello([0xAAAA] + CHROME[0][::-1],
                                                  [0x1A1A, 21] + CHROME[1][::-1] + [41]))
        self.assertEqual(a, shuffled)

    def test_different_clients_differ(self):
        self.assertNotEqual(addon.client_fingerprint(hello(*CHROME)), addon.client_fingerprint(hello(*APP)))
        self.assertNotEqual(addon.client_fingerprint(hello(*CHROME)),
                            addon.client_fingerprint(hello(*CHROME, alpn=(b"http/1.1",))))

    def test_unreadable_hello_is_none(self):
        self.assertIsNone(addon.client_fingerprint(types.SimpleNamespace(sni="x")))


class PerClientBypassTests(unittest.TestCase):
    """A pinned app failing twice must not switch decryption off for the
    browser on the same device (found 10 Oct 2026 on the A33)."""

    def setUp(self):
        self.a = quiet_addon(sites=["youtube"])
        self.n = 0

    def connect(self, kind, ip="10.10.0.50"):
        self.n += 1
        ciphers, exts = CHROME if kind == "browser" else APP
        data = types.SimpleNamespace(
            client_hello=hello(ciphers, exts),
            context=types.SimpleNamespace(client=types.SimpleNamespace(peername=(ip, 1), id="c%d" % self.n)))
        self.a.tls_clienthello(data)
        return data, "c%d" % self.n, not getattr(data, "ignore_connection", False)

    def fail(self, conn_id, ip="10.10.0.50"):
        self.a.tls_failed_client(types.SimpleNamespace(
            conn=types.SimpleNamespace(sni="www.youtube.com", id=conn_id),
            context=types.SimpleNamespace(client=types.SimpleNamespace(peername=(ip, 1)))))

    def test_app_failures_bypass_the_app_only(self):
        for _ in range(2):
            _, cid, decrypted = self.connect("app")
            self.assertTrue(decrypted)
            self.fail(cid)
        self.assertFalse(self.connect("app")[2], "the app is now passed through")
        self.assertTrue(self.connect("browser")[2], "the browser is still decrypted")

    def test_bypass_is_still_per_device(self):
        for _ in range(2):
            _, cid, _ = self.connect("app")
            self.fail(cid)
        self.assertTrue(self.connect("app", ip="10.10.0.53")[2])

    def test_a_success_in_between_resets_that_clients_count(self):
        _, cid, _ = self.connect("app")
        self.fail(cid)
        _, ok_id, _ = self.connect("app")
        self.a.tls_established_client(types.SimpleNamespace(
            conn=types.SimpleNamespace(sni="www.youtube.com", id=ok_id),
            context=types.SimpleNamespace(client=types.SimpleNamespace(peername=("10.10.0.50", 1)))))
        _, cid, _ = self.connect("app")
        self.fail(cid)
        self.assertTrue(self.connect("app")[2])


def fb_page_json():
    """The shape Facebook's home page embeds (10 Oct 2026 capture): nested
    "require" lists of prefetched chunks - one organic story, one
    sponsored - and the right column's sponsored unit."""
    organic = ["RelayPrefetchedStreamCache", "next", [], ["adp_feed", {"__bbox": {"result": {
        "label": "CometNewsFeed_viewerConnection$stream", "data": {"node": {"id": "organic", "th_dat_spo": None}}}}}]]
    sponsored = ["RelayPrefetchedStreamCache", "next", [], ["adp_feed", {"__bbox": {"result": {
        "label": "CometNewsFeed_viewerConnection$stream",
        "data": {"node": {"id": "ad", "comet_sections": {"footer": {"story": {"th_dat_spo": {"ad_id": "7"}}}}}}}}}]]
    aux = ["RelayPrefetchedStreamCache", "next", [], ["adp_aux", {"__bbox": {"result": {"data": {"viewer": {
        "auxColumnUnits": {"nodes": [
            {"id": "contacts", "item_collection": {"nodes": [{"name": "c1", "sponsored_data": None}]}},
            {"id": "ads", "item_collection": {"nodes": [{"sponsored_data": {"ad_id": "8"}}]}}]}}}}}}]]
    return {"require": [["ScheduledServerJS", "handle", None, [{"__bbox": {"require": [organic, sponsored, aux]}}]]]}


class InnermostTests(unittest.TestCase):
    OPS = [{"op": "drop_items", "list_key": "require", "contains_key": "th_dat_spo", "innermost": True},
           {"op": "drop_items", "list_key": "nodes", "contains_key": "sponsored_data"}]

    def test_only_the_smallest_matching_item_goes(self):
        doc = fb_page_json()
        n = addon.prune(doc, self.OPS)
        text = json.dumps(doc)
        self.assertNotIn('"ad_id": "7"', text)
        self.assertNotIn('"ad_id": "8"', text)
        self.assertIn('"organic"', text)
        self.assertIn('"contacts"', text)
        self.assertEqual(n, 2)

    def test_without_innermost_the_whole_page_would_go(self):
        doc = fb_page_json()
        addon.prune(doc, [{"op": "drop_items", "list_key": "require", "contains_key": "th_dat_spo"}])
        self.assertEqual(doc["require"], [], "the outer handle holds the ad, so it all goes - why innermost exists")

    def test_innermost_must_be_boolean(self):
        rules = adfilter_rules.default_rules()
        rules["modules"]["site"] = {"decrypt_suffixes": ["example.org"], "prune": [
            {"op": "drop_items", "list_key": "x", "contains_key": "y", "innermost": "yes"}]}
        with self.assertRaises(ValueError):
            adfilter_rules.validate_rules(rules)

    def test_shipped_facebook_rules_leave_page_chunks_alone(self):
        # Measured 10 Oct 2026: dropping the page-embedded sponsored chunk
        # left the feed stuck on loading placeholders, and dropping the
        # right-column ad units caused a page error on every load - so the
        # shipped rules remove fetched feed ads only (EVALUATION-RESULTS-2.md).
        a = quiet_addon()
        content = json.dumps(fb_page_json()).replace("<", "\\u003c")
        page = '<html><body><script type="application/json" data-content-len="%d" data-sjs>%s</script></body></html>' % (
            len(content), content)
        f = flow("www.facebook.com", "/", page, content_type="text/html; charset=utf-8")
        a.response(f)
        self.assertEqual(f.response.text, page)
        self.assertEqual(a.lines, [])


if __name__ == "__main__":
    unittest.main()
