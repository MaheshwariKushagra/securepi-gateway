#!/usr/bin/env python3
"""
SecurePi Gateway - blocklist utility and overlap (ENHANCEMENT-PLAN.md
steps 5.4(b) and 7.5: "per-list marginal utility and overlap").

Runs on the Mac, never on the gateway. It answers the question the
console's own per-list contribution can't: the DNS filter records only
the FIRST list that matched a blocked query, so it can say "list 1 got
the credit for 900 blocks" but not "how many of those would still be
blocked if list 1 were switched off". For that, every queried domain has
to be checked against every list on its own. This script does exactly
that:

  1. Download every enabled list (the gateway's own threat-intel list is
     only served on the gateway's loopback, so it is fetched over SSH).
  2. Export the distinct domains devices actually queried, with how many
     times each was allowed or blocked, and which list the DNS filter
     credited for each block.
  3. Check every domain against every list separately.
  4. Report, per list: how many real queries it would block on its own,
     how many ONLY it blocks (its marginal utility - what switching it
     off would lose), and a pairwise overlap matrix.

The matching here is a re-implementation of the DNS filter's rule syntax,
not the filter itself, so it is checked rather than trusted: step 3's
verdicts are compared with the filter's real recorded decisions, and the
agreement rate is printed and saved with the results. Rules this parser
doesn't understand (regular expressions, rules with modifiers other than
$important, URL-path rules) are counted and skipped, never guessed at.

The domain list itself is the network's browsing history, so it stays in
a local working directory and is never written into the repository; only
aggregate counts are saved to eval/results/.

Usage:
    python3 tools/blocklist_utility.py --workdir /path/to/scratch
    python3 tools/blocklist_utility.py --workdir /path/to/scratch --days 7 --offline
      (--offline reuses lists and the export already in --workdir)
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

GATEWAY = "maheshwari@192.168.2.5"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(REPO, "eval", "results")


# --------------------------------------------------------------- gateway side
# Both snippets run on the gateway as root with the project's own modules
# (/opt/securepi), so the list configuration and the query history come
# from exactly the places the console reads them from.

LISTS_SNIPPET = r"""
import adguard, json
st = adguard.filtering_status()
print(json.dumps([{k: f.get(k) for k in ("id", "name", "url", "enabled", "rules_count")}
                  for f in st.get("filters", []) if f.get("enabled")]))
"""

EXPORT_SNIPPET = r"""
import json, sqlite3, sys, time
days = float(sys.argv[1])
c = sqlite3.connect("/var/lib/securepi/securepi.db")
since = time.time() - days * 86400
rows = c.execute(
    "SELECT lower(rtrim(dns_rrname, '.')), blocked, dns_filter_list_id, count(*)"
    "  FROM events"
    " WHERE event_type = 'dns_query' AND ts > ? AND dns_rrname IS NOT NULL"
    " GROUP BY 1, 2, 3", (since,)).fetchall()
span = c.execute("SELECT min(ts), max(ts) FROM events WHERE event_type='dns_query' AND ts > ?",
                 (since,)).fetchone()
print(json.dumps({"since": span[0], "until": span[1], "rows": rows}))
"""


def _ssh_python(snippet, *args):
    cmd = ["ssh", "-o", "BatchMode=yes", GATEWAY,
           "cd /opt/securepi && sudo python3 - " + " ".join(args)]
    out = subprocess.run(cmd, input=snippet, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        sys.exit("gateway command failed: %s" % out.stderr.strip())
    return json.loads(out.stdout)


def fetch_inputs(workdir, days):
    os.makedirs(os.path.join(workdir, "lists"), exist_ok=True)
    lists = _ssh_python(LISTS_SNIPPET)
    for lst in lists:
        path = os.path.join(workdir, "lists", "%s.txt" % lst["id"])
        if lst["url"].startswith("http://127.0.0.1"):
            # Served only on the gateway's loopback (app/intel.py).
            out = subprocess.run(["ssh", "-o", "BatchMode=yes", GATEWAY, "curl -s " + lst["url"]],
                                 capture_output=True, timeout=60)
            data = out.stdout
        else:
            req = urllib.request.Request(lst["url"], headers={"User-Agent": "securepi-blocklist-utility"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
        with open(path, "wb") as f:
            f.write(data)
        print("  fetched %-45s %8d bytes" % (lst["name"][:45], len(data)))
    with open(os.path.join(workdir, "lists.json"), "w") as f:
        json.dump(lists, f, indent=1)

    export = _ssh_python(EXPORT_SNIPPET, str(days))
    with open(os.path.join(workdir, "queries.json"), "w") as f:
        json.dump(export, f)
    print("  exported %d (domain, verdict, list) rows" % len(export["rows"]))


# -------------------------------------------------------------- rule parsing

class ListRules:
    """One list's rules, reduced to what DNS-level matching needs.

    subtree:  domains blocked together with all their subdomains (||x^)
    exact:    domains blocked exactly, and only them (hosts-file lines)
    allow_subtree / allow_exact: the same for @@ exception rules
    skipped:  rules this parser deliberately doesn't interpret
    """

    def __init__(self):
        self.subtree, self.exact = set(), set()
        self.allow_subtree, self.allow_exact = set(), set()
        self.skipped = 0
        self.parsed = 0


def _clean_host(host):
    host = host.strip().lower().rstrip(".")
    if not host or "/" in host or "*" in host or " " in host or "." not in host:
        return None
    return host


def parse_list(text, plain_domain_is_subtree=True):
    """Adblock-style (||example.com^), hosts-style (0.0.0.0 example.com)
    and plain one-domain-per-line lists, the three shapes the configured
    lists use. `plain_domain_is_subtree` decides whether a bare
    "example.com" line also covers its subdomains; both readings are
    checked against the filter's real decisions (see agreement below)."""
    rules = ListRules()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#", "[")):
            continue
        allow = line.startswith("@@")
        if allow:
            line = line[2:]

        if line.startswith("/") and line.endswith("/"):
            rules.skipped += 1          # regular expression
            continue

        modifiers = ""
        if "$" in line:
            line, modifiers = line.split("$", 1)
            if modifiers not in ("important",):
                rules.skipped += 1      # client-, dnstype-, dnsrewrite-specific etc.
                continue

        if line.startswith("||"):
            body = line[2:]
            if body.endswith("^"):
                body = body[:-1]
            host = _clean_host(body)
            if host is None:
                rules.skipped += 1
                continue
            (rules.allow_subtree if allow else rules.subtree).add(host)
            rules.parsed += 1
            continue

        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            host = _clean_host(parts[1])
            if host is None or host in ("localhost", "localhost.localdomain"):
                rules.skipped += 1
                continue
            (rules.allow_exact if allow else rules.exact).add(host)
            rules.parsed += 1
            continue

        if len(parts) == 1:
            host = _clean_host(parts[0].rstrip("^").lstrip("|"))
            if host is None:
                rules.skipped += 1
                continue
            target = (rules.allow_subtree if allow else rules.subtree) if plain_domain_is_subtree \
                else (rules.allow_exact if allow else rules.exact)
            target.add(host)
            rules.parsed += 1
            continue

        rules.skipped += 1
    return rules


def _suffixes(domain):
    """example: a.b.example.com -> a.b.example.com, b.example.com, example.com, com"""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]


def blocks(rules, domain):
    """Would this list, on its own, block `domain`?"""
    sufs = _suffixes(domain)
    if domain in rules.allow_exact or any(s in rules.allow_subtree for s in sufs):
        return False
    return domain in rules.exact or any(s in rules.subtree for s in sufs)


# ------------------------------------------------------------------ analysis

def load_queries(workdir):
    """{domain: {"allowed": n, "blocked": n, "blocked_by": {list_id: n}}}"""
    with open(os.path.join(workdir, "queries.json")) as f:
        export = json.load(f)
    domains = {}
    for domain, blocked, list_id, n in export["rows"]:
        d = domains.setdefault(domain, {"allowed": 0, "blocked": 0, "blocked_by": {}})
        if blocked:
            d["blocked"] += n
            if list_id is not None:
                d["blocked_by"][list_id] = d["blocked_by"].get(list_id, 0) + n
        else:
            d["allowed"] += n
    return export, domains


def agreement(lists, parsed, domains):
    """How often does this script's verdict match the filter's real one?

    blocked_credited: queries the filter blocked AND credited to a list -
        does that list (standalone) block the domain here too?
    allowed: queries the filter allowed - does no list block it here?
        (Allowed-but-listed can legitimately happen: a device with
        filtering switched off by a profile or a pause, or a per-device
        allow rule. So this one is expected to be a little under 100%.)"""
    ids = {lst["id"] for lst in lists}
    cred_total = cred_match = 0
    allow_total = allow_match = 0
    for domain, d in domains.items():
        for list_id, n in d["blocked_by"].items():
            if list_id in ids:
                cred_total += n
                if blocks(parsed[list_id], domain):
                    cred_match += n
        if d["allowed"]:
            allow_total += d["allowed"]
            if not any(blocks(parsed[i], domain) for i in ids):
                allow_match += d["allowed"]
    return {
        "blocked_credited_queries": cred_total,
        "blocked_credited_agree_pct": round(100.0 * cred_match / cred_total, 2) if cred_total else None,
        "allowed_queries": allow_total,
        "allowed_agree_pct": round(100.0 * allow_match / allow_total, 2) if allow_total else None,
    }


def analyse(lists, parsed, domains):
    ids = [lst["id"] for lst in lists]
    # Which lists (standalone) block each queried domain.
    hit = {}
    for domain in domains:
        who = frozenset(i for i in ids if blocks(parsed[i], domain))
        if who:
            hit[domain] = who

    def queries(domain):
        return domains[domain]["allowed"] + domains[domain]["blocked"]

    total_q = sum(queries(d) for d in domains)
    any_blocked_q = sum(queries(d) for d in hit)
    per_list = []
    for lst in lists:
        i = lst["id"]
        mine = [d for d, who in hit.items() if i in who]
        only = [d for d, who in hit.items() if who == {i}]
        per_list.append({
            "id": i, "name": lst["name"], "rules_count": lst["rules_count"],
            "parsed_rules": parsed[i].parsed, "skipped_rules": parsed[i].skipped,
            "domains_blocked": len(mine),
            "queries_blocked": sum(queries(d) for d in mine),
            "unique_domains": len(only),
            "unique_queries": sum(queries(d) for d in only),
            # Marginal utility: the share of everything the configured lists
            # block together that would be lost if this list were removed.
            "marginal_utility_pct": round(100.0 * sum(queries(d) for d in only) / any_blocked_q, 2)
            if any_blocked_q else 0.0,
        })

    # Overlap: of the domains list A blocks, what share does list B also block?
    overlap = {}
    for a in ids:
        a_domains = [d for d, who in hit.items() if a in who]
        row = {}
        for b in ids:
            shared = sum(1 for d in a_domains if b in hit[d])
            row[str(b)] = round(100.0 * shared / len(a_domains), 1) if a_domains else None
        overlap[str(a)] = row

    return {
        "distinct_domains": len(domains),
        "total_queries": total_q,
        "domains_blocked_by_any_list": len(hit),
        "queries_blocked_by_any_list": any_blocked_q,
        "per_list": per_list,
        "overlap_pct_row_also_blocked_by_column": overlap,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--workdir", required=True,
                    help="local directory for downloaded lists and the query export (kept out of the repo)")
    ap.add_argument("--days", type=float, default=7.0, help="how many days of query history to use")
    ap.add_argument("--offline", action="store_true", help="reuse what is already in --workdir")
    args = ap.parse_args()

    if not args.offline:
        print("== fetching lists and query history")
        fetch_inputs(args.workdir, args.days)

    with open(os.path.join(args.workdir, "lists.json")) as f:
        lists = json.load(f)
    export, domains = load_queries(args.workdir)

    # Pick the plain-domain reading that agrees better with the filter.
    best = None
    for subtree in (True, False):
        parsed = {}
        for lst in lists:
            with open(os.path.join(args.workdir, "lists", "%s.txt" % lst["id"]),
                      encoding="utf-8", errors="replace") as f:
                parsed[lst["id"]] = parse_list(f.read(), plain_domain_is_subtree=subtree)
        agree = agreement(lists, parsed, domains)
        score = (agree["blocked_credited_agree_pct"] or 0) + (agree["allowed_agree_pct"] or 0)
        if best is None or score > best[0]:
            best = (score, subtree, parsed, agree)
    _, subtree, parsed, agree = best

    result = analyse(lists, parsed, domains)
    result.update({
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "history_from": time.strftime("%Y-%m-%d %H:%M", time.localtime(export["since"])),
        "history_to": time.strftime("%Y-%m-%d %H:%M", time.localtime(export["until"])),
        "plain_domain_lines_cover_subdomains": subtree,
        "agreement_with_the_filter": agree,
    })

    print("\nhistory %s -> %s: %d distinct domains, %d queries" % (
        result["history_from"], result["history_to"], result["distinct_domains"], result["total_queries"]))
    print("agreement with the filter's own decisions: blocked %s%% of %d, allowed %s%% of %d" % (
        agree["blocked_credited_agree_pct"], agree["blocked_credited_queries"],
        agree["allowed_agree_pct"], agree["allowed_queries"]))
    print("\n%-42s %9s %9s %8s %8s %9s" % ("list", "domains", "queries", "unique", "uniq q", "marginal"))
    for p in sorted(result["per_list"], key=lambda p: -p["queries_blocked"]):
        print("%-42s %9d %9d %8d %8d %8.2f%%" % (p["name"][:42], p["domains_blocked"], p["queries_blocked"],
                                                p["unique_domains"], p["unique_queries"],
                                                p["marginal_utility_pct"]))

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out = os.path.join(RESULTS_DIR, "blocklist-utility-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
    with open(out, "w") as f:
        json.dump(result, f, indent=1)
    print("\nsaved (aggregate counts only): %s" % os.path.relpath(out, REPO))


if __name__ == "__main__":
    main()
