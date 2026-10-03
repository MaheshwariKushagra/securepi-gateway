#!/usr/bin/env python3
"""
SecurePi Gateway - IDS alert-signature taxonomy (ENHANCEMENT-PLAN.md
step 2.3).

IDS/ET Open alerts are ingested already (source='suricata',
event_type='alert', with alert_signature/alert_category/alert_severity/
alert_signature_id - see app/ingest.py's flatten_suricata) but, before
this step, never turned into anything the console shows: the classic
"we're collecting the data but nothing reads it" gap ENHANCEMENT-PLAN.md
§1.1 names explicitly.

TAXONOMY below maps alert_category - the exact short DESCRIPTION text
the IDS's own classification.config assigns to each classtype, confirmed
live on this gateway (`/etc/suricata/classification.config`), not
guessed - to a plain-language name, our own severity, and (only where a
specific MITRE ATT&CK technique genuinely fits) a tag. Curated, not
exhaustive: classification.config defines around 40 classtypes; only the
ones representing a genuine, specific attack pattern are mapped here.
Everything else - including, confirmed against this gateway's own real
traffic, the overwhelmingly common case: ET's "INFO"-style priority-3
categories like "Misc activity" (this network's own STUN/WebRTC and
DNS-over-HTTPS-observation traffic fires these constantly) - falls
through to classify()'s generic fallback, tagged 'ids_other', with
severity taken from the IDS's own numeric priority rather than an
invented plain name. Deliberately not filtered out or suppressed here:
a real operator may want to see even a "Misc activity" pattern once it's
frequent enough to cross correlation.py's own threshold, and per-category
suppression (turning "I've seen this and it's fine" into a standing rule)
is exactly what step 2.7 (suppression rules) is for - building ad hoc
exclusion logic here would duplicate that step's own job.

The IDS's classification.config priority column (1/2/3/4, 1 = most
severe) is the fallback severity source: our own three-level scale
(high/medium/low) collapses 3 and 4 together, since nothing in this
project's default ruleset uses priority 4 for anything but the
essentially-diagnostic "A TCP connection was detected" classtype.
"""

PRIORITY_TO_SEVERITY = {1: "high", 2: "medium", 3: "low", 4: "low"}
DEFAULT_SEVERITY_FOR_UNKNOWN_PRIORITY = "medium"  # never seen priority 5+; don't guess low or high

# category (exact classification.config short description) -> entry.
# `attack` is (tactic, tactic_id, technique_or_None, technique_id_or_None,
# url) - technique fields are None for a tactic-level-only tag, the same
# "don't overstate a specific technique" caution app/playbooks.py already
# documents for volume_anomaly and dns_bypass.
TAXONOMY = {
    "A Network Trojan was detected": {
        "signal_type": "ids_trojan",
        "plain_name": "Network trojan activity detected",
        "severity": "high",
        "attack": ("Command and Control", "TA0011", "Application Layer Protocol", "T1071",
                   "https://attack.mitre.org/techniques/T1071/"),
    },
    "Malware Command and Control Activity Detected": {
        "signal_type": "ids_c2",
        "plain_name": "Malware command-and-control activity detected",
        "severity": "high",
        "attack": ("Command and Control", "TA0011", None, None,
                   "https://attack.mitre.org/tactics/TA0011/"),
    },
    "Domain Observed Used for C2 Detected": {
        "signal_type": "ids_c2_domain",
        "plain_name": "Contact with a domain known to host command-and-control infrastructure",
        "severity": "high",
        "attack": ("Command and Control", "TA0011", None, None,
                   "https://attack.mitre.org/tactics/TA0011/"),
    },
    "Exploit Kit Activity Detected": {
        "signal_type": "ids_exploit_kit",
        "plain_name": "Exploit kit activity detected",
        "severity": "high",
        "attack": ("Initial Access", "TA0001", "Drive-by Compromise", "T1189",
                   "https://attack.mitre.org/techniques/T1189/"),
    },
    "Executable code was detected": {
        "signal_type": "ids_shellcode",
        "plain_name": "Executable code (shellcode) detected in traffic",
        "severity": "high",
        "attack": ("Execution", "TA0002", "Exploitation for Client Execution", "T1203",
                   "https://attack.mitre.org/techniques/T1203/"),
    },
    "Attempted Administrator Privilege Gain": {
        "signal_type": "ids_privilege_gain",
        "plain_name": "Attempted or successful privilege escalation",
        "severity": "high",
        "attack": ("Privilege Escalation", "TA0004", None, None,
                   "https://attack.mitre.org/tactics/TA0004/"),
    },
    "Successful Administrator Privilege Gain": {
        "signal_type": "ids_privilege_gain",
        "plain_name": "Attempted or successful privilege escalation",
        "severity": "high",
        "attack": ("Privilege Escalation", "TA0004", None, None,
                   "https://attack.mitre.org/tactics/TA0004/"),
    },
    "Attempted User Privilege Gain": {
        "signal_type": "ids_privilege_gain",
        "plain_name": "Attempted or successful privilege escalation",
        "severity": "high",
        "attack": ("Privilege Escalation", "TA0004", None, None,
                   "https://attack.mitre.org/tactics/TA0004/"),
    },
    "Successful User Privilege Gain": {
        "signal_type": "ids_privilege_gain",
        "plain_name": "Attempted or successful privilege escalation",
        "severity": "high",
        "attack": ("Privilege Escalation", "TA0004", None, None,
                   "https://attack.mitre.org/tactics/TA0004/"),
    },
    "Successful Credential Theft Detected": {
        "signal_type": "ids_credential_theft",
        "plain_name": "Successful credential theft detected",
        "severity": "high",
        "attack": ("Credential Access", "TA0006", None, None,
                   "https://attack.mitre.org/tactics/TA0006/"),
    },
}

# Every distinct signal_type curated above, plus the generic fallback -
# the complete, bounded list app/playbooks.py needs a PLAYBOOKS/
# ATTACK_MAPPING entry for (checked by tests/test_playbooks_ids.py-style
# coverage, if that's ever added - see tests/test_correlation.py for now).
FALLBACK_SIGNAL_TYPE = "ids_other"
# IDS rules whose only evidence is the top-level domain of a DNS lookup
# (3 October 2026). As SQL LIKE patterns, because ids_alert_signal filters in
# its query and SQLite has no regular expressions. Checked against this
# gateway's whole rule set (/var/lib/suricata/rules/suricata.rules): these
# four patterns match exactly 26 rules, all of the "ET INFO Observed DNS
# Query to .biz TLD" kind, and nothing else - not the rules where a TLD is
# only part of the evidence (an .exe download from one, credentials posted
# to one, a certificate for one) and not the OpenNIC/EmerDNS lookups (an
# alternative DNS root such as BazarLoader's .bazar, which ordinary
# browsing never touches). Whether these raise incidents is the setting
# ids_raise_tld_lookup_rules (default off) - see its help text for why.
TLD_LOOKUP_SIGNATURE_PATTERNS = (
    "ET INFO Observed DNS Query to .% TLD%",
    "ET DNS Query for .% TLD%",
    "ET HUNTING Observed Query to .% TLD%",
    "ET INFO Observed DNS Query for Suspicious TLD%",
)


def tld_lookup_exclusion_sql():
    """SQL to AND onto an alert query to leave TLD-lookup rules out, and its
    parameters: (" AND NOT (alert_signature LIKE ? OR ...)", [patterns])."""
    likes = " OR ".join(["COALESCE(alert_signature, '') LIKE ?"] * len(TLD_LOOKUP_SIGNATURE_PATTERNS))
    return " AND NOT (%s)" % likes, list(TLD_LOOKUP_SIGNATURE_PATTERNS)


ALL_SIGNAL_TYPES = sorted({e["signal_type"] for e in TAXONOMY.values()} | {FALLBACK_SIGNAL_TYPE})


def classify(alert_category, suricata_priority):
    """Returns (signal_type, plain_name, severity, attack_tuple_or_None)
    for one IDS alert. Never raises - an unrecognized category (the
    common case, per this module's own docstring) or a missing/odd
    priority value falls through to a safe, honestly-generic default
    rather than guessing a specific classification."""
    entry = TAXONOMY.get(alert_category)
    if entry is not None:
        return entry["signal_type"], entry["plain_name"], entry["severity"], entry["attack"]

    severity = PRIORITY_TO_SEVERITY.get(suricata_priority, DEFAULT_SEVERITY_FOR_UNKNOWN_PRIORITY)
    plain_name = alert_category or "Unclassified IDS alert"
    return FALLBACK_SIGNAL_TYPE, plain_name, severity, None
