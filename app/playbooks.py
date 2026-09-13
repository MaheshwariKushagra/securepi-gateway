#!/usr/bin/env python3
"""
SecurePi Gateway - ATT&CK tags and analyst playbooks for step 6.4's
Incident workbench.

ENHANCEMENT-PLAN.md's V4 catalogue entry and step 6.4's own row both ask
for an "ATT&CK badge" and a "per-signal playbook". Both are built here as
static, per-signal-type content - not the full Stage 2 D7 ("cross-signal
campaign correlation + MITRE ATT&CK"), which would tag individual events,
build a campaign object linking incidents across tactics, and hasn't been
built. This is the minimal, honest slice 6.4 itself needs: a label on
each incident naming the real MITRE ATT&CK tactic/technique it maps to
(when one genuinely applies), and a short piece of guidance for an
analyst looking at it.

ATT&CK mapping is deliberately NOT forced onto every signal. Three of
this project's six signals do not get a tag, with the reason stated
rather than a guessed technique:

- malicious_domain fires on ad/tracker BLOCKLIST HIT VOLUME, which
  EVALUATION-RESULTS.md's own finding G3 already documents as frequently
  triggered by normal Android ad-SDK retry traffic, not by contact with
  confirmed-malicious infrastructure. Tagging it with a C2/DNS-tunnelling
  technique would overstate what it actually detected.
- new_device is an informational registry event, not an attack pattern.
- adblock_ineffective is about this project's OWN ad-removal degrading,
  not about anything the network did - it has no attacker-side technique
  at all.

The three signals that DO get a tag:

- port_scan -> Discovery / T1046 Network Service Discovery. A clean,
  well-established match: many distinct ports touched on one host in a
  short window IS the behaviour that technique describes.
- brute_force -> Credential Access / T1110 Brute Force. Equally clean:
  repeated failed connections against an auth port.
- volume_anomaly -> tagged at the TACTIC level only (Exfiltration,
  TA0010), with no technique id. A statistical z-score anomaly on total
  bytes doesn't match one specific exfiltration technique - it is one of
  the few externally observable signs that tactic can leave, which is
  why NDR products flag it at the tactic level rather than pretending to
  have identified a technique.
"""

ATTACK_MAPPING = {
    "port_scan": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Network Service Discovery", "technique_id": "T1046",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "brute_force": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique": "Brute Force", "technique_id": "T1110",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "volume_anomaly": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique": None, "technique_id": None,
        "url": "https://attack.mitre.org/tactics/TA0010/",
        "note": "Tactic-level only - a statistical volume anomaly is one of the few "
                "externally observable signs of this tactic, but doesn't match one "
                "specific technique.",
    },
}

PLAYBOOKS = {
    "port_scan": {
        "what_it_means": "A device touched enough distinct ports on one host, within a short "
            "window, to look like reconnaissance rather than normal browsing traffic.",
        "how_to_check": "Open the evidence chain below for the destination host and the exact "
            "ports touched. Some legitimate software does this too - a media-server discovery "
            "scan, a network-mapping app, a router's own health check - so check whether this "
            "device is expected to run anything like that.",
        "recommended_action": "If the behaviour is expected, mark this false positive rather "
            "than resolving it, so it doesn't get re-investigated next time. If it isn't, "
            "quarantine the device from its own page and find out what's actually running on it.",
    },
    "brute_force": {
        "what_it_means": "A device made enough failed connection attempts against an "
            "authentication-style port (SSH/Telnet/RDP-range) in a short window to look like "
            "credential guessing rather than a handful of accidental retries.",
        "how_to_check": "Check the evidence chain for the destination and port. Rule out a "
            "misconfigured legitimate service on your own network (a backup job or monitoring "
            "probe with a stale password) before assuming an attacker.",
        "recommended_action": "If it's a misconfigured legitimate service, fix the "
            "configuration and mark false positive. If the device attempting this isn't one you "
            "recognize, quarantine it immediately.",
    },
    "malicious_domain": {
        "what_it_means": "This device's blocked-DNS-lookup count against the ad/tracker "
            "blocklist crossed the threshold in a short window. This is blocklist HIT VOLUME, "
            "not a confirmed malicious destination - it is frequently just an app's ad SDK "
            "retrying its own requests (see EVALUATION-RESULTS.md finding G3).",
        "how_to_check": "Look at the actual domain names in the evidence chain, not just the "
            "count. A handful of distinct, well-known ad-network domains is most likely normal "
            "ad traffic. The same unfamiliar domain hit many times in a tight burst is more "
            "worth a closer look.",
        "recommended_action": "For confirmed ad-SDK noise, mark false positive. For a domain "
            "that genuinely looks suspicious, use \"Block this domain\" to cut it off "
            "immediately, then investigate the device that queried it.",
    },
    "new_device": {
        "what_it_means": "A device the registry had never seen before joined the network. This "
            "is informational, not itself a threat signal - most of the time it's a new phone, "
            "laptop, or IoT device being set up.",
        "how_to_check": "Open the device's own page and check its hostname, its fingerprint "
            "evidence (step 6.2), and what it's talked to so far.",
        "recommended_action": "Resolve this once you recognize the device. If it's not "
            "something you or anyone in the household set up, quarantine it and investigate "
            "before resolving.",
    },
    "adblock_ineffective": {
        "what_it_means": "SecurePi's own YouTube ad-removal (the Tier 2 mitmproxy-based DPI "
            "rewriter) appears to be missing more ads than usual for this device. This is a "
            "platform-effectiveness signal about OUR OWN filtering, not a network threat - "
            "it usually means YouTube changed its ad markup and the DPI ruleset needs updating.",
        "how_to_check": "Open Filtering -> DPI rules and check the addon's own hit-rate stats "
            "for the fields/renderers currently configured.",
        "recommended_action": "Update the ad-field or ad-renderer rules to match what YouTube "
            "is currently sending. Resolve once effectiveness recovers; if the drop turns out "
            "to be temporary and self-corrects, false-positive is also reasonable.",
    },
    "volume_anomaly": {
        "what_it_means": "This device moved noticeably more data than its own learned "
            "hour-of-day baseline, by more standard deviations than the configured threshold "
            "(Settings -> Detection Thresholds). This is a statistical anomaly, not a confirmed "
            "exfiltration detection.",
        "how_to_check": "Check the device's traffic chart for the flagged hour against its "
            "baseline badge. Consider whether a large legitimate transfer - a backup, a big "
            "download, a video call - explains it.",
        "recommended_action": "If legitimate activity explains it, mark false positive; the "
            "baseline adapts over time. If the volume is genuinely unexplained, investigate what "
            "this device sent and to where.",
    },
}


def get_attack(signal_type):
    """The real MITRE ATT&CK tag for this signal, or None if this signal
    type is deliberately not mapped (see the module docstring for why)."""
    return ATTACK_MAPPING.get(signal_type)


def get_playbook(signal_type):
    """The analyst playbook for this signal type, or None for a signal
    type this module doesn't recognize (should not happen in practice -
    every entry in webapp.py's SIGNALS list has one)."""
    return PLAYBOOKS.get(signal_type)
