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
- dns_bypass (ENHANCEMENT-PLAN.md step 2.2) fires on DoH/DoT/QUIC/Private-
  Relay indicators, but modern OSes and browsers increasingly enable
  encrypted DNS BY DEFAULT for ordinary privacy reasons (iOS 14+'s
  Private Relay, Firefox's DoH rollouts) - not to evade THIS network's
  policy specifically. Tagged at the TACTIC level only (Defense Evasion,
  TA0005), the same treatment volume_anomaly gets for the same reason:
  real evidence of evaded filtering, not reliable evidence of intent.
- new_device is an informational registry event, not an attack pattern.
- ids_other (ENHANCEMENT-PLAN.md step 2.3's fallback bucket for every
  Suricata/ET alert category not in signature_taxonomy.py's curated set -
  overwhelmingly "Misc activity"-style informational alerts on this
  gateway's own real traffic) gets no technique tag, for the same
  distinct-hit-volume-isn't-intent reasoning as malicious_domain.
- adblock_ineffective is about this project's OWN ad-removal degrading,
  not about anything the network did - it has no attacker-side technique
  at all.

The signals that DO get a tag:

- port_scan -> Discovery / T1046 Network Service Discovery. A clean,
  well-established match: many distinct ports touched on one host in a
  short window IS the behaviour that technique describes.
- network_sweep -> Discovery / T1018 Remote System Discovery. The mirror
  case of port_scan: one port touched across many hosts is "which
  machines exist on this network", not "what does this one machine run" -
  a different, equally well-established technique (ENHANCEMENT-PLAN.md
  step 2.1).
- slow_port_scan / slow_network_sweep -> the SAME two techniques as
  port_scan / network_sweep above. Pacing (fast vs. slow enough to evade
  a short window) changes which SIGNAL notices the behaviour, not what
  the behaviour IS in ATT&CK's terms.
- brute_force -> Credential Access / T1110 Brute Force. Equally clean:
  repeated failed connections against an auth port.
- volume_anomaly -> tagged at the TACTIC level only (Exfiltration,
  TA0010), with no technique id. A statistical z-score anomaly on total
  bytes doesn't match one specific exfiltration technique - it is one of
  the few externally observable signs that tactic can leave, which is
  why NDR products flag it at the tactic level rather than pretending to
  have identified a technique.
- The seven curated ids_* signal types (ENHANCEMENT-PLAN.md step 2.3,
  full mapping in app/signature_taxonomy.py, confirmed against this
  gateway's own real `/etc/suricata/classification.config`): ids_trojan,
  ids_c2 and ids_c2_domain all map to Command and Control / TA0011 (the
  latter two tactic-level only - "malware C2 traffic" and "contacted a
  known C2 domain" don't each pin down one specific technique the way
  trojan-activity's T1071 Application Layer Protocol does).
  ids_exploit_kit -> Initial Access / T1189 Drive-by Compromise.
  ids_shellcode -> Execution / T1203 Exploitation for Client Execution.
  ids_privilege_gain -> Privilege Escalation / TA0004 (tactic-level -
  Suricata's admin/user, attempted/successful classtypes all collapse
  into this one signal_type, and don't share one specific technique).
  ids_credential_theft -> Credential Access / TA0006 (tactic-level - many
  distinct techniques could produce this classtype).
- threat_intel (ENHANCEMENT-PLAN.md step 2.4) -> Command and Control /
  TA0011, tactic-level only. A curated abuse.ch indicator confirms the
  destination itself is malicious infrastructure - real, specific
  evidence - but not which C2 technique this device's own traffic to it
  represents.
- dns_tunneling (ENHANCEMENT-PLAN.md step 2.5) -> Command and Control /
  T1071.004 Application Layer Protocol: DNS. An exact, textbook match:
  this technique's own MITRE definition IS "using DNS as a C2 channel",
  which is precisely the behaviour pattern (many high-entropy subdomains
  or an unusual TXT-query ratio under one domain) this signal looks for.
- dga -> Command and Control / T1568.002 Dynamic Resolution: Domain
  Generation Algorithms. Also an exact match by definition, not an
  inference - a burst of genuine NXDOMAIN lookups with high-entropy
  labels under one domain IS what this technique describes.
  have identified a technique.
"""

ATTACK_MAPPING = {
    "port_scan": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Network Service Discovery", "technique_id": "T1046",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "network_sweep": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Remote System Discovery", "technique_id": "T1018",
        "url": "https://attack.mitre.org/techniques/T1018/",
    },
    "slow_port_scan": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Network Service Discovery", "technique_id": "T1046",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "slow_network_sweep": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Remote System Discovery", "technique_id": "T1018",
        "url": "https://attack.mitre.org/techniques/T1018/",
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
    "dns_bypass": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique": None, "technique_id": None,
        "url": "https://attack.mitre.org/tactics/TA0005/",
        "note": "Tactic-level only - modern devices increasingly enable encrypted DNS by "
                "default for privacy reasons unrelated to evading this network's own "
                "filtering, so a specific technique tag would overstate a single device's intent.",
    },
    "ids_trojan": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique": "Application Layer Protocol", "technique_id": "T1071",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "ids_c2": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique": None, "technique_id": None,
        "url": "https://attack.mitre.org/tactics/TA0011/",
    },
    "ids_c2_domain": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique": None, "technique_id": None,
        "url": "https://attack.mitre.org/tactics/TA0011/",
    },
    "ids_exploit_kit": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique": "Drive-by Compromise", "technique_id": "T1189",
        "url": "https://attack.mitre.org/techniques/T1189/",
    },
    "ids_shellcode": {
        "tactic": "Execution", "tactic_id": "TA0002",
        "technique": "Exploitation for Client Execution", "technique_id": "T1203",
        "url": "https://attack.mitre.org/techniques/T1203/",
    },
    "ids_privilege_gain": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique": None, "technique_id": None,
        "url": "https://attack.mitre.org/tactics/TA0004/",
    },
    "ids_credential_theft": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique": None, "technique_id": None,
        "url": "https://attack.mitre.org/tactics/TA0006/",
    },
    # ids_other deliberately absent - see the module docstring's "does NOT
    # get a tag" section.
    "threat_intel": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique": None, "technique_id": None,
        "url": "https://attack.mitre.org/tactics/TA0011/",
        "note": "Tactic-level only - a curated indicator (abuse.ch Feodo/URLhaus/ThreatFox) "
                "confirms the DESTINATION is malicious infrastructure, but not which specific "
                "technique this device's traffic to it represents.",
    },
    "dns_tunneling": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique": "Application Layer Protocol: DNS", "technique_id": "T1071.004",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
    },
    "dga": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique": "Dynamic Resolution: Domain Generation Algorithms", "technique_id": "T1568.002",
        "url": "https://attack.mitre.org/techniques/T1568/002/",
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
    "network_sweep": {
        "what_it_means": "A device touched the same port on enough distinct hosts, within a "
            "short window, to look like host discovery rather than normal browsing - checking "
            "which machines on the network are alive, typically the step before a targeted scan.",
        "how_to_check": "Open the evidence chain for the port and the exact hosts touched. Some "
            "legitimate software does this too - a network-discovery/media-server app, a backup "
            "tool checking for other backup targets, a router's own LAN health check.",
        "recommended_action": "If the behaviour is expected, mark this false positive. If it "
            "isn't, quarantine the device and find out what's actually running on it - and check "
            "whether a related port_scan incident against one of the swept hosts followed.",
    },
    "slow_port_scan": {
        "what_it_means": "The same pattern as a port scan (many distinct ports on one host), "
            "but paced too slowly for the fast port-scan signal's short window to ever catch "
            "enough of it at once - the deliberate pacing nmap's slower timing templates "
            "(-T0/-T1) use specifically to stay under quick detection thresholds.",
        "how_to_check": "Same as port_scan: open the evidence chain for the destination and "
            "exact ports, spread out over a much longer window this time.",
        "recommended_action": "Same as port_scan. The slow pacing itself is worth noting in an "
            "incident note - it suggests a more deliberate actor than an accidental trigger.",
    },
    "slow_network_sweep": {
        "what_it_means": "The same pattern as a network sweep (one port across many hosts), but "
            "paced too slowly for the fast network-sweep signal's short window to catch.",
        "how_to_check": "Same as network_sweep, over a much longer window.",
        "recommended_action": "Same as network_sweep.",
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
    "dns_bypass": {
        "what_it_means": "This device's traffic showed enough combined signs of routing DNS "
            "around AdGuard - a rejected DoT/DoH/QUIC connection, a query for Firefox's or "
            "Apple's own encrypted-DNS canary domains, or a TLS connection to a known DoH "
            "provider - to cross the threshold. This is very often a normal privacy default "
            "(iOS Private Relay, a browser's own DoH rollout), not an attempt to evade this "
            "network specifically.",
        "how_to_check": "Open the evidence chain and read the breakdown in the description - it "
            "names which specific mechanism(s) were seen and how many times each.",
        "recommended_action": "For a known device with encrypted DNS enabled by its own OS/"
            "browser defaults, mark false positive - filtering continues to apply to every "
            "other device regardless. If this is unexpected for the device (e.g. a device that "
            "should have no reason to seek out a specific third-party DoH provider), investigate "
            "further before deciding.",
    },
    "ids_trojan": {
        "what_it_means": "Suricata/ET Open flagged network traffic matching a known trojan "
            "signature from this device - a signature-based match against published rules, "
            "not this project's own correlation logic.",
        "how_to_check": "Open the evidence chain and read the specific signature name(s) in "
            "the description. Search the signature text online (most ET signature names are "
            "self-describing or documented) to understand exactly what pattern matched.",
        "recommended_action": "Treat as a real finding until ruled out - quarantine the device "
            "and investigate. If it turns out to be a known-benign match against this specific "
            "signature (some are broad), mark false positive.",
    },
    "ids_c2": {
        "what_it_means": "Suricata/ET Open flagged traffic matching known malware command-and-"
            "control patterns from this device.",
        "how_to_check": "Open the evidence chain for the destination and the specific "
            "signature(s) matched.",
        "recommended_action": "Quarantine and investigate - this classtype has no common "
            "benign explanation the way an INFO-level alert might.",
    },
    "ids_c2_domain": {
        "what_it_means": "This device contacted a domain Suricata/ET Open's threat intelligence "
            "identifies as known command-and-control infrastructure.",
        "how_to_check": "Open the evidence chain for the exact domain and destination IP.",
        "recommended_action": "Quarantine and investigate. Also consider blocking the domain "
            "network-wide from the Filtering page.",
    },
    "ids_exploit_kit": {
        "what_it_means": "Suricata/ET Open flagged traffic matching a known exploit-kit "
            "delivery pattern - typically a compromised or malicious website attempting to "
            "silently exploit a browser vulnerability.",
        "how_to_check": "Open the evidence chain for the destination and what the device was "
            "doing just before this fired (recent browsing history in Hunt/explorer).",
        "recommended_action": "Quarantine and investigate, especially if the device's browser "
            "or OS is out of date.",
    },
    "ids_shellcode": {
        "what_it_means": "Suricata/ET Open detected a byte pattern in traffic consistent with "
            "executable shellcode - often a sign of an exploit attempt in progress.",
        "how_to_check": "Open the evidence chain for the destination and protocol involved.",
        "recommended_action": "Quarantine and investigate. Shellcode-pattern matches can "
            "occasionally be triggered by legitimate binary data (e.g. some file transfers) - "
            "check what was actually being transferred before concluding it's malicious.",
    },
    "ids_privilege_gain": {
        "what_it_means": "Suricata/ET Open flagged an attempted or successful privilege-"
            "escalation pattern involving this device, either as source or target.",
        "how_to_check": "Open the evidence chain for the destination, port and specific "
            "signature(s) - this covers several related classtypes (attempted/successful, "
            "user/admin), and which one matters for how urgent this is.",
        "recommended_action": "Investigate promptly, especially for a 'successful' classtype. "
            "Check whether the device or destination is one you administer directly.",
    },
    "ids_credential_theft": {
        "what_it_means": "Suricata/ET Open flagged a pattern consistent with successful "
            "credential theft involving this device.",
        "how_to_check": "Open the evidence chain for the destination and specific signature.",
        "recommended_action": "Treat as urgent - quarantine and change any credentials that "
            "may have been exposed, independent of this console.",
    },
    "ids_other": {
        "what_it_means": "Suricata/ET Open raised enough alerts of the same category from this "
            "device, in a short window, to cross the threshold - but this category isn't one of "
            "the specific patterns this project curates a plain name and ATT&CK tag for (see "
            "app/signature_taxonomy.py). On this gateway's own real traffic, the overwhelming "
            "majority of alerts are ET's own INFO-priority categories like \"Misc activity\" "
            "(e.g. STUN/WebRTC traffic, or a TLS SNI matching a known DNS-over-HTTPS provider) - "
            "genuinely low-value on their own, which is exactly why they're grouped and "
            "thresholded rather than raised one-by-one.",
        "how_to_check": "Open the evidence chain and read the raw category name and specific "
            "signature(s) in the description - the severity shown reflects Suricata's own "
            "priority for this category, not a per-incident judgment.",
        "recommended_action": "For a recognized low-value pattern, mark false positive - "
            "step 2.7's suppression rules (once built) will let a verdict like this apply "
            "automatically going forward instead of needing to be repeated. For anything "
            "unfamiliar, investigate before deciding.",
    },
    "threat_intel": {
        "what_it_means": "This device contacted an IP address or domain that abuse.ch's Feodo "
            "Tracker, URLhaus or ThreatFox feeds - curated, community-run threat intelligence, "
            "refreshed daily - list as confirmed-malicious infrastructure. Unlike a blocklist-"
            "hit-volume signal, this fires on even a single match.",
        "how_to_check": "Open the evidence chain for the exact indicator and which feed(s) "
            "listed it, plus the malware family name if the feed supplied one.",
        "recommended_action": "Treat as a real finding - quarantine the device and investigate. "
            "A confirmed indicator match has a much lower false-positive rate than this "
            "project's other domain-based signals.",
    },
    "dns_tunneling": {
        "what_it_means": "This device queried an unusually large number of distinct, "
            "random-looking subdomains under one domain (or an unusual share of TXT-record "
            "lookups) - a common way malware smuggles data out through DNS, since DNS traffic "
            "is rarely blocked outbound.",
        "how_to_check": "Open the evidence chain for the base domain and the actual subdomain "
            "strings queried. A handful of legitimate services use varied, machine-generated "
            "subdomains too (some CDNs, some IoT cloud platforms) - check whether this device "
            "is expected to talk to anything like that.",
        "recommended_action": "If it's expected traffic, mark false positive. Otherwise "
            "quarantine and investigate - this is a data-exfiltration pattern, not just "
            "reconnaissance.",
    },
    "dga": {
        "what_it_means": "This device looked up a burst of domain names that don't exist "
            "anywhere (genuine NXDOMAIN, not just blocked), with random-looking names - the "
            "classic pattern of malware trying candidate command-and-control domains from a "
            "domain-generation algorithm until one resolves.",
        "how_to_check": "Open the evidence chain for the actual failed domain names. Real "
            "typos and decommissioned services also produce occasional NXDOMAIN, but not a "
            "burst of high-entropy names in a short window.",
        "recommended_action": "Quarantine and investigate promptly - unlike most signals in "
            "this project, this pattern has few ordinary explanations.",
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
