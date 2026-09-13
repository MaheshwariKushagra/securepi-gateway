#!/usr/bin/env python3
"""
SecurePi Gateway - tracker company attribution.

Turns a blocked or contacted domain into a plain company name, so the
console can say "Device X contacted 6 tracking companies, 4 blocked"
instead of just listing raw hostnames.

This is a small, hand-curated map, NOT the full DuckDuckGo Tracker Radar
or Disconnect entity list. Those datasets are far larger (thousands of
domains) and carry their own licence terms (Tracker Radar in particular
restricts redistribution outside DuckDuckGo's own products), so rather
than bundle or silently subset one of them, this file lists the ~50
companies most likely to actually show up in this project's own traffic:
the ad/analytics SDKs bundled into ordinary Android and iOS apps, plus
the ad-tech networks that the blocklists already in use (AdGuard DNS
filter, OISD, HaGeZi) are built to catch. See ENHANCEMENT-PLAN.md step 5.3.

If this project ever needs the full dataset, the right move is to add an
explicit, cited import step for one licensed source - not to grow this
list domain by domain until it becomes an uncredited copy of one.
"""

# company name -> list of domain suffixes. A queried domain matches a
# suffix `d` if it equals `d` or ends with `.` + `d`.
TRACKER_COMPANIES = {
    "Google (Ads/Analytics)": [
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "google-analytics.com", "googletagmanager.com", "googletagservices.com",
        "admob.com", "adservice.google.com",
    ],
    "Google (Firebase/Crashlytics)": [
        "firebaseinstallations.googleapis.com", "firebaselogging-pa.googleapis.com",
        "crashlytics.com", "app-measurement.com", "firebaseremoteconfig.googleapis.com",
    ],
    "Meta / Facebook": [
        "facebook.com", "fbcdn.net", "graph.facebook.com", "connect.facebook.net",
        "an.facebook.com",
    ],
    "Amazon Advertising": [
        "amazon-adsystem.com", "aax.amazon-adsystem.com",
    ],
    "Microsoft Advertising / Clarity": [
        "clarity.ms", "bat.bing.com", "ads.microsoft.com",
    ],
    "TikTok / ByteDance": [
        "analytics.tiktok.com", "ads-api.tiktok.com", "log.byteoversea.com",
        "log.tiktokv.com", "tiktokcdn.com",
    ],
    "Criteo": ["criteo.com", "criteo.net"],
    "Taboola": ["taboola.com"],
    "Outbrain": ["outbrain.com"],
    "AppNexus / Xandr (Microsoft)": ["adnxs.com"],
    "Rubicon Project / Magnite": ["rubiconproject.com", "chocolateplatform.com"],
    "PubMatic": ["pubmatic.com"],
    "OpenX": ["openx.net"],
    "Index Exchange": ["casalemedia.com", "indexww.com"],
    "Media.net": ["media.net"],
    "MoPub (AppLovin)": ["mopub.com"],
    "AppLovin": ["applovin.com"],
    "Unity Ads": ["unityads.unity3d.com", "unity3d.com"],
    "ironSource": ["ironsrc.com", "supersonicads.com"],
    "Chartboost": ["chartboost.com"],
    "Vungle": ["vungle.com"],
    "AdColony": ["adcolony.com"],
    "Moat (Oracle)": ["moatads.com"],
    "Scorecard Research (comScore)": ["scorecardresearch.com"],
    "Quantcast": ["quantserve.com", "quantcount.com"],
    "AppsFlyer": ["appsflyer.com"],
    "Branch": ["branch.io", "app.link"],
    "Adjust": ["adjust.com"],
    "Kochava": ["kochava.com"],
    "Segment (Twilio)": ["segment.io", "segment.com"],
    "Mixpanel": ["mixpanel.com"],
    "Amplitude": ["amplitude.com"],
    "Sentry": ["sentry.io"],
    "Bugsnag": ["bugsnag.com"],
    "Hotjar": ["hotjar.com"],
    "FullStory": ["fullstory.com"],
    "Yandex Metrica": ["mc.yandex.ru", "yandex.ru"],
    "DoubleVerify": ["doubleverify.com"],
    "Integral Ad Science": ["adsafeprotected.com"],
    "Smart AdServer (Equativ)": ["smartadserver.com"],
    "Adform": ["adform.net"],
    "Teads": ["teads.tv"],
    "Sharethrough": ["sharethrough.com"],
    "Neustar": ["exelator.com"],
    "Oracle BlueKai": ["bluekai.com"],
    "Adobe Experience Cloud": ["demdex.net", "omtrdc.net", "everesttech.net", "2o7.net"],
    "MediaMath": ["mathtag.com"],
    "Tapad": ["tapad.com"],
    "AddThis (Oracle)": ["addthis.com"],
    "Snap Inc.": ["sc-static.net", "snapads.com"],
    "The Trade Desk": ["adsrvr.org"],
}

# Built once at import time: exact-suffix lookup avoids scanning every
# company's domain list for every query.
_DOMAIN_TO_COMPANY = {
    d.lower(): company
    for company, domains in TRACKER_COMPANIES.items()
    for d in domains
}


def attribute_domain(domain):
    """Return the tracker company for `domain`, or None if it isn't in
    this curated list. Matches the domain itself or any subdomain of it
    ('googlesyndication.com' also matches 'pagead2.googlesyndication.com')."""
    if not domain:
        return None
    domain = domain.lower().rstrip(".")
    if domain in _DOMAIN_TO_COMPANY:
        return _DOMAIN_TO_COMPANY[domain]
    for suffix, company in _DOMAIN_TO_COMPANY.items():
        if domain.endswith("." + suffix):
            return company
    return None
