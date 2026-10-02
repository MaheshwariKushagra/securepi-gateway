# Facilitator notes: success criteria and hints

Checked against the demo on 2 October 2026 (a pilot by the developer, through
the same calls the console's buttons make): the riskiest device is `kali`
(risk 100, the next highest 20), and allowing `track.hubspot.com` for the
Finance Laptop allows it there and nowhere else.

| Task | Success (1) | Partial (0.5) | The one hint, if stuck for a minute |
|---|---|---|---|
| 1. Riskiest device | Names **kali** and says it scanned / attacked another device (the NAS) - port scan or SSH brute force, in any words | Names kali, can't say why | "Is there a way to see devices ranked?" |
| 2. Unbreak HubSpot, one device | An **allow rule for the Finance Laptop only** covering `track.hubspot.com` (or `hubspot.com`); the console's own domain test for the laptop says allowed. Check the Response page: one new `allow_domain` policy, device = Finance Laptop | Allowed it for **every** device, or allowed the right domain but couldn't confirm it | "Is there a list of what's been blocked for that laptop?" |
| 3. Cut off kali for an hour | A **quarantine on kali, timed for 60 minutes** (Response page shows it, with an end time) | Quarantined without a time limit, or the wrong length | "Look at what you can do from that device's page." |
| 4. Why doubleclick.net | Says it is **blocked on purpose by an ad/tracker blocklist** (the domain test or the device's "Recently blocked" shows the list) | Says "it's blocked" without why | "Is there a way to test a domain?" |
| 5. Strict privacy for Reception PC | Reception PC's filtering profile is **Strict privacy** | Chose another profile | "What can you change on that device's page?" |
| 6. Most data | Names the device the Devices page shows at the top by data (note it before the session - usually the **Lobby Smart TV**) | Names the second | "Where would you see devices compared?" |

Stop a task at **5 minutes** (score 0, seconds 300). After the session,
before the next participant, re-run `seed.py` and restart `serve.py`.

What to write in `notes`: where they looked first, anything they said that
shows a wrong mental model ("I thought quarantine meant delete"), and any
console wording they asked about.
