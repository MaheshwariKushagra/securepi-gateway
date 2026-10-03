# Cognitive walkthrough of the six study tasks (step 7.9 replacement, 3 October 2026)

This is part 2 of the expert review that stands in for the 7.9 participant study.
Part 1, with the scope and its limits, is
[`heuristic-evaluation.md`](heuristic-evaluation.md).

**Persona.** Priya manages a small office and has set up a home router through
its web page before. She knows what an IP address and an ad blocker are, but has
no security training. She has never seen SecurePi and gets the task cards in
`tasks.md`, nothing more.

**Method.** Each step on the shortest path (the same paths
`tools/usability_expert.py` measures) gets the four standard walkthrough
questions (Wharton et al., 1994):

- **Q1 Goal.** Will she be trying to do the right thing at this point?
- **Q2 Notice.** Will she notice that the right control is there?
- **Q3 Associate.** Will she connect that control with what she's trying to do?
- **Q4 Feedback.** After acting, will she see that it worked?

Answers: ✓ likely, ? uncertain, ✗ likely to fail. Every ? and ✗ is a
predicted failure point, and the F-numbers refer to the heuristic evaluation.

## Task 1: which device is the riskiest, and why?

| Step | Q1 | Q2 | Q3 | Q4 | Notes |
|---|---|---|---|---|---|
| Open Devices from the sidebar | ✓ | ✓ | ✓ | ✓ | "Devices" is the obvious place for "which device" |
| Find the riskiest row | ✓ | **?** | **?** | - | No risk column (F9). The rows are sorted by download. The cue is the red "3" in Incidents for kali, plus kali's orange "unknown" tag. Some people will choose the heaviest user (Lobby TV) instead |
| Open kali and read the Risk score card | ✓ | ✓ | ✓ | ✓ | "Risk 100 / 100" in the header and a card that lists port scan, slow port scan and brute force. A clear answer |
| Alternative: the dashboard's open-incident list or the Incidents page | ✓ | ✓ | ✓ | ✓ | All three high-severity incidents name kali. Probably the faster route for someone who starts from "something looks suspicious" |

**Predicted:** mostly succeeds. The main risk is ranking by traffic on the
Devices page (F9).

## Task 2: make HubSpot forms work on the Finance Laptop only

| Step | Q1 | Q2 | Q3 | Q4 | Notes |
|---|---|---|---|---|---|
| Open the Finance Laptop | ✓ | ✓ | ✓ | ✓ | |
| Find what's blocked for it | ✓ | **?** | ✓ | - | Recently Blocked sits below the fold under the Risk and Incidents cards (F11). People who stay above the fold won't find it. Some will go to Filtering → Blocklists & rules instead, which is network-wide |
| Recognise `track.hubspot.com` | ✓ | ✓ | ✓ | - | The domain names the vendor |
| Choose Allow or Allow 1h | ✓ | ✓ | **?** | - | Nothing on the row says "for this device only". That is the task's key constraint, and it shows only in a tooltip |
| Type the reason in the browser prompt | **?** | ✓ | ✓ | ✓ | A plain browser dialog with no context (F6). A first-time user may hesitate over whether it is the site or the browser asking. The "Allowed for this device" toast confirms it |
| (Wrong path) Filtering page → Allow | ✓ | ✓ | ✓ | ✓ | Allows it for **every** device: partial credit in the facilitator guide. The page doesn't warn that a per-device option exists |

**Predicted:** the riskiest task. Many people will allow network-wide (partial
credit) or not find Recently Blocked.

## Task 3: cut kali off the internet for an hour

| Step | Q1 | Q2 | Q3 | Q4 | Notes |
|---|---|---|---|---|---|
| Open kali | ✓ | ✓ | ✓ | ✓ | Remembered from task 1 |
| Find Network access → Quarantine | ✓ | ✓ | **?** | - | "Quarantine" is IT language. The description under it ("drops all traffic from this device's MAC at the firewall") helps, but "MAC" and "firewall" are jargon. "Block" under Trust looks just as plausible, and is permanent until changed |
| Choose "1 hour" | ✓ | ✓ | ✓ | - | The menu offers 15 minutes, 1 hour, 24 hours and Until released |
| Give a reason and confirm | ✓ | ✓ | ✓ | ✓ | The dialog says the device will be "released automatically" after 1 hour. The control row then shows "Quarantined · 59m left · Console · enforced at the firewall" |

**Predicted:** succeeds. Some people will choose Trust → Block, which has no
time limit (partial credit).

## Task 4: why is doubleclick.net blocked on the Manager iPhone?

| Step | Q1 | Q2 | Q3 | Q4 | Notes |
|---|---|---|---|---|---|
| Open the Manager iPhone | ✓ | ✓ | ✓ | ✓ | |
| Use the domain test ("Test a domain") | ✓ | **?** | ✓ | - | Below the fold, inside the Recently Blocked card (F11). Filtering → Domain check is the other route and is easier to spot |
| Read the answer | ✓ | **✗** | ✓ | **?** | The device page's answer is a toast that disappears (F1) and says only "Blocked by a blocklist rule" (F4). A participant who looks away misses it, and none of it says the block is an ad/tracker list doing its job. The Filtering page's check gives a persistent box with the matching rule |

**Predicted:** people find the "blocked" part. Many won't be able to say it is
an ad/tracker blocklist (partial credit), especially by the device-page route.

## Task 5: give the Reception PC the "Strict privacy" profile

| Step | Q1 | Q2 | Q3 | Q4 | Notes |
|---|---|---|---|---|---|
| Open the Reception PC | ✓ | ✓ | ✓ | ✓ | |
| Find "DNS filtering profile" | ✓ | ✓ | **?** | - | Two "profile" dropdowns sit on the same card (F7). "Native telemetry profile" also sounds privacy-related and shows a pre-filled value (F2) |
| Choose "Strict privacy" | ✓ | ✓ | ✓ | ✓ | Applies immediately, with a toast and an updated description. Easy, and that ease is also F8: there is no confirmation |

**Predicted:** succeeds. A minority may try the telemetry dropdown first.

## Task 6: which device used the most data?

| Step | Q1 | Q2 | Q3 | Q4 | Notes |
|---|---|---|---|---|---|
| Open Devices | ✓ | ✓ | ✓ | ✓ | |
| Read the top row | ✓ | ✓ | **?** | - | Sorted by Down (download) by default, shown by a small arrow. "Most data" could mean download plus upload. In this demo the order is the same either way, but on another network it might not be. Clicking a column header re-sorts |

**Predicted:** succeeds.

## Summary of predicted trouble spots

| Spot | Tasks | Finding |
|---|---|---|
| Devices list ranks traffic, not risk | 1 | F9 |
| Per-device actions sit below the fold; "this device only" is a tooltip | 2, 4 | F11, F6 |
| Domain test answer is temporary and doesn't say why | 4 | F1, F4 |
| Similar controls side by side ("Block" vs "Quarantine", two profile dropdowns) | 3, 5 | F7, F2 |

All of these are predictions from one expert. The participant study
(`README.md`) is the way to find out how often they actually happen, and whether
there are problems this walkthrough cannot see.
