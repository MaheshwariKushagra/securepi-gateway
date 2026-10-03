# Heuristic evaluation of the console (step 7.9 replacement, 3 October 2026)

The planned 7.9 study needs 5-8 people who did not build SecurePi. It could not
happen inside the session that closed Stage 7, so 7.9 was replaced by an expert
review. This file is one of its three parts:

1. **This heuristic evaluation:** Nielsen's ten usability heuristics, applied to
   the six study tasks and the main pages.
2. **A cognitive walkthrough of the same six tasks:**
   [`cognitive-walkthrough.md`](cognitive-walkthrough.md).
3. **Measurements:** produced by `tools/usability_expert.py`, results in
   `eval/results/usability/`.
   - Scripted expert paths with click counts and Keystroke-Level Model times.
   - An axe-core accessibility audit.
   - Keyboard-only checks.

**What this is not.** One evaluator, who also built the system, reviewed the
demo console (the real app on synthetic data, `docs/demo`). That gives no task
success rates, no real completion times and no SUS score. It also cannot reveal
the mental models of people who don't already know how the system works. The
participant kit in this folder is unchanged and ready for the real study.

**Setup.**
- Demo console at 1440×900 and 390×844, dark (default) and light themes.
- Served with the gateway's own library versions: FastAPI 0.101.0,
  Starlette 0.31.1, pydantic v1, in `.venv-demo`.
- The newer Starlette 1.x in `.venv-bench` cannot render the console's templates
  (see F17 below).

**Severity scale** (Nielsen): 0 = not a problem, 1 = cosmetic, 2 = minor,
3 = major (should be fixed), 4 = catastrophe.

## Measured task paths

`tools/usability_expert.py paths`. Each path starts on the dashboard. Every path
reached the correct end state, checked through the console's own API.

| Task | Shortest path | Clicks | Keys | Page loads | KLM expert time |
|---|---|---|---|---|---|
| 1. Riskiest device and why | Devices → kali → read the Risk score card | 2 | 0 | 2 | 6.7 s |
| 2. Unbreak HubSpot for the Finance Laptop only | Devices → Finance Laptop → Recently Blocked → Allow (track.hubspot.com) → reason in a browser prompt | 3 | 26 | 2 | 18.7 s |
| 3. Cut kali off for an hour | Devices → kali → Quarantine → 1 hour → reason → Quarantine | 5 | 19 | 2 | 20.7 s |
| 4. Why is doubleclick.net blocked on the Manager iPhone | Devices → Manager iPhone → type in the domain test → read the toast | 3 | 16 | 2 | 15.9 s |
| 5. Strict privacy for the Reception PC | Devices → Reception PC → DNS filtering profile → Strict privacy | 4 | 0 | 2 | 9.2 s |
| 6. Device that used the most data | Devices → read the first row (sorted by download) | 1 | 0 | 1 | 4.0 s |

- **KLM** is the Keystroke-Level Model, using the standard operator times
  listed in the script's docstring. It estimates an error-free expert. Novices
  are typically several times slower.
- **End-state checks:**
  - Task 2: the domain is allowed on the laptop and still blocked on the
    Reception PC.
  - Task 3: quarantined with 3,598 s left.
  - Task 5: the profile is `strict_privacy`.
  - Task 6: the top row matches the device with the most bytes according to
    the API.
- **Keyboard only** (`axe` mode):
  - Device rows **cannot** be reached with Tab.
  - The command palette (⌘K, type, Enter) does open a device.
  - From the top of a device page, Quarantine takes **25 Tab presses**, and its
    menu opens with Enter.

## Accessibility audit (axe-core 4.13, WCAG 2.1 A/AA)

The audit covered 10 pages × 2 themes × 2 widths = 40 page views. Only 2 of
the 40 were clean.

| Rule | Impact | Page views | Where |
|---|---|---|---|
| `color-contrast` | serious | 32 | About 1,100 elements in the dark theme against 16 in the light theme. Cause: the dark tokens `--text-3` `#69758a` and `--muted` `#64748b` reach only 3.4-4.2:1 on the card surfaces (WCAG AA needs 4.5:1). Primary and secondary text pass (6.2-16.7:1) |
| `scrollable-region-focusable` | serious | 20 | Scrolling lists a keyboard can't scroll: dashboard event feed, devices table wrapper, Hunt results and destinations, incident list, settings audit log |
| `link-in-text-block` | serious | 5 | Device links inside sentences on Incidents and Response, distinguishable by colour only |

## Findings by heuristic

### 1. Visibility of system status

The console does this well:
- a live/paused clock and a pipeline-health pill on every page;
- "applied at the gateway" on device controls;
- "Verified 3 s ago" against each enforced policy, plus the Response page's
  read-back of every enforcement point;
- a remaining-time display for timed quarantines.

- **F1 (2) The device page's domain test answers in a toast that disappears**
  after a few seconds. Task 4's whole answer lives there. The same test on the
  Filtering page leaves a persistent result box.
- **F2 (2) "Native telemetry profile" pre-selects a profile that isn't
  applied.** The dropdown shows "Apple (iOS/macOS) telemetry (3)" while the text
  under it says "No native-tracker profile applied". It reads as already on.

### 2. Match between system and the real world

Incident titles are plain sentences ("Possible brute-force attempt against
10.10.0.20 (SSH)"), and policy reasons are shown in the operator's own words.

- **F3 (1) Internal terms leak into the interface:**
  - "Tier 2" and "HTTPS ad removal (Tier 2)";
  - "Baseline: learning (0/7d)";
  - "JA3" in the fingerprint;
  - "Chain" as a risk-score row;
  - "Enforcement points".

  Each is explained somewhere (tooltips, card footers), but not where the term
  first appears.
- **F4 (2) "Blocked by a blocklist rule" says what, not why.** On the device
  page the domain test doesn't name the list or the matching rule, although the
  API returns both and the Filtering page shows the rule. Task 4 asks "why".

### 3. User control and freedom

- Quarantine has a duration from the start, plus Extend and Release.
- Every policy can be ended from the Response page.
- Pause is time-boxed.

- **F5 (1) No undo after "Allow".** The toast confirms the allow, but removing
  it means finding it on the Response page.

### 4. Consistency and standards

- **F6 (2) The device page's Allow / Allow 1h buttons ask for the reason with
  the browser's own `prompt()`.** Every other action uses the console's dialog,
  whose own code comment says it "replaces window.prompt() for every Stage 4
  action (a browser dialog blocks the whole page and can't show context)". The
  prompt also doesn't say the allow covers this device only.
- **F7 (1) Two different "profiles" on one card behave differently.** The DNS
  filtering profile applies the moment it is changed. The native telemetry
  profile needs a separate Apply button.

### 5. Error prevention

- Quarantine and turning filtering off both need a confirmation and a reason.
- Allow is scoped to the device by default.

- **F8 (2) Changing the DNS filtering profile applies immediately, with no
  confirmation,** unless the choice is "Unrestricted". Moving through a focused
  dropdown with the arrow keys changes a device's filtering on the spot.

### 6. Recognition rather than recall

- **F9 (3) The Devices list doesn't show the risk score.** `/api/devices`
  already returns `risk_score` and `risk_band`, and the dashboard and device
  pages show risk. But the one page that lists every device side by side ranks
  by traffic, not risk.
  - So "which device is riskiest" (task 1) means inferring it from the
    Incidents column, or knowing to open each device.
  - The facilitator's hint for task 1 exists because of this.

### 7. Flexibility and efficiency of use

- A command palette (⌘K), time-range presets, CSV export, saved Hunt searches,
  and a phone bottom tab bar.

- **F10 (3) Device rows open only on a mouse click** (`onclick` on the table
  row). There is no link and no Tab stop, so a keyboard or switch user cannot
  open a device from the Devices list. The palette works, but only for someone
  who knows it exists.

### 8. Aesthetic and minimalist design

The visual design is consistent and calm, with colour reserved for severity.

- **F11 (1) The device page is long:** about 3,300 px at desktop width. Recently
  Blocked, which task 2 needs, sits below the fold under the risk and incident
  cards. At phone width the breadcrumb truncates the device's name ("Rec…").

### 9. Help users recognise, diagnose and recover from errors

Failures produce specific toasts ("The DNS filter did not accept the change",
"Could not reach the DNS filter"). No issues beyond F1 and F4.

### 10. Help and documentation

Cards carry short explanations: the risk-score formula, the Response page's
"every row is desired state" footer, and the tooltips on settings.

- **F12 (1) No glossary or help link for the terms in F3.**

### Accessibility (from the audit)

- **F13 (3) Dark-theme contrast.** `--text-3` and `--muted` are below 4.5:1 on
  every surface (above). Dark is the default theme.
- **F14 (2) Six scrolling regions can't be scrolled with a keyboard.**
- **F15 (1) Links inside sentences are marked by colour only.**

### Found on the way (engineering, not a heuristic)

- **F17 (2) The console's templates use Starlette's old
  `TemplateResponse(name, context)` call.** Starlette 1.x has removed it, so an
  Ubuntu upgrade of `python3-starlette` past 1.0 would break every console page.
  The gateway runs 0.31.1 today. The new `TemplateResponse(request, name,
  context)` form works on both versions.

## Recommendations, in priority order

1. **F13:** raise the dark theme's `--text-3`/`--muted` to about `#8792a6`
   (about 5:1 on `--surface-3`). This is a two-token change.
2. **F9:** add a sortable Risk column to the Devices list. The data is already
   in the API response.
3. **F10, F14, F15:**
   - make each device name in the table a real link (the row can keep its
     click);
   - give scrolling regions `tabindex="0"` and a label;
   - underline links that sit inside sentences.
4. **F1, F4, F6:**
   - show the device page's domain test in a persistent result box with the
     rule and list, like the Filtering page;
   - move Allow / Allow 1h to the console dialog, saying "for this device
     only".
5. **F2, F7, F8:**
   - make the telemetry selector start empty ("Choose…");
   - confirm profile changes the way Unrestricted already is.
6. **F17:** switch the 13 `TemplateResponse` calls to the new signature.
7. **F3, F5, F12:** add a short glossary and an Undo action on the "Allowed"
   toast.

None of these was changed during Stage 7: the code was frozen for the
evaluation. They are queued for Stage 8.
