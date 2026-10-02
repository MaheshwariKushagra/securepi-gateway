# Usability study (ENHANCEMENT-PLAN.md step 7.9)

A moderated, task-based study of the SecurePi console with **5–8 people**,
measuring task success, time on task and the System Usability Scale (SUS).
Everything a facilitator needs is in this folder; the analysis is
`tools/usability_analysis.py`.

| File | What it is |
|---|---|
| `README.md` | This protocol |
| `consent.md` | The consent and information sheet, read and signed before the session |
| `tasks.md` | The six task cards, one per page, in the order they are given |
| `facilitator.md` | Success criteria for each task, what to note, when to stop a task |
| `sus.md` | The System Usability Scale, given right after the last task |
| `observations.csv` | The observer's sheet: one row per participant per task |
| `sus.csv` | One row per participant: their ten SUS answers |

## Who

5–8 adults who did **not** build or test SecurePi. Aim for a mix: at least
two who would call themselves non-technical (they set up a home router at
most), and at least two who are comfortable with technology (they have
changed DNS settings or used a router's admin page). Ask only two background
questions (`observations.csv` columns `tech_level` and `age_band`); nothing
that identifies them is written down - each is `P1`, `P2`, ...

Five participants find most usability problems in a task-based test; eight
narrow the SUS estimate. With n = 5-8 the results are descriptive (medians,
ranges, confidence intervals), not a statistical comparison.

## Where

Not the live gateway: participants work in the **demo console**, which runs
the real console code against an invented network (`docs/demo/README.md`).
Every participant then sees the same devices, the same attack and the same
"broken" site, and nothing they do can affect a real network.

Before **each** session (so every participant starts from the same state):

```bash
cd docs/demo
../../.venv-bench/bin/python seed.py      # fresh invented network, attack ~14 min old
../../.venv-bench/bin/python serve.py     # console at http://127.0.0.1:8765, user securepi / password demo
```

Then, in a browser on the facilitator's laptop: sign in, open the Dashboard,
and hand over. Note from the Devices page which device used the most data
(task 6's answer moves a little from one seed to the next).

## How a session runs (about 30 minutes)

1. **Welcome and consent** (3 min) - read `consent.md` together; sign.
2. **Context, not training** (1 min) - read aloud: *"This is the control panel
   of a home network security box. It watches the devices on a network, warns
   about suspicious behaviour, and blocks ads and trackers. I'm going to give
   you six short tasks. There are no wrong answers - we're testing the
   software, not you. Please think aloud as you go."* No tour of the console.
3. **Tasks** (about 20 min) - hand over the cards in `tasks.md` one at a
   time, in order. Start the clock when they finish reading; stop it when
   they say they're done or give up, or at **5 minutes** (then the task is a
   failure and you move on). Do not help. If they ask, say *"What would you
   try?"*. If they are completely stuck for a minute, you may give **one**
   hint from `facilitator.md` - recorded as an assist.
4. **SUS** (2 min) - `sus.md`, on paper, straight after the last task.
5. **Debrief** (3 min) - *"What was the hardest part? What would you
   change?"* Write the answers in `observations.csv`'s notes.

## Recording

One row per participant per task in `observations.csv`:

- `success`: **1** completed as the criteria say, **0.5** partly (e.g. fixed
  the site for every device instead of one), **0** not done.
- `seconds`: from reading the card to finishing, giving up, or 300.
- `errors`: wrong turns that needed undoing (count).
- `assists`: hints given (0 or 1).

## Analysis

```bash
python3 tools/usability_analysis.py docs/usability-study/observations.csv docs/usability-study/sus.csv
```

Reports per-task success rate with a 95% Wilson interval, median and range
of time on task, errors and assists, each participant's SUS score (the
standard 0-100 scoring), the mean SUS with a 95% t-interval, and where that
falls on Bangor, Kortum and Miller's adjective scale (68 is the commonly
quoted average).
