# Independent recall labelling — packet and rubric (NOT YET SENT)

## Why this exists

`staledep/seeded.py` was written by me, after building the detector, using my own
reading of the TOCTOU literature. There was no second labeller and no blind
protocol. Two of the three recall gains I reported are therefore circular: I
authored both the case and the thing that catches it, and I split
`derived-value` into two classes in a way that converted a miss into a hit.

**Relabelling my own cases would not fix this.** The packet below goes to someone
who has not seen the detector.

## What the labeller receives

A randomised list of trajectories with **identity hidden**: no class label, no
provenance, no indication whether a case is seeded or drawn from the corpus. Each
item is a bare call sequence with arguments and outputs.

The list mixes:
- the 13 seeded cases, stripped of their `cls` and `why` fields;
- **decoys** — corpus trajectories the detector flags, and corpus trajectories it
  does not, in unknown proportion.

Without decoys the labeller could infer that everything shown is a positive.

## Rubric

For each item, independently of any tool output:

1. Does a later state-changing call depend on state observed by an earlier call?
   **yes / no / unclear**
2. If yes, would mutating that state between the two calls change *what the
   action does* — not merely whether it errors? **yes / no / unclear**
3. Which earlier call is the dependency on? (index)
4. Free-text: one sentence on the mechanism.

Question 2 is the load-bearing one: it is the snapshot-versus-temporal
distinction, asked without naming it.

## Analysis, fixed in advance

- Agreement on Q1 and Q2 reported as Cohen's κ against the detector's labels.
- The detector's recall is recomputed against the **labeller's** Q2 answers, not
  mine. That figure supersedes 8/13.
- Disagreements are listed individually in the writeup. They are the result, not
  noise to be reconciled away.
- If κ < 0.4 the seeded set is not a usable ground truth and the recall claim is
  withdrawn entirely rather than adjusted.

## Status

**BLOCKED — needs a person.** No automated substitute is acceptable: a second
pass by me, or by another model I prompt, reproduces the same construct.
