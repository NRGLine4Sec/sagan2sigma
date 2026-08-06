# Conceptual overlap with SigmaHQ

This document describes `sagan2sigma-conceptual`, a second and deliberately
separate analysis from the behavioural one in
[`SIGMAHQ-OVERLAP.md`](SIGMAHQ-OVERLAP.md). Read the framing in section 1 before
the results, because the whole risk of this analysis is being mistaken for the
other one.

## 1. What it is, and what it is emphatically not

The behavioural analysis proves, by running the RSigma engine, that two rules
fire on the same event. This analysis proves nothing of the sort. It looks at
what a rule is *about*, from the distinctive terms it searches for and the
ATT&CK techniques it declares, and it proposes pairs a human should look at.

- Its output is **review candidates, not verdicts.** A shared term is a hint
  that two rules may be written to catch the same thing, not evidence that they
  do.
- It is **not grounds for retiring any rule.** Nothing here licenses dropping a
  converted rule. Only the behavioural analysis, and a human, can support that.
- It exists to cover the ground the behavioural method cannot reach. Most
  converted rules match the raw syslog body and so can never fire the same event
  as a SigmaHQ rule matching a structured field, even when both are plainly
  written for the same attack. A lexical and tag comparison is the only thing
  that can pair those, and it does so as a triage aid, nothing more.

Why this caution is not merely rhetorical is shown in section 5: of the 1,346
candidate pairs this analysis proposes, only 11 also appear in the behavioural
analysis, and only 6 are behaviourally confirmed coverage. The two methods see
almost entirely different things. That is the point, and also the warning.

## 2. Method

### 2.1 A concept fingerprint per rule

Each rule becomes two things: the set of ATT&CK techniques it declares, and a
bag of distinctive tokens drawn from its title, its description, and, above all,
the literal strings it actually searches for. The literals carry the most
signal: a rule looking for `sethc.exe` or `win32_shadowcopy` states what it
detects far more precisely than any title, and two rules that both look for the
same rare artefact are very likely about the same thing. Tokens keep the inner
dots and hyphens of file names and commands, so `set-psreadlineoption` stays
whole, and a stoplist removes words too generic to ever be evidence.

### 2.2 Weighting by rarity

A shared token matters only in proportion to how rare it is. Two rules both
mentioning `powershell` say little; two both mentioning `set-psreadlineoption`
say a great deal. Inverse document frequency, computed over both corpora
together, captures exactly that, and the lexical score between two rules is a
cosine over their IDF-weighted token vectors: it rewards sharing rare terms and
is unmoved by sharing common ones. ATT&CK techniques are weighted the same way
by their own inverse frequency, so a shared broad technique like Valid Accounts
(`t1078`) counts for almost nothing while a shared narrow one counts for a lot.

### 2.3 Lexical leads, ATT&CK corroborates

The two signals are kept separate rather than folded into one number. A
candidate is proposed only when the **lexical similarity clears a floor**;
technique agreement can then raise a lexically-plausible candidate in the
ranking, but it can never create one on its own. This is deliberate. An early
version without the floor paired a converted Apache authentication rule with a
SigmaHQ Huawei BGP rule on nothing but two broad shared techniques and the word
"authentication". Requiring lexical support first removes that whole class of
false pairing.

The search is blocked for tractability: a converted rule is only ever compared
against SigmaHQ rules with which it shares at least one *distinctive* token,
found through an inverted index. Two rules sharing no rare term are not close by
this method's lights, so skipping them costs nothing.

### 2.4 Every candidate shows its evidence

Each proposed pair carries the distinctive tokens and techniques behind it, so a
reviewer reads one row, sees why the tool paired the two rules, and decides in
seconds whether it is right. The computation is pure lexical arithmetic, so it
needs no engine, runs in about a minute and a half over the full corpora, and is
byte-identical between runs.

## 3. The taxonomy, such as it is

There is only one relation here, "candidate", scored by a composite of the
lexical cosine and the corroborating technique weight. That is intentional: with
no engine in the loop there is no containment to establish, so there is no
`EQUIVALENT` or `REDUNDANT`. A high lexical score with a rare shared term is a
strong candidate; a score near the floor with one common-ish term is a weak one,
and the shared-terms column is there so the reader can tell them apart without
trusting the number.

## 4. Results

Run over the same corpora as the behavioural analysis (`rsigma-syslog` profile,
SigmaHQ with `rules-placeholder/` excluded), with the default lexical floor of
0.35 and up to three candidates kept per converted rule:

| Metric | Value |
| --- | ---: |
| Converted rules | 7,911 |
| SigmaHQ rules | 4,013 |
| Converted rules with at least one candidate | 798 |
| Candidate pairs | 1,346 |

The strongest candidates are unambiguous, and they are exactly the pairs the
behavioural method cannot see, because both sides match structured Sysmon or
PowerShell fields the converted rule reaches only through the raw body:

| Converted rule | Candidate SigmaHQ rule | Lexical | Shared terms |
| --- | --- | ---: | --- |
| `[WINDOWS-SYSMON] KeePass Password Dumping` | Remote Thread Created In KeePass.EXE | 0.59 | `keepass.exe`, dumping, password |
| `[WINDOWS-POWERSHELL] Create Volume Shadow Copy` | Create Volume Shadow Copy with Powershell | 0.76 | `win32_shadowcopy`, shadow, volume |
| `[WINDOWS-SECURITY] Sticky Key Backdoor` | Sticky Key Like Backdoor Execution | 0.44 | `sethc.exe`, `utilman.exe`, sticky |
| `[WINDOWS-SECURITY] Possible Rclone Exfiltration` | PUA - Rclone Execution | 0.42 | `multi-thread-streams`, `ignore-existing` |
| `[WINDOWS-POWERSHELL] Local User Create` | PowerShell Create Local User | 0.40 | `new-localuser`, local, powershell |

Weaker, near-floor candidates are visibly weaker in the same column, for example
a converted log-clearing rule paired with `Security Event Log Cleared` on the
single shared term "cleared". The column is the point: a reviewer keeps the
first group and discards the second in seconds.

## 5. How this relates to the behavioural analysis

This is the number that justifies keeping the two apart. Of the 1,346 conceptual
candidate pairs:

- **11** also appear anywhere in the behavioural analysis;
- **6** are behaviourally confirmed as log-source-compatible coverage;
- **1,335** have no behavioural co-firing at all.

So the two lenses are almost disjoint, and each is strongest where the other is
blind. The behavioural analysis is silent on raw-text rules because they share
no event vocabulary with structured SigmaHQ rules; this analysis pairs them on
shared terms. A pair that shows up in **both** is the strongest evidence the
project can produce: conceptually about the same thing, and confirmed to fire on
the same event. Those six are worth looking at first.

The practical reading: treat the behavioural 58 as the deployable-coverage list,
and treat these 1,346 as a review queue for detection engineers deciding, rule
by rule, whether a converted rule is worth keeping now that SigmaHQ is deployed.
The two answer different questions and neither replaces the other.

## 6. Limits, stated plainly

- **Lexical is not semantic.** Sharing a rare term is strong evidence and
  sharing a common one is weak, but neither is understanding. Two rules can
  share `powershell` and detect entirely different things; the floor and the IDF
  weighting reduce this but do not remove it. Read the shared terms.
- **ATT&CK coverage is lopsided.** Only about 9% of converted rules carry an
  ATT&CK technique, against 88% of SigmaHQ rules, so the technique signal helps
  on a minority of converted rules and the lexical signal does most of the work.
- **A candidate is not coverage.** This bears repeating because it is the one
  way to misuse the report: nothing here says a rule can be dropped.
- **It is a starting point for review, deterministic and cheap to re-run** as
  either corpus moves, not a conclusion.

## 7. Reproducing this

```sh
pip install sagan2sigma        # no extra needed; this analysis is pure stdlib
sagan2sigma sagan-rules -o converted
sagan2sigma-conceptual \
  --converted converted/rules \
  --sigmahq /path/to/sigmahq \
  --output conceptual [--min-lexical 0.35] [--top-k 3]
```

It writes `CONCEPTUAL-OVERLAP-REPORT.md`, the ranked candidate list with
evidence, and `conceptual-overlap-report.json`, the same untruncated and
machine-readable. Raising `--min-lexical` yields fewer, stronger candidates.
