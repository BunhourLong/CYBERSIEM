# Learned detection plan
Status: planned, starts after P2. Budget: $0, CPU only. Tasks: T-046 to T-048 in `plan.md` §5.

## The idea
Training means giving software many requests already labelled malicious or normal, and letting it work out which signals matter. The output is a small file of numbers. Nothing learns live in production, and retraining is a deliberate step that has to pass the same tests as any code change.

We don't teach it what SQL injection looks like. OWASP CRS already knows hundreds of attack patterns, but it adds up fixed scores, so one rule can block a legitimate request on one site while missing attacks on another. The model learns **how much to trust each rule, for your traffic**. This approach comes from ModSec-Learn, and it's cheap because CRS does the hard part.

```
request → OWASP CRS → which rules fired? → model weighs them → score → existing reputation engine
                      [942100:1, 941160:0, ...]
```

## Why this approach
- **Evidence:** ModSec-Learn caught about 99.3% of SQL injection at a 1% false-positive rate at paranoia level 4, against 68.6% for plain ModSecurity. Those numbers cover SQL injection only, on a balanced research set, and 1% is far too high for production. Treat them as a reason to try it, not as what we'll get.
- **Explainable:** every point of score traces to named rules, which is what CLAUDE.md invariant 6 requires.
- **Small:** a linear model is a dictionary of weights. Production needs a loop and an addition, not scikit-learn.
- **Hard to overfit to wording:** features are rule hits, not raw text. The ModSec-AdvLearn follow-up shows the same setup can be hardened against crafted evasions.

## Stages
Each stage ends in a yes-or-no gate. A "no" means stop and keep the rules.

### 0. Prerequisites
CRS running in observe mode (T-029), the detection corpus and `task eval` (T-007), and rule IDs stored per request.
**Gate:** CRS rule hits are recorded for real traffic.

### 1. Data (T-046)
| Source | Gives us | Note |
|---|---|---|
| Analyst decisions in the alert queue | Your best labels | Safe/malicious is already collected. Grows with use |
| Your own traffic | Normal requests | Only with tokens and personal data redacted (T-044). Never commit it |
| OWASP CRS regression tests | Labelled attacks by rule family | Apache-2.0 |
| PayloadsAllTheThings, SecLists | Attack strings | MIT. Mostly attacks, so they can't teach what normal looks like |
| `pralab/modsec-learn-dataset` | 500k+ benign and 30k SQL injection samples | **No licence on the repo.** Ask the authors, and keep it for private experiments until then |

Split by time and by site, never randomly. Random splits put near-duplicates of a request on both sides and inflate the score.
**Gate:** at least a few thousand benign requests per site and attacks in every family we plan to score.

### 2. Baseline to beat (T-048)
Run plain CRS scoring and today's detectors through `task eval`, and write down their numbers. Without this, no result means anything.

### 3. First model (T-048)
L1-regularized logistic regression on the rule-hit vector, using scikit-learn on a laptop. Expect minutes of training. It keeps only rules that help and shows each weight. Try LightGBM or Random Forest only if this leaves a measured gap, because they lose the "dictionary of weights" simplicity.
**Gate, on data the model has never seen:** detection is better than the baseline at a false-positive rate of **0.01% or lower**, and 0 benign corpus lines block. Measure at that rate because of volume: 1% on a million requests a day is 10,000 wrong flags.

### 4. Attack it
The `pentester` agent and `WAF-A-MoLE`-style mutations try to evade it. Add successful evasions to the corpus and retrain.
**Gate:** detection under mutation is no worse than the baseline.

### 5. Shadow mode (T-048)
Score real traffic and record the result, with no effect on blocking, for 30 days. Compare with analyst decisions weekly.
**Gate:** it would have added no wrong blocks, and it caught at least something the rules alone didn't.

### 6. Turn on, carefully
It adds capped score to reputation, per site, and can be switched off with one env var. **It never blocks alone.** An inline block still needs a high-confidence CRS match.

### 7. Keep it honest
- Retrain monthly at most, from analyst-confirmed labels only. Attackers can otherwise teach it that their traffic is normal.
- Version every model with its training data's date and its eval results, and keep the previous one for rollback.
- Per-site weights only once a site has enough labels. Until then use the global model.

## Later, only with a measured gap
- **Per-site baselines (T-047):** plain statistics for behaviour that no rule describes, such as one client walking through every ID.
- **Character n-gram features:** can catch unknown payloads, but they're easier to evade and harder to explain.
- **Deep learning:** only with a large, private labelled set and evidence that linear models have plateaued.

## Cost
| Item | Cost |
|---|---|
| Training | Your laptop, minutes |
| Serving | A few lines of Python; no GPU and no new service |
| Data | Free sources, plus your own analysts' decisions |
| Real cost | Your time labelling. About 15 minutes a week in the alert queue is the fuel for this plan |

## Sources
[ModSec-Learn](https://arxiv.org/abs/2406.13547) · [ModSec-AdvLearn](https://arxiv.org/abs/2308.04964) · [modsec-learn code, MIT](https://github.com/pralab/modsec-learn) · [OWASP CRS](https://github.com/coreruleset/coreruleset) · [Coraza](https://github.com/corazawaf/coraza)
