---
name: new-detector
description: Use when adding or changing a detector, its patterns or thresholds, or an alert's weight in CyberSIEM.
---

Detectors extend `Detector` (`src/security_engine/detectors/base.py`). An alert can end in a block, so a false positive here locks out a real person.

1. **Corpus first.** Add attack lines and at least as many look-alike benign lines to `tests/corpus/` (from T-007). Run `task eval` and see the new attack lines missed or the benign lines firing.
2. **Failing unit test** next to the existing detector tests, using `HTTPLogEvent` directly with no database.
3. **Least code that passes.** Reuse the shared decoding and window helpers if they exist.
4. **Bounded state:** any per-IP dict or deque needs eviction. IPs are attacker-chosen, so unbounded means a memory leak on demand.
5. **Thresholds and weights come from env**, documented in `stack/.env.example`. Add the type to `DEFAULT_ALERT_WEIGHTS`, since an unknown type falls back to its severity's weight.
6. **Severity decides blocking.** Before choosing `high`, check `evaluate_ip_reputation()`: one unresolved high alert can hold an IP blocked until an analyst reviews it. Use `high` only when a benign request can't plausibly match.
7. **Trust nothing in the event:** log fields are attacker-controlled, and metadata is rendered in the analyst UI.
8. Register it in `src/security_engine/engine.py`, then run `/verify`. Report the before and after `task eval` rates in the task's "Learned".
