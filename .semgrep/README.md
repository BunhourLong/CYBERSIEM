# Custom Semgrep rules
This project's invariants as rules, run by `task security:code` in CI. Only local rules are used, and no code leaves the machine. CodeQL handles generic taint analysis, so these rules cover only what is specific to this project.

- **Add a rule:** when a review or bug finds a pattern a rule could catch, add it to the `.yaml`, with `ruleid: <id>` and `ok: <id>` comments above matching and non-matching lines in the fixture of the same name. See it fail, then pass, with `task security:rules`.
- **Suppress a finding:** put `nosemgrep: <id> -- why this is safe` on the line. The reason is required, and the reviewer checks it.
- **A rule that would fail today ships with its fix,** in the same task, so the gate never stays red.
- **Limits:** rules see one function or file, and find patterns, not logic bugs. Whether a route checks the right role stays with the route test and the reviewer.
