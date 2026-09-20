# Explainable analysis rules

These are educational heuristics, not a measured probability of compromise or
a complete password-strength estimator. No breach database or network is used.

## Strength

Character groups are lowercase, uppercase, digits, and non-whitespace symbols.
Check the following conditions in this order:

| Condition | Classification | Base points |
|---|---|---:|
| 16+ characters and 3+ groups | VERY_STRONG | 100 |
| 12+ characters and 3+ groups | STRONG | 80 |
| 8+ characters and 2+ groups | MODERATE | 50 |
| Otherwise | WEAK | 20 |

Length uses Java `char` count (UTF-16 units), not Unicode grapheme count. These
simple categories can underestimate long passphrases and overestimate complex
but predictable passwords; the separate pattern check helps with the latter.

## Reuse and patterns

Reuse is an exact, case-sensitive password comparison within the current user's
accounts. A hash bucket is only an optimization; actual equality is always
checked, so a hash collision cannot incorrectly report reuse. Report counts show
**accounts affected**, not the number of distinct reused-password groups.

Pattern checks are case-insensitive: common words (`password`, `welcome`,
`letmein`, `admin`), username/email local part of 3+ characters, 3 repeated
characters, 3 ascending/descending ASCII digits, 3 consecutive keyboard-row
letters in either direction, and year-like numbers from 1900 to 2099. This is
deliberately a small, explainable rule set; it does not catch every pattern.

## Score and risk

Account score = max(0, strength points - reuse penalty - pattern penalty).
Subtract 30 once for reuse, and 20 once if any pattern is found. Multiple pattern
findings explain the problem but do not repeatedly subtract points.

| Account score | Risk |
|---|---|
| 0-24 | CRITICAL |
| 25-49 | HIGH |
| 50-74 | MEDIUM |
| 75-100 | LOW |

Overall score is the rounded arithmetic mean of all account scores. For zero
accounts, the UI shows `N/A` and asks the user to add an account. It does not
present an empty vault as secure. High-risk statistics include HIGH and CRITICAL.

Example: a MODERATE password reused across two accounts and containing a pattern
scores max(0, 50 - 30 - 20) = 0, so each affected account is CRITICAL.
Recommendations are generated from each account's actual findings.
