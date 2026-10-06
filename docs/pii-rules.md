# PII rules

Policies → **PII rules** decides what the Prompt Firewall
(`backend/app/services/prompt_firewall.py`) looks for before a prompt leaves
and what it does with it. The rules apply in the LLM gateway, user AI
requests and the provider playground; the masked views of stored text
(observability) use them too, where *block* only masks.

## Built-in types

| Type | Finds | Default |
|------|-------|---------|
| `EMAIL`, `PHONE`, `CREDIT_CARD`, `SSN`, `IP_ADDRESS`, `API_KEY` | regular expressions | on, mask |
| `PERSON`, `ORG`, `LOCATION` | the NER model when configured (`PROMPT_FIREWALL_NER_*`), and the Uzbek gazetteer | on, mask |

Each type can be switched off, or set to **block**: a prompt containing it is
refused (the reason names the type, never the value; flag
`blocked_pii:<type>`). **Mask** replaces the value with `[MASKED:<TYPE>]`
(flag `masked:<type>`). Without any settings every type is on and masks -
the behaviour before this page existed.

## Your rules

A rule is a name, a label (`[MASKED:<LABEL>]`, A-Z 0-9 _, not a built-in
type), a regular expression (the `regex` module's syntax), *ignore case*,
mask or block, on or off. Your rules are checked first: a 14-digit ПИНФЛ
caught by a rule is masked as `PINFL`, not as a card number. A built-in type
set to block still blocks wherever it is found, unless one of your rules
covers that whole value. Start-from
presets: ПИНФЛ `\b[3-6]\d{13}\b`, ИНН `\b[2-7]\d{8}\b`, passport
`\b[A-Z]{2}\d{7}\b`, contract number `\b(?:ДОГ|DOG)-\d{4}/\d{1,6}\b` -
adjust them to your data.

**Try it** runs a sample through the firewall with the current settings and
the rule being edited, highlights what the rule finds and shows what the
provider would get. Nothing is stored.

### Slow patterns

Some regular expressions take exponential time on a crafted input
(catastrophic backtracking): `(a|aa)+$` on forty `a`s and a `!` runs for
minutes; `.*.*x` takes time growing with the square of the whole prompt. A
rule runs on every prompt, so (`backend/app/core/pii_patterns.py`):

1. **Before saving**, the parsed pattern is refused when it has
   - a back reference;
   - a variable-length repetition inside another repetition (`(a+)+`,
     `(\w+\s?)*`, `(.*a){20}`, `(\d{3}-?){3}` - write the parts out:
     `\d{3}-?\d{3}-?\d{3}`);
   - alternatives inside a repetition (`(a|aa)+` - use a character class
     like `[-\s]`);
   - an open-ended repetition of characters that include spaces (`.*`,
     `\D+`, `[^@]+`, `[a-z ]*` - prose is one long run of those): give it a
     limit, like `[^\n]{0,50}`;
   - counts whose product is over 1000 (`(?:a{1000}){1000}` would take
     gigabytes to compile);
   - a brace that is not a count (the run-time engine reads `{e<=3}` as
     fuzzy matching - write `\{` for a brace);
   - more than 500 characters, or a match of empty text.
2. **Also before saving**, it runs over 20 000 characters of prose-like
   text with its own literal parts placed in it (at the start, all through,
   and with the last one missing) and must finish within 50 ms - a fifth of
   the run-time limit for a fifth of a 100 000-character prompt. The live
   tester skips this step; saving runs it.
3. **At run time** every rule has 250 ms per text, all rules together
   500 ms per text, and in the gateway 1 s of rule time for all messages of
   a request. A rule that runs out of time - or no longer compiles -
   **refuses the prompt** (flag `pii_timeout:<label>`): letting unchecked
   text through would defeat the rule. The page shows how often that
   happened. In masked views of stored text, such text is withheld. A rule
   that finds more than 10 000 values in one text counts as matching all of
   it (the whole text is masked, or blocked).

What can still be slow is a quadratic pattern over a long run of narrow
characters (`\w+@` on a 100 000-letter "word"): fast on real text, and a
crafted prompt only gets itself refused.

## Records

Every change is in the audit log: `pii_settings` / `updated` (each type
before and after), `pii_rule` / `created`, `updated` (changed fields before
and after), `deleted`. Removed rules are kept, marked deleted.

## API

- `GET /api/v1/pii` (admin, approver): types, rules, NER status, limits.
- `PUT /api/v1/pii/builtin` (admin): `{"types": {"EMAIL": {"action": "block"}}, "revision": 3}`.
- `POST /api/v1/pii/rules`, `PATCH /api/v1/pii/rules/{id}` (with `revision`), `DELETE /api/v1/pii/rules/{id}` (admin).
- `POST /api/v1/pii/test` (admin, approver): `{"sample": "...", "rule": {"pattern": "...", "label": "...", "action": "mask"}, "rule_id": 4}`.

Concurrent edits are refused (`409 pii.stale`) rather than overwritten.
