# Blocked terms

Policies → **Blocked terms** is the one place for words a prompt must not
contain: project code names, client names, confidential markers. It
replaces the term lists that used to live in the gateway settings, in the
policy hierarchy and in policy versions (`backend/app/services/blocked_terms.py`).

## A term

| Field | Values |
|-------|--------|
| term | up to 200 characters, at least two letters or digits |
| applies to | **organization** (gateway, user requests, playground) · **all agents** (gateway) · **team** (gateway calls of the team's agents and its sub-teams') · **agent** · **policy** (user requests of use cases governed by the policy; the playground while it is active) |
| matching | **whole word** (default) or **anywhere** |
| action | **block** - the prompt is refused (`blocked_term:<term>`) · **monitor** - let through and counted; not flagged on the request, so the person or agent being watched does not see it |
| category | optional; a switched-off category switches its terms off |
| on / off, note | |

Two terms with the same letters (see below) and the same scope are the same
term: `Project Titan` and `project-titan` cannot both exist.

## Matching (`backend/app/core/term_match.py`)

Text and term are reduced the same way first:

* Unicode compatibility forms and accents dropped (`Ｐｒｏｊｅｃｔ`, `Tītan`,
  also accents typed as separate marks), case folded;
* look-alike letters of other scripts read as Latin (Cyrillic `о` in
  `Prоject`, Greek `ο`) - on both sides, so a Cyrillic term (`секретно`)
  still finds itself;
* in a word that has letters, digits standing for letters are read as
  letters: `0 o, 1 i, 3 e, 4 a, 5 s, 7 t, 8 b` - a `1` may also stand for an
  `l` (`he11o`, `c1ient`); a number on its own stays a number (`room 105` is
  not "iOS");
* `$` starting a word is an `s`; invisible characters (zero-width space,
  soft hyphen...) are removed.

The text is split into words. Between two words there is a space or a
glue (`_ - . / '` with no space); spaced-out single letters - three or more
(`P r o j e c t`) - are glued. A term matches when its letters appear with the text's spaces
falling only where the term has a word boundary (between its words, at
`_ -`, at camelCase):

* **whole word** - the match starts and ends at word edges: `Project Titan`,
  `project_titan`, `PROJECT-TITAN`, `ProjectTitan`, `P r o j e c t  T i t a n`,
  `Pr0ject T1tan`, `bob@titan.com` match; `class` does not match "ass",
  `the rapist` does not match "therapist", `titanium` does not match "titan";
* **anywhere** - the match may start or end inside a word (`titanium`), but
  still does not run across a space the term does not have (`send it` is not
  "dit").

Terms migrated from the old lists keep **anywhere** (what the old
substring check did); switch them to whole word when that is what you mean.

A text that takes longer than 2 seconds to check against all terms (a
crafted prompt) is refused (`blocked_terms_timeout`) rather than let through
unchecked.

## Hits

Each gateway call, user request or playground message that contains a term
adds one to its count and updates "last seen" - the text is never kept for
this. Monitor terms are the way to see how often a term would fire
before blocking it.

## CSV

**Export** gives `term, match, action, scope, target, category, enabled,
note`; a cell starting with `= + - @` is prefixed with `'` so a spreadsheet
does not run it as a formula. **Import** takes the same columns (only
`term` is required; target and category by name; a missing category is
created), shows a preview first - to add, already there, errors per line -
and adds nothing until confirmed. At most 5 000 rows per import and 5 000
terms per organization.

## Tester

**Try it** runs a sample against every switched-on term (any scope) and the
term being edited, and highlights what each finds. Nothing is stored or
counted.

## Records and permissions

Admins edit; admins and approvers read. Every change is in the audit log
(`blocked_term` created / updated / deleted / imported,
`blocked_term_category`). Removed terms are kept, marked deleted. A team
with terms scoped to it is not deleted (`team.not_empty`, part
`blocked_terms`).

## Upgrading (migration `b5e7a9c1d3f6`)

| From | To |
|------|----|
| gateway settings | all agents |
| policy hierarchy, organization / team / agent level | organization / team / agent; the key is removed from the level (its YAML is then shown from the document) |
| policy versions | that policy: terms of the latest approved version and of every version a use case is linked to |

`blocked_terms` sent to the gateway settings, in a hierarchy document or in
a new policy version is refused with a pointer to this page. Old policy
versions keep their rules as history.

## API

- `GET /api/v1/blocked-terms` · `POST` · `PATCH /{id}` · `DELETE /{id}`
- `POST /categories` · `PATCH /categories/{id}` · `DELETE /categories/{id}` (its terms stay, uncategorized)
- `POST /test` `{"sample": "...", "term": {"term": "...", "match": "word", "action": "block"}}`
- `GET /export.csv` · `POST /import` `{"csv": "...", "dry_run": true}`
