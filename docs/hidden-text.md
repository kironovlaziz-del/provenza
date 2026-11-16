# Hidden text in tool definitions

A person approves a tool by reading its definition; the agent's model reads
the same definition character by character. Some characters break that link:
the screen shows one thing and the model reads another. A tool poisoned
this way passes review because there is nothing to see.

- **Unicode tag characters** (U+E0000-E007F) spell ASCII that no font draws
  ("ASCII smuggling"): `Read a file.` on screen can be followed by an
  invisible `ignore previous instructions and ...` that the model reads.
- **Bidirectional controls** (U+202A-202E, U+2066-2069) show text in another
  order than it is stored ("Trojan Source").
- **Variation selectors** carry one byte each: one emoji can hide a whole
  message in the selectors after it.
- **Zero-width and other invisible characters**, private-use characters,
  and long blank runs that push text out of view.

## What Provenza does

Every MCP tool definition, A2A agent card and HTTP tool is checked
(`backend/app/pvp/hidden_text.py`) - every string and every key, including
the input schema:

| Found | Approval | Served to agents |
|-------|----------|------------------|
| tag characters (outside an emoji flag), bidi controls, control characters, variation-selector data | **refused** | **no** - not even a tool approved before this check existed |
| zero-width / invisible characters (a joiner inside an emoji is fine), private-use characters, 40 blank characters or 10 line breaks in a row | only after the approver **confirms** having seen them | yes, once approved |
| anything else - accents, other scripts, emoji | as usual | as usual |

An HTTP tool cannot be saved with text of the first kind.

The definition is never cleaned: a rewritten definition would no longer
hash to what the upstream serves, and the approval pins that hash. The
server's owner removes the hidden text; the next sync shows the clean
definition for approval.

## Where it shows

**Gateways → MCP servers → tools**: a tool with findings carries
*Hidden text* or *Invisible characters*; *Full definition* shows the whole
definition as the model reads it, with every invisible character written
out (`⟦U+200B⟧`) and tag characters as the text they spell
(`⟦hidden: ignore previous instructions⟧`). The same for A2A peers. Approving
from the Tool Registry page applies the same rules to the definition the
entry pins.

API: `GET /mcp-servers/{id}/tools` and `GET /a2a-peers` give `definition`
(MCP), `hidden` (each finding: `path`, `kind`, `count`, `codepoints`, and
`hidden` - the decoded text) and `hidden_level` (`clean`, `confirm`,
`refuse`). Approval (`POST .../approve`, also `/tool-registry/{id}/approve`)
answers `409 tool.hidden_text` for a refused definition and
`409 tool.hidden_text_confirm` until the body says `{"confirm_hidden": true}`.
The audit record of the approval names what was confirmed (`hidden_text`).
