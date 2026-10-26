# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
JSON Schema of every PVP message, generated from app/pvp/model.py.

docs/pvp/schemas/ holds the committed copies, for implementations in other
languages (the SDKs). Regenerate after a model change:

    python -m app.pvp.schema ../docs/pvp/schemas

tests/test_pvp_model.py fails while the committed copies differ.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict

from pydantic import TypeAdapter

from app.pvp.model import MESSAGE_TYPES, PVP_VERSION, PVPMessage

# a URN, not a URL: nothing has to be hosted for the ids to stay valid
SCHEMA_BASE = "urn:provenza:pvp:1:"


def _file(model) -> str:
    return model.model_fields["type"].default + ".schema.json"


def _stable(node: Any) -> Any:
    """The schema the same whatever pydantic generated it: pydantic 2.11 and
    later spell out "additionalProperties": true on free-form objects, which
    is JSON Schema's default and changes nothing - so it is left out."""
    if isinstance(node, dict):
        return {k: _stable(v) for k, v in node.items() if not (k == "additionalProperties" and v is True)}
    if isinstance(node, list):
        return [_stable(v) for v in node]
    return node


def json_schemas() -> Dict[str, Dict[str, Any]]:
    """{file name: schema} - one per message type, plus message.schema.json
    (any message, chosen by "type")."""
    out = {}
    for model in MESSAGE_TYPES:
        schema = _stable(model.model_json_schema())
        out[_file(model)] = {"$schema": "https://json-schema.org/draft/2020-12/schema",
                             "$id": SCHEMA_BASE + _file(model), **schema}
    out["message.schema.json"] = {"$schema": "https://json-schema.org/draft/2020-12/schema",
                                  "$id": SCHEMA_BASE + "message.schema.json",
                                  "title": f"PVP message ({PVP_VERSION})",
                                  **_stable(TypeAdapter(PVPMessage).json_schema())}
    return out


def render(schema: Dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, schema in json_schemas().items():
        (directory / name).write_text(render(schema), encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    write(Path(sys.argv[1] if len(sys.argv) > 1 else "../docs/pvp/schemas"))
