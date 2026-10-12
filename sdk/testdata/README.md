# Shared test data for the SDKs

`canonical-vectors.json`: the canonical form and SHA-256 that the **server**
computes (backend/app/core/agent_signing.py) for JSON a client sends. Each
SDK must produce exactly these outputs. Some cases differ from a naive port:

- Python sorts object keys by code point;
- non-ASCII is escaped as `\uXXXX`;
- floats use Python's `repr`, so `1e-07` and `1e-05` appear in exponent form.

Generated from the server's code, never edited by hand. To add a case,
append its JSON text to the list in the generator and re-run it from
`backend/`:

```python
import json
from app.core.agent_signing import canonical_text, content_hash
texts = [...]   # raw JSON texts as a client would send them
json.dump([{"json": t, "canonical": canonical_text(json.loads(t)),
            "sha256": content_hash(json.loads(t))} for t in texts],
          open("../sdk/testdata/canonical-vectors.json", "w"), indent=1)
```

Used by `sdk/js/test/sdk.test.mjs` and `sdk/go/canonical_test.go`.

`proxy-descriptor-vectors.json`: the checked input of a request through the
egress proxy (docs/pvp/spec.md, 5.5): route, method, path as sent, raw query
and body. The proxy (`proxy/internal/egress/proxy_test.go`, through its real
handler) and the SDKs' proxy checks (`sdk/python/tests/test_proxy.py`) must
compute exactly these descriptors, or every SDK-mode request is refused as a
mismatch.
