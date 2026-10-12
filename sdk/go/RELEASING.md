# Releasing the Go SDK

Go has no package registry to upload to. A release is a **git tag**, and
`proxy.golang.org` and `pkg.go.dev` pick it up from the public repository.
This module lives in a subdirectory, so its tags carry that directory as a
prefix:

```bash
git tag sdk/go/v0.1.0
git push origin sdk/go/v0.1.0
```

After pushing the tag:

1. Ask the proxy to fetch it, so it shows up right away:

   ```bash
   GOPROXY=proxy.golang.org go list -m github.com/kironovlaziz-del/provenza/sdk/go@v0.1.0
   ```

   pkg.go.dev shows the documentation shortly after; `LICENSE` in this
   directory lets it display the docs.
2. Users install it with `go get github.com/kironovlaziz-del/provenza/sdk/go@v0.1.0`.

Before tagging:

- add the release to `CHANGELOG.md`;
- make sure CI is green (`go vet`, `go test -race`, and the cross-language
  tests in `backend/tests/test_sdk_go.py`).

A published version can never be changed. The proxy keeps it forever, so
fix a mistake with a new version. Tags of `v1` and above are a promise not
to break the API; stay on `v0.x` while it may still change.
