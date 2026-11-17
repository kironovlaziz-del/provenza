# Releases

A release of Provenza is a tag `vX.Y.Z` on `main`. The release workflow
(`.github/workflows/release.yml`) publishes on its GitHub release:

| File | What |
|------|------|
| `provenza-vX.Y.Z.tar.gz` | the source of the tag (`git archive`) |
| `provenza-vX.Y.Z.spdx.json` | SBOM in SPDX: the dependencies the source pins - Python, npm and Go modules |
| `provenza-vX.Y.Z.cdx.json` | the same SBOM in CycloneDX |
| `release.json` | the release record: tag, commit, tree and the SHA-256 of each file above |
| `SHA256SUMS` | the hash of each file |

Each file is signed with a **build provenance attestation**: a Sigstore
signature, keyless, that says *this workflow, in this repository, at this
commit, made exactly this file*. No signing key is kept anywhere - the
identity is the workflow's own, issued by GitHub for that run and logged in
the public transparency log. The source archive also carries an attested
SBOM.

## Checking a release

With the [GitHub CLI](https://cli.github.com/):

```bash
gh release download v0.4.0 -R kironovlaziz-del/provenza
gh attestation verify provenza-v0.4.0.tar.gz -R kironovlaziz-del/provenza
gh attestation verify release.json -R kironovlaziz-del/provenza
sha256sum -c SHA256SUMS
```

Against a checkout: the tag must point at the commit the record names.

```bash
git rev-parse v0.4.0^{commit}
grep '"commit"' release.json
```

## What install.sh and upgrade.sh check

Before installing or upgrading to a tagged release, they fetch its
`release.json` and compare its commit with the checkout:

- the same commit: `✓ vX.Y.Z is the published release` - and, when the
  GitHub CLI is installed and signed in, that the record is signed by the
  release workflow;
- another commit: `THIS IS NOT THE RELEASED CODE` - the tag in this checkout
  was moved, or the checkout came from somewhere else;
- no record: a release made before records existed, or one not published yet;
- not a tag (the default branch): nothing to check against, and it says so.

These are warnings: the scripts go on, and `upgrade.sh` still asks before
upgrading. They catch a moved tag or a substituted mirror; the signature
check (`gh attestation verify`) is what proves the record itself.

## Making a release

1. Versions and `CHANGELOG.md` on `main` (the SDKs are released with their own tags, `sdk-python-v…`, `sdk-js-v…`).
2. `git tag v0.4.0 && git push origin v0.4.0` - the tag must be on `main`.
3. The workflow creates the release as a **draft** with the files above.
   Write the notes, then publish it.
