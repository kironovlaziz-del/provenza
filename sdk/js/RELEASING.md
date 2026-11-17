# Releasing the JS/TS SDK

Releases go to npm from GitHub Actions
(`.github/workflows/release-sdk-js.yml`) through **trusted publishing**
(OIDC). No npm token is stored anywhere, and npm attaches a provenance
attestation that links the package to the commit and workflow that built
it.

The workflow only **stages** a version (`npm stage publish`). It goes live
when a maintainer approves it on npmjs.com with their npm two-factor
authentication, so a compromised workflow or GitHub account cannot release a
version on its own.

## One-time setup (an npm account owner)

1. Publish the first version by hand, because npm attaches a trusted
   publisher to an existing package:

   ```bash
   cd sdk/js
   npm ci
   npm test
   npm publish --access public
   ```

2. On npmjs.com, open **provenza → Settings → Trusted publishing**, add
   GitHub Actions and enter:

   | field | value |
   |---|---|
   | Organization or user | `kironovlaziz-del` |
   | Repository | `provenza` |
   | Workflow filename | `release-sdk-js.yml` |
   | Environment | `npm` |
   | Allow npm publish | unchecked (only staged publishing) |
   | Allow npm dist-tag | unchecked |

3. In **Publishing access**, choose "Require two-factor authentication and
   disallow bypass 2fa tokens".
4. On GitHub, open **Settings → Environments** and create `npm`, with
   yourself as a required reviewer.

## Each release

1. Bump `version` in `package.json` and `VERSION` in `src/index.ts`. A test
   keeps the two equal. Add the release to `CHANGELOG.md`.
2. Merge, then tag that commit and push the tag:

   ```bash
   git tag sdk-js-v0.2.0
   git push origin sdk-js-v0.2.0
   ```

3. The workflow checks that the tag equals the version, runs the tests,
   waits for the `npm` environment approval, then stages the version with
   provenance.
4. On npmjs.com, open **provenza → Staged Packages**, check the version and
   approve it with your two-factor authentication (or run
   `npm stage approve provenza@<version>`). Only then does it go live.
