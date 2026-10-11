# Releasing the Python SDK

Releases go to PyPI from GitHub Actions
(`.github/workflows/release-sdk-python.yml`) through **Trusted Publishing**:
PyPI trusts the workflow's OIDC identity, so no API token exists to leak.

## One-time setup (a PyPI account owner)

1. On pypi.org, open **Your account → Publishing → Add a new pending
   publisher** and enter:

   | field | value |
   |---|---|
   | PyPI project name | `provenza` |
   | Owner | `kironovlaziz-del` |
   | Repository name | `provenza` |
   | Workflow name | `release-sdk-python.yml` |
   | Environment name | `pypi` |

   A pending publisher reserves the name until the first upload. `provenza`
   was free on PyPI on 2026-10-11.
2. On GitHub, open **Settings → Environments → New environment** and create
   `pypi`. Add yourself as a **required reviewer**, so that every upload
   waits for a human click.

## Each release

1. Set `__version__` in `src/provenza/__init__.py` (semantic versioning;
   `0.x` while the API may still change). Add the release to
   `CHANGELOG.md`.
2. Merge to `main`, then tag that commit:

   ```bash
   git tag sdk-python-v0.1.0
   git push origin sdk-python-v0.1.0
   ```

3. The workflow checks that the tag equals the version, runs the tests,
   builds the sdist and wheel, and runs `twine check --strict`. It then
   waits for the `pypi` environment approval and publishes.

Before tagging, you can build and check locally:

```bash
pip install build twine
python -m build && twine check --strict dist/*
```
