# Contributing to Provenza

Thanks for your interest! This document explains how to file issues,
set up a development environment, and submit changes.

## Code of Conduct

By participating in this project you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Report bugs** — open an issue using the *Bug report* template.
- **Suggest features** — open an issue using the *Feature request* template.
- **Fix a bug or implement a feature** — open a pull request.
- **Improve docs** — README, CONTRIBUTING, examples, comments.
- **Add tests** — more coverage is always welcome.
- **Answer questions** — in GitHub Discussions or issues.

## Development setup

### Requirements

- Python 3.12
- Node.js 20+
- Docker + Docker Compose v2
- PostgreSQL 16 (via docker compose)
- Redis 7 (via docker compose)

### Getting started

```bash
git clone git@github.com:kironovlaziz-del/provenza.git
cd provenza

# 1. Environment files
cp .env.example .env
cp backend/.env.example backend/.env

# 2. Start Postgres and Redis
docker compose up -d

# 3. Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head

# 4. Frontend
cd ../frontend
npm install
Then run backend and frontend in two terminals:# backend
cd backend && source .venv/bin/activate
uvicorn app.main:app --reload --port 8000

# frontend
cd frontend
npm run devOpen http://localhost:3000 and register a new organization at /register.
Making changes
Branching

    main is protected. All changes go through pull requests.

    Create a branch from main with a descriptive name:

        feature/short-description

        fix/short-description

        docs/short-description

        refactor/short-description

Commits

Write clear, focused commit messages. Prefer the imperative mood:

    ✅ Add retry logic to discovery worker

    ❌ added retry logic

    ❌ fixes stuff

Group related changes into a single commit; avoid mixing refactors
with features.
Coding conventions

Backend (Python):

    4-space indentation, 100-char line length (see .editorconfig).

    Async everywhere in request handlers.

    New list endpoints must return Page[T] (see schemas/pagination.py).

    Raise api_error(status, "domain.code", **context) instead of
    hard-coded messages so the frontend can translate.

    Keep user-facing text out of backend code.

Frontend (TypeScript/React):

    2-space indentation.

    Client components need "use client" at the top.

    API calls go through lib/api.ts; components never call axios directly.

    All UI text must live in locales/en.json and locales/uz.json.
    No hard-coded strings in JSX.

    Prefer CSS classes (see utility set in globals.css) over inline styles.

TestsBackend tests live in backend/tests/:cd backend
source .venv/bin/activate
pytest                        # run all
pytest tests/test_auth.py     # one file
pytest -k test_login          # filter by name
pytest --cov=app              # with coverageNew behaviour should come with a test. Bug fixes should come with a
regression test that would have caught the bug.
Frontendcd frontend
npx tsc --noEmit              # type check
npm run build                 # production build (must pass)Pull requests

    Push your branch and open a PR against main.

    Fill in the PR template.

    Make sure CI is green (tests, build, security scan).

    A reviewer will look at the PR — expect comments and follow-ups.

    Once approved, the PR is squash-merged or merged via rebase
    depending on the reviewer's choice.

Keep PRs small and focused. If a change touches more than ~500 lines,
consider splitting it.Reporting security issues

Do not open a public issue for security vulnerabilities.
See SECURITY.md for the responsible disclosure process.
Licence

By contributing, you agree that your contributions will be licensed
under the Apache License 2.0 (see LICENSE).
