# ZeroPulse Release Checklist

**Verification date:** 2026-11-24  
**Branch:** `main`  
**Docker:** CLI available; daemon unavailable. Docker-backed checks below were not run.

## Verification

| Area | Status | Evidence / notes |
|---|---|---|
| Docker Compose configuration | PASS | `docker compose -f docker-compose.yml config --quiet` passed using process-only placeholder values for required variables. |
| Backend Docker image build | NOT VERIFIED | Docker daemon did not respond to `docker info`; image build could not run. |
| Frontend Docker image build | NOT VERIFIED | Docker daemon did not respond to `docker info`; image build could not run. |
| PostgreSQL healthcheck | NOT VERIFIED | Compose config defines `pg_isready`; container health was not observed. |
| Redis healthcheck | NOT VERIFIED | Compose config defines `redis-cli ping`; container health was not observed. |
| Backend / frontend container startup | NOT VERIFIED | No containers could be started without a working Docker daemon. |
| Existing backend test suite | PASS | `cd backend; npm test` — exit 0; 33 passed, 0 failed, 0 skipped. |
| Frontend production build | PASS | `cd frontend; npm run build` — exit 0. |
| Frontend lint | PASS | `cd frontend; npm run lint` — exit 0. |
| Authentication and protected API behavior | PASS | Existing tests cover valid and invalid JWT/session states, revoked-session HTTP 401, and Redis-failure HTTP 503 using test doubles. Live database/cache authentication remains unverified. |
| CAEP parsing, risk scoring, and enforcement | PASS | Existing backend tests cover event parsing, risk threshold behavior, Redis/PostgreSQL revocation calls, and denied requests using test doubles. |
| Socket.IO revocation notification | PASS | Existing test receives a revocation event over a local Socket.IO connection and confirms it is scoped to the affected session. |
| Browser forced logout | NOT VERIFIED | Frontend code handles the revocation event by clearing the local token and navigating to login, but no browser E2E run was performed. |
| Full live CAEP-to-browser revocation flow | NOT VERIFIED | Redis Pub/Sub, PostgreSQL, Redis session state, and browser behavior were not exercised together in the Compose stack. |
| README benchmark figures | PASS | README values match the existing sanitized reports to the displayed precision; benchmarks were not rerun. |
| Benchmark report sanitization | PASS | Report key scan found no account, token, session, event, or credential identifier fields; existing tests also assert safe-report exclusions. |
| `.env` ignore rule / example | PASS | `.env` patterns are in `.gitignore`; `.env.example` contains replacement placeholders, not actual secrets. |
| Tracked credential file | FAIL | `backend/.env` is tracked and has populated credential-like values at lines 7, 12, and 13. Values are intentionally omitted. `.gitignore` does not untrack files already in Git. Do not publish this file; remove it from tracking/history and rotate any values that were valid. |
| Staged credential changes | PASS | No staged changes were present at inspection. |
| Dependencies, generated files, and volumes | PASS | `node_modules` and frontend `dist` are ignored, not tracked; benchmark `results/` is empty; Compose volumes are named runtime volumes, not repository files. |
| README, architecture, Docker, and benchmark docs | PASS | README, `docs/architecture.mmd`, and `backend/benchmark/README.md` are present. Compose configuration validates. |
| Demo recording guide | NOT VERIFIED | README has local demo instructions, but no dedicated recording guide was found. |
| Demo recording | MANUAL | No video recording was found. Record and review a demo before claiming it is complete. |
| GitHub branch and remote | PASS | Current branch is `main`, tracking `Zeropulse/main`; remote URL is `https://github.com/Tannistha-Pal/Zeropulse.git`. |
| GitHub release readiness | FAIL | A tracked `.env` with populated credential-like values must be addressed before publication. No commit or push was performed. |

## Worktree baseline

At initial inspection, the worktree already contained 14 modified tracked files and 26 untracked ZeroPulse files, with no staged changes. These were present before this checklist was created; no unrelated changes were identified. This checklist is the only file added during verification. The tracked `backend/.env` was not modified.

The existing worktree changes cover the README, Compose setup, backend hardening and tests, Docker files, benchmark tooling/reports, frontend Docker/Nginx configuration, and architecture documentation. Review the current `git status` before staging; do not stage `backend/.env`.

## Remaining manual steps

1. Remove `backend/.env` from version control and its history, and rotate any real credentials it contained.
2. Start Docker Desktop/Engine, then build and start the Compose stack; verify PostgreSQL and Redis health, backend/frontend readiness, authentication, and Redis failure behavior.
3. Perform a browser demo of CAEP-triggered notification, forced logout, and a subsequent HTTP 401; create a recording and add a recording guide if required.
4. Review the final staged diff and sanitized files before committing or pushing.
