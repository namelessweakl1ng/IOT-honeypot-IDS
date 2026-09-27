# Final Verification Report

## Environment

- Windows workspace, PowerShell; Python 3.14.2; Node dependencies installed temporarily without changing tracked lockfiles.
- No Pi, analysis server, Elasticsearch, or live honeypot services connected.
- IoT-23 archive was not downloaded.

## Results

| Check | Status | Evidence |
|---|---|---|
| Python unit suite | PASS | `python -m pytest tests/unit -q -o addopts= --disable-warnings`: 878 passed, 2 warnings in 63.37s. |
| Python integration suite | SKIPPED | `python -m pytest tests/integration -q -o addopts= --disable-warnings`: 5 skipped because API/Elasticsearch services are unavailable. |
| Frontend Bun tests | FAIL | `npx --yes bun@1.3.6 test`: 57 passed, 25 failed. The failures in `tests/overview-presentation.test.ts` assert the superseded per-page `displayMode` prop design; the current app owns mode in the shell `src/app/page.tsx`. This test contract needs migration. |
| Root frontend lint | PASS | `npm run lint` |
| Root frontend production build | PASS | `npm run build`; Next build, TypeScript, static generation, and standalone copy completed. |
| Compose validation | PASS | `python scripts/testing/validate-compose.py`: both Pi and dashboard compose files validated. |
| Python compile / Git diff checks | PASS | `py_compile` on the importer, validator, feature pipeline, experiment runner, latency recorder, and wrappers; `git diff --check`. |
| Edited shell syntax | PASS | Git Bash `-n` on E2E, preflight, query helpers, test runner, resource recorder, and dataset download scripts. |
| E2E against physical telemetry | NOT RUN | Lab services are unavailable; E2E requires `API_SECRET_KEY`, LIVE mode, and a reachable lab. |
| IoT-23 preparation and benchmark | NOT RUN | No archive or measured dataset results; importer/validator tests use small fixtures only. |
| Physical resource and latency measurements | NOT RUN | No physical Pi/ELK execution. |
| Dependency audit | NOT COMPLETED | npm audit could not run without an npm lockfile; repository lock is Bun. |

## Limits

The build used temporary npm-resolved dependencies without editing tracked lockfiles; this verifies the source tree but is not a lockfile-reproducible build. The Python unit suite initially exposed two outdated E2E contract assertions; those checks now pass after documenting the API-side timestamp lower-bound (`gte`) semantics. The Bun suite remains failing until its obsolete overview tests are migrated. Integration skips and unexecuted dataset and physical procedures do not support runtime or benchmark performance claims.
