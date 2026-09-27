# Final Verification Report

## Environment

- Windows workspace, PowerShell; Python 3.14.2; Node dependencies installed temporarily without changing lockfiles.
- No Pi, analysis server, Elasticsearch, or live honeypot services connected.
- IoT-23 archive was not downloaded.

## Results

| Check | Status | Evidence |
|---|---|---|
| Python unit suite | PASS | `python -m pytest tests/unit -q -o addopts= --disable-warnings`: 874 passed, 2 warnings in 62.03s |
| Python integration suite | SKIPPED | 5 skipped because API/Elasticsearch services are unavailable |
| Root frontend lint | PASS | `npm run lint` |
| Root frontend production build | PASS | `npm run build`; Next build and standalone copy completed |
| Compose validation | PASS | `python scripts/testing/validate-compose.py` |
| Edited shell syntax | PASS | Git Bash `-n` checks on edited research and E2E shell scripts |
| E2E against physical telemetry | NOT RUN | Lab services are unavailable; E2E now requires API_SECRET_KEY and checks detection/session/event lineage |
| IoT-23 preparation and benchmark | NOT RUN | No archive or measured dataset results; fixture tests only |
| Physical resource and latency measurements | NOT RUN | No physical Pi/ELK execution |
| Dependency audit | NOT COMPLETED | npm audit could not run without npm lockfile; canonical repository lock is Bun |

## Limits

The build used temporary npm-resolved dependencies without editing tracked lockfiles; this verifies the current source tree but is not a lockfile-reproducible build. Integration skips and the unexecuted dataset and physical procedures do not support runtime or benchmark performance claims.