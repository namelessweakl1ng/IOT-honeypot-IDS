# Scripts — cross-machine orchestration entry points

| Folder           | Contents                                                  |
|------------------|-----------------------------------------------------------|
| `setup/`         | One-time setup scripts (clone, install deps, init env)    |
| `development/`   | Dev helpers (lint, typecheck, import sample data)         |
| `deployment/`    | Start / stop / restart / status across machines            |
| `testing/`       | Unit + integration + e2e test runners                       |
| `demo/`          | The single-entry-point demo runner for the final demo      |

All scripts have `.sh` (bash, Fedora/Pi) and `.ps1` (PowerShell, Windows)
variants where applicable. Both invoke the same underlying commands.
