# DEPRECATED — Old Shell-Based Attacker Framework

**STATUS: DEPRECATED. DO NOT USE.**

This directory contains the old shell-based attacker framework that was
replaced by the Python attack simulator in `../sim/`.

## Why it was deprecated

- Uses `StrictHostKeyChecking=no` — unsafe SSH host-key bypass
- Uses `UserKnownHostsFile=/dev/null` — unsafe known-hosts bypass
- Uses `sshpass` — external dependency with credential-handling risks
- Does NOT enforce hard safety ceilings on connections/auth attempts
- Does NOT support dry-run, manifests, reproducibility, or global budgets
- Creates a second executable attack path — violates the "one authoritative
  implementation" principle

## What replaced it

The canonical attacker implementation is now:

```
attacker/trapsig_attack.py
attacker/sim/
```

See `../sim/README.md` for the supported workflow.

## Files retained for reference only

The files in this directory are kept for historical/reference purposes.
They MUST NOT be executed. They are not part of the supported attacker
workflow.
