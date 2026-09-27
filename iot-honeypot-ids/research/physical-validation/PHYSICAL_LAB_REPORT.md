# Physical Lab Validation Report

## Status

Physical validation was **NOT RUN** for this freeze. No Pi, attacker host, or analysis server was contacted, and no telemetry, detection, latency, or resource measurements were collected. Network identifiers are intentionally omitted from this tracked report.

## Current software checks

See [FINAL_VERIFICATION_REPORT.md](../../docs/research/FINAL_VERIFICATION_REPORT.md) for this freeze's commands and results. The prior 869-test figure in the archived report has been superseded by the current 874-test unit run; it is not a physical validation result.

## Operator procedure

Follow [DEMO.md](../../../DEMO.md) for the current live demonstration steps and safety boundaries. Set local addresses and unique credentials in ignored environment files. Run the E2E procedure from the analysis host only after services are available. Physical measurements are recorded using `scripts/research/measure-pi.sh` and the adjacent measurement schema; do not substitute estimates for readings.
