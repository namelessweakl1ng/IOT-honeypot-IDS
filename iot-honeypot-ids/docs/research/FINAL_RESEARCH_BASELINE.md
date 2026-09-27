# Final research baseline

## Frozen implementation scope

Root Next.js is the single dashboard. `iot-honeypot-ids/` is the canonical runtime and research project. FastAPI owns domain behavior, Elasticsearch stores telemetry, and the Pi forwards honeypot events through Filebeat and Logstash. Root Next routes are a server-side browser facade.

The project has two separate research tracks: IoT-23 flow classification (public benchmark) and TRAPSIG physical campaigns (controlled validation). IoT-23 has a parser, explicit label mappings, compatibility map, provenance, and preparation/audit workflow. Public archive download and model evaluation were not run in this environment. Physical lab remains NOT RUN.

## Evidence boundaries

DEMO fixtures are synthetic development material and are not research evidence. LIVE telemetry must come from the configured backend. EMPTY means no confirmed data. Public dataset evaluation measures performance on IoT-23 network flows; physical validation measures the Pi event/session pipeline. Neither substitutes for the other. Rule output is detector output; ground truth remains independently sourced.

No benchmark score, resource measurement, physical latency, or field performance is asserted by this baseline. See [claims audit](CLAIMS_AUDIT.md), [methodology](RESEARCH_METHODOLOGY.md), [dataset card](datasets/IOT23_DATASET_CARD.md), and [physical lab report](../../research/physical-validation/PHYSICAL_LAB_REPORT.md).
