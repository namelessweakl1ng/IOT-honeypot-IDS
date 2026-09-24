# Kibana saved objects
#
# NDJSON exports of:
#   - index patterns (honeypot-events-*, honeypot-sessions-*, ...)
#   - dashboards (SOC overview, attack timeline, source IP analysis, etc.)
#   - searches / visualizations used by those dashboards
#
# Import via Kibana UI: Stack Management -> Saved Objects -> Import
# Or via API: POST /api/saved_objects/_import
#
# These are optional — Kibana works without them. They are provided so
# a fresh deployment gets a useful SOC-style dashboard immediately.
