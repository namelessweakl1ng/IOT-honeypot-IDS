# Kibana saved objects

`trapsig.ndjson` is imported automatically by the `kibana-setup` Compose job. It provisions four data views and seven named research workspaces without sample telemetry or fabricated results. Analysts add or save lab-specific visualizations from live indices in these workspaces.

Manual re-import:

```bash
curl -f -H 'kbn-xsrf: true' -F file=@trapsig.ndjson http://localhost:5601/api/saved_objects/_import?overwrite=true
```
