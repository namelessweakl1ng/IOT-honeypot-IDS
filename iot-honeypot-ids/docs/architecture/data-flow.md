# Data flow — end-to-end telemetry path

```
+--------+   attack     +-------------+   JSON log    +----------+
|  PC2   | -----------> | Pi honeypots| ------------> | Filebeat |
+--------+              | (Cowrie /   |               +----------+
                        |  Camera /   |                     |
                        |  IoT svc)   |                     | Beats
                        +-------------+                     v
                                                    +----------------+
                                                    | PC1 Logstash   |
                                                    |  (parse,       |
                                                    |   normalize,   |
                                                    |   enrich)      |
                                                    +-------+--------+
                                                            |
                                                            v
                                              +-----------------------------+
                                              | PC1 Elasticsearch           |
                                              |  honeypot-events-*          |
                                              |  honeypot-sessions-*        |
                                              |  honeypot-detections-*      |
                                              |  honeypot-errors-*          |
                                              |  honeypot-training-*        |
                                              +--------------+--------------+
                                                             |
                                       +---------------------+--------------------+
                                       |                                          |
                                       v                                          v
                                +-------------+                            +----------------+
                                | PC1 Kibana  |                            | PC1 FastAPI    |
                                | (dashboards)|                            | (sessions, ML) |
                                +-------------+                            +-------+--------+
                                                                                   |
                                                                                   v
                                                                        +-------------------+
                                                                        | model-lab CLI     |
                                                                        | (train/eval/replay)|
                                                                        +-------------------+
```

## Step-by-step

1. **PC2** runs `./run-scenario.sh --target <pi_ip> --scenario ssh-bruteforce`.
2. The runner refuses if `target` is not inside `LAB_SUBNET`.
3. The runner opens SSH connections to `<pi_ip>:2222` (Cowrie's port).
4. **Cowrie** logs each connection / auth attempt / command as a JSON event
   to `/var/log/cowrie/cowrie.json` inside the container (named volume).
5. **Filebeat** (running on the Pi) tails that file, parses the JSON, and
   ships it to PC1 Logstash over TCP 5044.
6. If PC1 is unreachable, Filebeat spools to disk and retries — no data
   is lost.
7. **Logstash** (on PC1) receives the event, normalizes fields into the
   ECS-style schema, enriches with attack stage / classification tags, and
   routes to the appropriate index.
8. Malformed events are routed to `honeypot-errors-*` (never silently
   discarded).
9. **Elasticsearch** indexes the event.
10. **Kibana** visualizes the data via the imported dashboards.
11. **FastAPI** exposes `/sessions`, `/detections`, `/models`, `/experiments`,
    `/replay` to the React dashboard.
12. The **model-lab CLI** pulls session events from ES, extracts features,
    trains a model, evaluates it on a held-out session-level split, and
    persists the model under `model-lab/models/<id>/`.

## Failure handling

| Failure                  | Behavior                                                  |
|--------------------------|-----------------------------------------------------------|
| PC1 unreachable          | Pi keeps running; Filebeat spools locally                 |
| Logstash down            | Filebeat retries with backoff; no data lost              |
| Elasticsearch down       | Logstash back-pressures; data buffered in pipeline queue  |
| ML service down          | ELK + Kibana still work; replay unavailable               |
| One honeypot crashes     | Docker restarts it (unless-stopped policy)               |
| Pi host SD card full     | Resource limits + log rotation prevent runaway writes   |
