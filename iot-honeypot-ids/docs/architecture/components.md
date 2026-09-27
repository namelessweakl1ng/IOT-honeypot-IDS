# Component inventory

Every container that runs in the platform, grouped by host.

## Pi 4 (4 GB RAM) — `pi/docker-compose.yml`

| Container      | Image                                 | Mem limit | CPU cap | Profile     |
|----------------|---------------------------------------|-----------|---------|-------------|
| `pi-cowrie`    | `cowrie/cowrie:latest`                | 256 MB    | 0.5     | cowrie      |
| `pi-camera`    | built from `honeypots/camera`         | 96 MB     | 0.25    | camera      |
| `pi-iot-service` | built from `honeypots/iot-service`  | 64 MB     | 0.2     | iot-service |
| `pi-collector` | built from `collector`               | 64 MB     | 0.2     | collector (optional) |
| `pi-filebeat`  | `docker.elastic.co/beats/filebeat:8.13.4` | 96 MB  | 0.3     | default     |

These are configured container resource limits, not measured use. Measured
steady-state or attack-load RAM/CPU remain NOT RUN; capture them with
`scripts/research/measure-pi.sh` during physical validation.

## Computer 2 (Fedora analysis host) — `dashboard/docker-compose.yml`

| Container        | Image                                              | Purpose                       |
|------------------|----------------------------------------------------|-------------------------------|
| `pc1-elasticsearch` | `docker.elastic.co/elasticsearch/elasticsearch:8.13.4` | Storage + search         |
| `pc1-logstash`   | `docker.elastic.co/logstash/logstash:8.13.4`       | Telemetry pipeline             |
| `pc1-kibana`     | `docker.elastic.co/kibana/kibana:8.13.4`           | Visualization                  |
| `pc1-api`        | built from `dashboard/api`                         | FastAPI service                |

PC1 RAM sizing:

| RAM   | Notes                                                       |
|-------|-------------------------------------------------------------|
| 8 GB  | Minimum. ES heap 2 GB, LS heap 1 GB, rest for OS + API     |
| 16 GB | Comfortable. ES heap 4 GB, LS heap 2 GB                     |
| 32 GB | Generous. Can train larger models, run experiments in parallel |

## Computer 3 (configured attacker host) — `attacker/`

PC2 does not run any long-lived containers. It runs `./run-scenario.sh`
on demand. The runner is a Bash script that invokes `ssh`, `curl`, `nc`,
and Python one-liners.

Required binaries on PC2:

- `bash` (any version ≥ 4)
- `python3` (≥ 3.8, for the safety check)
- `ssh` + `sshpass` (for SSH scenarios)
- `curl` (for HTTP scenarios)
- `nc` or `python3` (for IoT scenarios — falls back to Python if nc missing)
