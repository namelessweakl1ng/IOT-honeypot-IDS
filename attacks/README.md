# Controlled attack runner

Install `requirements.txt`, copy `.env.example` to `.env`, export its values, then run one named manifest against one explicit target:

```bash
python -m attacks.runner.run multi-honeypot-attack --target "$HONEYPOT_IP"
```

## Safety boundary

`attacks/runner/safety.py` requires the target to be a usable private address inside `LAB_SUBNET`; loopback, public, network, and broadcast addresses are rejected before network activity. The runner never discovers hosts or iterates CIDRs and can connect only to SSH 2222, Telnet 2223, camera 8081, router 8080, IoT TCP 9000, and MQTT 1883. Scenarios contain no callbacks, persistence, downloads, scanning, malware, arbitrary URLs/ports, or exfiltration.

## Persona-aware actions

HTTP steps retain simple GET and compatible Basic authentication, while `auth_mode: form` submits URL-encoded `username` and `password` using a cookie jar so camera/router redirects complete normally. SSH accepts a backward-compatible `command` or a `commands` list executed in one interactive Cowrie shell. IoT steps send only bounded persona commands. MQTT steps encode valid MQTT 3.1.1 packets and may set deterministic `client_id` and `topic` values; standalone bounded SUBSCRIBE remains supported by the persona.

Every run writes a JSON ground-truth summary to ignored `attacks/runs/`, including the manifest SHA-256, timestamps, expected detection, and intent-aware step outcomes. Supplying both `--experiment-id` and `--api-url` also submits that summary to the API; local output is written first.
