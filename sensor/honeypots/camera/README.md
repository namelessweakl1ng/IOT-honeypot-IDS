# AsterView CV-210 camera persona

> **Fictional device:** AsterView, AsterView Systems, and the CV-210 are invented for this project. They are not a real manufacturer or product and are not derived from any vendor interface.

This persona emulates the bounded web-management surface of an **AsterView Network Camera**, model **CV-210**. It provides believable HTTP presentation and telemetry without camera hardware, real video, firmware, vulnerabilities, or access to the host.

## Device identity

| Field | Synthetic value |
|---|---|
| Product | AsterView Network Camera |
| Model | CV-210 |
| Firmware | 2.4.7 |
| Hardware | CV210-R2 |
| Hostname | AV-CAM-01 |
| Device name | Front Entrance |

The displayed network configuration, serial number, locally administered MAC address, image, clock, recording state, and uptime are synthetic. Displayed HTTP and RTSP ports do not cause the service to bind them; deployment remains on project port 8081.

## Routes

| Route | Behavior |
|---|---|
| `GET /`, `GET /login` | Login interface |
| `POST /login` | Form authentication |
| `GET /login` with Basic authorization | Backward-compatible authentication path |
| `GET /live` | Synthetic camera viewer and stream metadata |
| `GET /status` | Compact device status JSON |
| `GET /snapshot` | Generated SVG surveillance frame |
| `GET /stream` | Bounded temporary-unavailable response; never a continuous stream |
| `GET /device` | Synthetic hardware and device identity |
| `GET /network` | Display-only network settings |
| `GET /maintenance` | Non-operative maintenance controls |
| `GET /firmware` | Firmware metadata and cosmetic upload control |
| `POST /firmware` | Rejects the package without storing or processing it |
| `GET /logout` | Invalidates the session and returns to login |

All management, status, image, and stream routes require authentication. The sole synthetic credential is `admin` / `admin`. A successful form or Basic login creates a cryptographically random, in-memory session with an approximately 30-minute lifetime. Sessions are lost on container restart; no database or persistent authentication store exists. Cookies are scoped to `/` with `HttpOnly` and `SameSite=Lax`.

## Telemetry

Every request continues through the shared JSONL contract. HTTP telemetry includes `http.request.method` and `url.path`. Submitted form or Basic credentials add `authentication.username` and `authentication.password`, use the `authentication` category and `login_attempt` action, and report `success` only for the synthetic credential. Service identity remains `camera` / `camera-01`, preserving `DEFAULT_CREDENTIALS` and `WEB_ENUMERATION` evaluations; the final controlled credential scenario uses the form flow.

## Boundaries and limitations

The viewer and snapshot are generated presentation only: the persona does not use a webcam, connect to another camera, or implement video streaming. Maintenance controls cannot execute host commands, invoke Docker, reboot anything, read host files, or change configuration. Firmware submissions are rejected in memory and are never written, unpacked, inspected, or executed. The service implements no real firmware, vendor vulnerability, shell, database, persistence, outbound callback, scanning, or arbitrary file access. Container hardening remains defined by the sensor Compose configuration.
