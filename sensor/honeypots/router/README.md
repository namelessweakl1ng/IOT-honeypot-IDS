# Nexora NR-1800 router persona

Nexora Networks, the Nexora Wireless Router, and model NR-1800 are entirely fictional identities created for this project. The presentation does not reproduce a real manufacturer's interface, assets, firmware, behavior, or vulnerabilities.

## Identity and interface

The persona presents firmware `1.8.3`, hardware `NR18-R3`, and hostname `NEXORA-GW` in a compact light-gray/orange embedded-router console. All displayed WAN, LAN, DNS, radio, DHCP lease, client, MAC, serial, log, and system values are fixed synthetic data. Documentation-reserved WAN/DNS addresses and locally administered MAC addresses are used.

Public compatibility routes are `GET /`, `GET /login`, `GET /status`, `GET /network`, and `GET /system`. Successful authentication enables `GET /dashboard`, `/internet`, `/lan`, `/wifi`, `/dhcp`, `/clients`, `/firmware`, and `/logs`. `GET /logout` ends the current session. Firmware and system-operation forms are cosmetic simulations only.

## Authentication and sessions

Both an HTML form and HTTP Basic authentication are supported at `/login`. The synthetic credentials are `admin` / `admin`. A successful request receives a cryptographically random, in-memory session cookie with `HttpOnly`, `SameSite=Lax`, and `Path=/` attributes. Sessions expire after approximately 30 minutes. Expired records are purged, the table is capped at 128 entries, and the earliest-expiring entry is evicted when necessary. Sessions are neither persisted nor tied to any host or operating-system account.

## Telemetry and scenario compatibility

Shared HTTP parsing continues to populate `http.request.method`, `http.user_agent`, `url.path`, and submitted `authentication.username` / `authentication.password` fields. Credential submissions use the existing `authentication` / `login_attempt` contract with `success` for `admin` / `admin` and `failure` otherwise.

The `router-default-creds` scenario uses the realistic form flow and remains compatible with the `DEFAULT_CREDENTIALS` detector; Basic authentication is retained for compatibility. The `router-recon` paths (`/`, `/status`, `/network`, `/system`) remain distinct and meaningful for `WEB_ENUMERATION` detection.

## Security boundaries and limitations

This persona only constructs bounded HTTP responses and telemetry. It does not route or forward packets, provide DNS or DHCP, control radios, alter firewall/network settings, read host configuration or logs, invoke commands, scan, or make outbound connections. Firmware submissions are never written, unpacked, inspected, or executed. Reboot, restore, and configuration export are hardcoded simulations and cannot change the container or host. The state is intentionally transient and disappears when the process exits.
