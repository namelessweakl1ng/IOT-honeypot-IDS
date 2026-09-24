# Pi-side configuration overrides

This directory holds optional per-host configuration that overrides the
defaults in `docker-compose.yml`.

- `logging.yml` — optional Python logging config (camera + iot-service)
- `pcap/` — `tcpdump` capture settings if `ENABLE_PCAP=true`
- `networks/` — extra `iptables` / `nftables` rules to apply on the Pi host
  so honeypot ports are reachable from PC2 but not from the internet.

The defaults in the compose file are safe for a typical home-lab LAN.
