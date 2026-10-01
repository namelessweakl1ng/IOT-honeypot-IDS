# Velora Edge Controller TCP emulation

This persona is a bounded, fictional emulation of the **Velora Systems VEC-100**
Edge Controller (firmware 3.2.1, hardware VEC1-R2, VCP/1.0). Velora Systems and
the VEC-100 are invented for this project and do not reproduce a real vendor's
protocol.

The line-oriented interface accepts only `STATUS`, `VERSION`, `INFO`, `HELP`,
and `AUTH <username> <password>` (case-insensitively). Responses contain only
stable synthetic identity/network data and monotonic synthetic uptime. `AUTH`
compares one fixed fictional pair in memory; it never consults a host, database,
or external service.

Telemetry retains the base event fields, adds `iot.operation`, and records
normalized authentication fields plus success/failure for authentication
attempts. Three separate `STATUS`, `VERSION`, and `INFO` interactions therefore
remain compatible with the `iot-probe` reconnaissance detector behavior. One `AUTH admin admin` interaction provides bounded `iot-default-creds` coverage for the default-credential detector.

This is not an IoT operating system or a production protocol. Input and
credentials are length-bounded. There is no device control, GPIO, serial/USB,
Modbus, shell execution, host inspection, persistence, or outbound networking.
