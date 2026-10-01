# Velora Message Gateway MQTT emulation

The MQTT persona is a bounded emulation of the fictional **Velora Message
Gateway VMG-100**. It parses one bounded socket read as an MQTT 3.1.1 packet; it
is not a complete or production MQTT broker.

Supported behavior is deliberately small:

* valid MQTT 3.1.1 `CONNECT` receives an accepted `CONNACK`;
* `PINGREQ` receives `PINGRESP`;
* a valid QoS 0 `SUBSCRIBE` receives a matching `SUBACK`;
* `DISCONNECT` closes without a response;
* `PUBLISH` records its topic and QoS, without storing or forwarding content
  (QoS 1 may receive a minimal `PUBACK`);
* other and malformed packets close without a fabricated response.

The controlled runner uses a new TCP connection for each operation. Consequently
the persona deliberately accepts a standalone `SUBSCRIBE` without an earlier
`CONNECT`. This compatibility behavior is not full broker session semantics.

Telemetry preserves `mqtt.operation` and adds safely parsed fixed-header fields,
client identity/connect flags, packet identifiers, topics, and QoS where
available. This keeps `mqtt-recon` and repeated-connect `mqtt-auth-probe`
compatible with the existing detector.

Remaining Length decoding is limited to MQTT's four encoded bytes and parsing
never allocates from a declared length. There are no subscribers, delivery,
retained messages, persistence, filesystem messages, real authentication,
callbacks, host access, or outbound connections.
