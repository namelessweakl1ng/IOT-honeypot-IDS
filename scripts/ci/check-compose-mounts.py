#!/usr/bin/env python3
"""Validate security-sensitive mounts in a resolved Compose model."""

import json
import sys

compose = json.load(sys.stdin)
services = compose.get("services", {})
mounts = [mount for service in services.values() for mount in service.get("volumes", [])]

for mount in mounts:
    assert mount.get("source") != "Z", f"accidental mount source: {mount}"
    assert mount.get("target") != "Z", f"accidental mount target: {mount}"

target = "/usr/share/elasticsearch/config/elasticsearch.yml"
elasticsearch_mounts = services.get("elasticsearch", {}).get("volumes", [])
config_mount = next((mount for mount in elasticsearch_mounts if mount.get("target") == target), None)
assert config_mount is not None, f"missing Elasticsearch configuration mount at {target}"
assert config_mount.get("type") == "bind", config_mount
assert config_mount.get("read_only") is True, config_mount
assert config_mount.get("bind", {}).get("selinux") == "Z", config_mount
