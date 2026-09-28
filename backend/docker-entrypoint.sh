#!/bin/sh
set -eu

source_dir=/run/trapsig-secrets
ssh_dir=/home/trapsig/.ssh
private_key="$source_dir/pi_ssh_key"
host_keys="$source_dir/known_hosts"

if [ -z "${PI_HOST:-}" ]; then
  exec gosu trapsig "$@"
fi

[ -f "$private_key" ] || { echo "missing Pi private key: $private_key" >&2; exit 1; }
[ -f "$host_keys" ] || { echo "missing Pi known_hosts file: $host_keys" >&2; exit 1; }
[ -s "$private_key" ] || { echo "Pi private key is empty" >&2; exit 1; }
[ -s "$host_keys" ] || { echo "Pi known_hosts file is empty" >&2; exit 1; }

install -d -o trapsig -g trapsig -m 0700 "$ssh_dir"
install -o trapsig -g trapsig -m 0600 "$private_key" "$ssh_dir/pi_ssh_key"
install -o trapsig -g trapsig -m 0600 "$host_keys" "$ssh_dir/known_hosts"

gosu trapsig test -r "$ssh_dir/pi_ssh_key"
gosu trapsig test -r "$ssh_dir/known_hosts"
exec gosu trapsig "$@"
