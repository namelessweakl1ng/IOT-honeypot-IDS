# Cowrie VEG-200 persona

This directory configures the existing Cowrie SSH/Telnet honeypot as a fictional
**Velora Systems Velora Edge Gateway VEG-200**. It does not describe or emulate a
real vendor product.

## Identity and access contract

| Property | Synthetic value |
| --- | --- |
| Firmware / hardware | `2.7.4` / `VEG2-R1` |
| Hostname | `VE-GW-01` |
| OS / architecture | Velora Embedded Linux / `armv7l` |
| Kernel | `4.14.98-velora` |
| SSH / Telnet host ports | `2222` / `2223` |

`userdb.txt` deliberately permits only `root` / `root`; the wildcard rule rejects
all other credentials. Fake users in `/etc/passwd` are scenery and do not grant
authentication. This preserves the `ssh-interaction`, `ssh-bruteforce`, and
`telnet-auth-attempts` scenario contracts, including command telemetry for `id`.

## Operator-owned filesystem content

`cowrie.cfg` selects Cowrie's supported `contents_path`. Compose mounts each
repository-owned persona file individually and read-only over its matching file
in Cowrie's packaged `honeyfs`. This preserves every other fake file shipped by
Cowrie while overriding the hostname, Velora OS, banner/MOTD, account, resolver,
network, kernel, and four-core ARM information.
`/etc/issue.net` is the understated pre-login identity and `/etc/motd` is the
post-login maintenance notice. SSH and Telnet use the same Cowrie configuration,
user database, fake filesystem, prompt hostname, and firmware identity.

Cowrie's fake-filesystem metadata (`fs.pickle`) controls which paths exist. The
overlay changes file contents only; it neither exposes nor reads the container
host filesystem. The network values (`192.168.10.1/24`, gateway
`192.168.10.254`) are synthetic and are not derived from Docker or the sensor.

## Telemetry and safety

JSON events remain at `var/log/cowrie/cowrie.json`. The existing named volume is
read by Filebeat at `/logs/cowrie/*.json`, so event IDs and downstream detection
contracts are unchanged.

This remains Cowrie's low-interaction emulated shell. No proxy, QEMU, LLM, real
shell, external command execution, uploaded-file execution, host mount, elevated
capability, or outbound callback is enabled. The container retains its dropped
capabilities, no-new-privileges setting, and resource limits.

## Limitations

Cowrie implements a useful subset of Linux commands rather than a complete
operating system. Outputs from commands such as `ip`, `route`, and `netstat`
depend on the commands included by the Cowrie image. Repository-owned identity
files and Cowrie's `hostname`/`uname` settings are kept coherent, but this persona
does not add a custom command framework or patch Cowrie internals.
