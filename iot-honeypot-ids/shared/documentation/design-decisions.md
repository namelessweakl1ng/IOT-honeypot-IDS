# Design decisions

This document captures the "why" behind the major architectural choices so
future contributors (and the final-year-project viva) can defend them.

## Why Docker Compose and not Kubernetes?

Spec section 50 (No Overengineering) explicitly forbids Kubernetes for this
project. Docker Compose is sufficient for a 3-machine lab, simpler to reason
about, and ships on Windows + Fedora + Pi OS without exotic dependencies.

## Why pin Elastic stack to a single version?

Elastic documents that components must be version-aligned. Using `latest`
silently breaks when one component moves forward and another doesn't.
Pinning to `8.13.4` makes the deployment reproducible.

## Why Filebeat on the Pi instead of Logstash?

Filebeat is ~60 MB, ships as a single container, spools to disk if the central
server is unreachable, and has documented Cowrie integration. Running full
Logstash on the Pi would burn RAM and add operational complexity for no
benefit.

## Why a JSONL file as the inter-container contract?

JSONL is:

- atomic per line (no half-events on crash)
- easy to tail with Filebeat
- trivially parseable in Python
- self-describing (each line is a complete JSON object)

A binary protocol would be smaller but harder to debug.

## Why Cowrie as the SSH honeypot?

Cowrie is the de-facto SSH/Telnet honeypot in academic literature, has a
documented Filebeat integration, and produces structured JSON telemetry. We
do not reinvent SSH deception.

## Why a hybrid rule + ML architecture?

Rules catch the obvious deterministic patterns with high confidence and
provide ground-truth labels for ML training. ML handles behavioral
classification and anomaly detection that rules cannot. This is the standard
hybrid detection pattern in IDS research.

## Why session-level train/test split?

Events from one session are correlated. Random event-level splits leak
information between train and test. Splitting at the session level (or
campaign level) is the standard practice in intrusion-detection research.

## Why scikit-learn and not deep learning?

Spec section 27 explicitly asks for interpretable baselines first. Logistic
regression, random forest, gradient boosting, and isolation forest are all
interpretable, fast to train, and reproducible. Deep learning would add
complexity without a clear data-driven justification for a lab of this size.

## Why a custom React dashboard when Kibana exists?

Kibana is excellent for raw event exploration. The custom dashboard covers
what Kibana does not conveniently provide:

- ML model registry status
- Experiment comparison
- Replay trigger UI
- System health summary

The custom dashboard is deliberately small.

## Why does the attacker tooling refuse non-lab IPs?

Spec section 48 is explicit: every attack script must require an explicit
target, refuse obvious non-lab targets, never default to internet addresses.
A single mistake here would turn a defensive research tool into an offensive
one. The Python `ipaddress` check is the simplest reliable gate.

## Why never expose Docker socket to honeypots?

An attacker who reaches the Docker socket can escape the container. The
spec is explicit on this point and we follow it without exception.

## Why dead-letter index instead of dropping malformed events?

Spec section 15: "Do not silently discard malformed events." Routing to a
dead-letter index (`honeypot-errors-*`) keeps them visible in Kibana for
debugging without polluting the main event index.
