# Glossary

| Term                  | Meaning                                                              |
|-----------------------|----------------------------------------------------------------------|
| Honeypot              | A fake service designed to attract and record attacker behavior      |
| Cowrie                | An SSH/Telnet honeypot — used here as the SSH honeypot                |
| ELK                   | Elasticsearch + Logstash + Kibana                                     |
| ECS                   | Elastic Common Schema — the field naming convention we mirror          |
| Filebeat              | Lightweight shipper that tails log files and sends to Logstash       |
| Session               | A group of events from one attacker/source within an idle window     |
| Rule engine           | Deterministic detector — fires only on confident signatures          |
| Classifier            | Supervised ML model that maps sessions to known attack classes        |
| Anomaly detector      | Unsupervised ML model that flags sessions unlike the training dist    |
| Hybrid detection      | Combining rules + classifier + anomaly detector                       |
| Campaign              | A group of related attack scenarios (recon + exploit + post-exploit)   |
| Model registry        | The directory + metadata that tracks every trained model             |
| Model version         | `model-vNNN` — never overwritten; statuses experimental→active→retired |
| Replay                | Re-running an attacker scenario, then running the model on the result |
| Data leakage          | When train/test split contains overlapping sessions — strictly avoided |
| MITRE ATT&CK          | A knowledge base of attacker tactics and techniques                  |
| Rule engine label     | `label_source=RULE_ENGINE` — derived from rule engine on real events  |
| SYNTHETIC             | `label_source=SYNTHETIC` — generated offline, never from real captures |
| REAL CAPTURE          | `label_source=REAL CAPTURE` — produced by an actual attacker run      |
| INSUFFICIENT DATA     | Status the platform returns when a metric cannot be computed honestly  |
