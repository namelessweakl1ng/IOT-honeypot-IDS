# Tests for the IoT honeypot IDS platform.

Run:

```bash
./scripts/testing/run-tests.sh
```

Unit tests run anywhere. Integration tests assume Elasticsearch is reachable
on `localhost:9200` (skip with `pytest -m "not integration"`).

## Layout

```
tests/
├── unit/           # fast, no external deps
│   ├── test_features.py
│   ├── test_session_reconstruction.py
│   ├── test_rules.py
│   ├── test_event_schema.py
│   ├── test_attacker_safety.py
│   └── test_config.py
├── integration/    # needs running services
│   ├── test_elasticsearch.py
│   └── test_api.py
└── e2e/             # full pipeline — run via scripts/testing/run-e2e.sh
    └── README.md
```
