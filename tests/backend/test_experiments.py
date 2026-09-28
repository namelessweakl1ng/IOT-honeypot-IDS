from backend.app.services.experiments import correlate
def test_correlation_uses_window_source_and_target():
 experiment={"start_time":"2026-01-01T00:00:00Z","end_time":"2026-01-01T00:05:00Z","attacker_ip":"10.0.0.2","target_ip":"10.0.0.10","expected_detection":"BRUTE_FORCE"}
 events=[{"@timestamp":"2026-01-01T00:01:00Z","event":{"id":"yes"},"source":{"ip":"10.0.0.2"},"destination":{"ip":"10.0.0.10"}},{"@timestamp":"2026-01-01T00:01:00Z","event":{"id":"no"},"source":{"ip":"10.0.0.3"},"destination":{"ip":"10.0.0.10"}}]
 result=correlate(experiment,events,[{"session_id":"s1","event_ids":["yes"]}],[{"detection_id":"d1","session_id":"s1","type":"BRUTE_FORCE"}])
 assert result["event_ids"]==["yes"] and result["result"]=="TP"
