"""Replay a scenario and run the model on the resulting session.

Usage:
    python -m model_lab.replay --scenario ssh-bruteforce --target 192.168.1.50 --model-id model-v001
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    from .common import models_dir, setup_paths
    setup_paths()
except ImportError:
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    from common import models_dir, setup_paths  # type: ignore
    setup_paths()

from features import extract_features  # type: ignore  # noqa: E402
from models import predict  # type: ignore  # noqa: E402


def run_attacker(scenario: str, target: str, campaign_id: str | None = None) -> dict:
    """Invoke attacker/run-scenario.sh and capture its summary."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    runner = repo_root / "attacker" / "run-scenario.sh"
    if not runner.exists():
        raise FileNotFoundError(f"runner not found: {runner}")

    cmd = [str(runner), "--target", target, "--scenario", scenario]
    if campaign_id:
        cmd += ["--campaign-id", campaign_id]

    env = os.environ.copy()
    env["TARGET"] = target
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"attacker runner failed: {result.stderr[:1000]}")

    # Find the latest run summary
    runs_dir = repo_root / "attacker" / "runs"
    summaries = sorted(runs_dir.glob("run-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not summaries:
        raise RuntimeError("no run summary written by attacker runner")
    return json.loads(summaries[0].read_text())


def fetch_session_from_es(session_id: str) -> list[dict]:
    """Fetch all events of a session from Elasticsearch (best-effort)."""
    try:
        from elasticsearch import Elasticsearch
        es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
        es = Elasticsearch(es_url, basic_auth=("elastic", os.environ.get("ELASTIC_PASSWORD", "")), request_timeout=5)
        resp = es.search(index="honeypot-events-*", body={
            "query": {"term": {"session_id": session_id}},
            "sort": [{"@timestamp": "asc"}],
            "size": 500,
        })
        body = resp.body if hasattr(resp, "body") else resp
        return [h["_source"] for h in body["hits"]["hits"]]
    except Exception as exc:  # noqa: BLE001
        print(f"WARN: could not fetch session from ES: {exc}", file=sys.stderr)
        return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay a scenario + run the model on the result")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--target", required=True,
                        help="Honeypot IP (must be in lab subnet)")
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--campaign-id", default=None)
    args = parser.parse_args(argv)

    print(f"replaying scenario '{args.scenario}' against {args.target}")
    summary = run_attacker(args.scenario, args.target, args.campaign_id)
    print(f"attacker run_id={summary.get('run_id')}")

    # Wait briefly so Filebeat + Logstash can index
    print("waiting 5s for telemetry to flow through ELK...")
    time.sleep(5)

    # Query ES for events from THIS campaign/scenario/run — NOT just "latest".
    # The previous implementation queried `match_all` + sorted by @timestamp desc,
    # which could select a completely unrelated attack. Now we filter by
    # campaign_id (preferred), run_id, or scenario_id.
    try:
        from elasticsearch import Elasticsearch
        es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
        es = Elasticsearch(es_url, basic_auth=("elastic", os.environ.get("ELASTIC_PASSWORD", "")), request_timeout=10)

        must = []
        if summary.get("campaign_id"):
            must.append({"term": {"labels.campaign_id.keyword": summary["campaign_id"]}})
        if summary.get("run_id"):
            must.append({"term": {"labels.run_id.keyword": summary["run_id"]}})
        if summary.get("scenario"):
            must.append({"term": {"labels.scenario_id.keyword": summary["scenario"]}})
        # Also match tags (the attacker runner tags events with SCENARIO name)
        if summary.get("scenario"):
            must.append({"term": {"tags.keyword": summary["scenario"]}})

        if not must:
            print("ERROR: no campaign_id/run_id/scenario available to filter by.", file=sys.stderr)
            print("The replay must classify the SAME attack it just executed.", file=sys.stderr)
            return 4

        # Use scroll to get ALL events from this campaign (not just the latest)
        query = {
            "query": {"bool": {"should": must, "minimum_should_match": 1}},
            "sort": [{"@timestamp": "asc"}],
        }
        page = es.search(index="honeypot-events-*", body=query, size=5000, scroll="2m")
        body = page.body if hasattr(page, "body") else page
        scroll_id = body.get("_scroll_id")
        hits = body["hits"]["hits"]
        all_events = [h["_source"] for h in hits]
        while hits:
            page = es.scroll(scroll_id=scroll_id, scroll="2m")
            body = page.body if hasattr(page, "body") else page
            hits = body["hits"]["hits"]
            all_events.extend(h["_source"] for h in hits)
            if len(hits) < 5000:
                break

        if not all_events:
            print(f"No events found for campaign_id={summary.get('campaign_id')} "
                  f"run_id={summary.get('run_id')} scenario={summary.get('scenario')}")
            print("Make sure PC1 is reachable and Filebeat is shipping telemetry with the correct labels.")
            return 1

        # Group by session_id and take the first (or only) session
        sessions_map: dict = {}
        for e in all_events:
            sid = e.get("session_id")
            if sid:
                sessions_map.setdefault(sid, []).append(e)

        if not sessions_map:
            print("Events found but none have a session_id — cannot classify.")
            return 3

        # Take the longest session (most events) as the one to classify
        session_id = max(sessions_map.keys(), key=lambda k: len(sessions_map[k]))
        events = sessions_map[session_id]
        print(f"using session_id={session_id} ({len(events)} events from {len(all_events)} total)")
    except Exception as exc:
        print(f"ERROR: could not query ES: {exc}", file=sys.stderr)
        return 2

    if not events:
        print("session has no events — nothing to classify.")
        return 3

    features = extract_features(events)
    print("extracted features:")
    print(json.dumps(features, indent=2))

    preds = predict(models_dir(), args.model_id, [features])
    print("\nmodel prediction:")
    print(json.dumps(preds[0], indent=2))

    # Persist a replay record so the dashboard can show it
    import time as _time, json as _json
    from pathlib import Path as _P
    replay_dir = models_dir().parent / "replays"
    replay_dir.mkdir(parents=True, exist_ok=True)
    replay_id = f"replay-{int(_time.time())}"
    replay_record = {
        "replay_id": replay_id,
        "campaign_id": summary.get("campaign_id"),
        "run_id": summary.get("run_id"),
        "scenario_id": summary.get("scenario"),
        "target": summary.get("target"),
        "started_at": summary.get("started_at"),
        "finished_at": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
        "model_id": args.model_id,
        "session_id": session_id,
        "event_count": len(events),
        "prediction": preds[0].get("prediction"),
        "confidence": max(preds[0].get("probabilities", {}).values()) if preds[0].get("probabilities") else None,
        "anomaly_score": preds[0].get("anomaly_score"),
    }
    (replay_dir / f"{replay_id}.json").write_text(_json.dumps(replay_record, indent=2, default=str))
    print(f"\nreplay record written: {replay_dir / (replay_id + '.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
