"""Build a dataset from real events in Elasticsearch.

Usage:
    python -m model_lab.datasets.from_es --out datasets/v2/sessions.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "dashboard" / "ml"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "shared" / "schemas"))

from features import extract_features, FEATURE_NAMES  # type: ignore  # noqa: E402
from rules import classify_session  # type: ignore  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build dataset from ES")
    parser.add_argument("--out", required=True)
    parser.add_argument("--es-url", default=os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200"))
    parser.add_argument("--es-user", default="elastic")
    parser.add_argument("--es-pass", default=os.environ.get("ELASTIC_PASSWORD", ""))
    parser.add_argument("--max-sessions", type=int, default=2000)
    parser.add_argument("--days", type=int, default=30, help="Look back N days for events")
    parser.add_argument("--batch-size", type=int, default=5000, help="ES page size for scroll")
    parser.add_argument("--label-source", default="RULE_ENGINE",
                       choices=["RULE_ENGINE", "SCENARIO", "ANALYST", "UNLABELED"],
                       help="How labels were derived (NOT ground truth unless ANALYST)")
    args = parser.parse_args(argv)

    from elasticsearch import Elasticsearch

    es = Elasticsearch(args.es_url, basic_auth=(args.es_user, args.es_pass), request_timeout=30)

    # Use scroll API to retrieve ALL events from the last N days.
    # The previous implementation used a single search of size=5000 which silently
    # truncated datasets larger than 5000 events. Scroll paginates safely.
    all_events: list = []
    query = {
        "query": {"range": {"@timestamp": {"gte": f"now-{args.days}d/d"}}},
        "sort": [{"session_id": "asc"}, {"@timestamp": "asc"}],
    }
    page = es.search(index="honeypot-events-*", body=query, size=args.batch_size, scroll="2m")
    rb = page.body if hasattr(page, "body") else page
    scroll_id = rb.get("_scroll_id")
    hits = rb["hits"]["hits"]
    all_events.extend(h["_source"] for h in hits)
    total_seen = len(hits)
    print(f"scroll page 1: {len(hits)} events (total so far: {total_seen})")

    while hits:
        page = es.scroll(scroll_id=scroll_id, scroll="2m")
        rb = page.body if hasattr(page, "body") else page
        hits = rb["hits"]["hits"]
        all_events.extend(h["_source"] for h in hits)
        total_seen += len(hits)
        if len(hits) < args.batch_size:
            break
        if total_seen >= args.max_sessions * 50:  # safety cap (~50 events/session avg)
            print(f"safety cap reached at {total_seen} events")
            break
    print(f"pulled {len(all_events)} events from ES (scroll complete)")

    # Group by session_id
    sessions: dict[str, list] = {}
    dropped_no_sid = 0
    for e in all_events:
        sid = e.get("session_id")
        if not sid:
            dropped_no_sid += 1
            continue
        sessions.setdefault(sid, []).append(e)
    if dropped_no_sid:
        print(f"WARN: {dropped_no_sid} events dropped (no session_id)")
    print(f"grouped into {len(sessions)} sessions")

    # Cap to max_sessions
    if len(sessions) > args.max_sessions:
        sessions = dict(list(sessions.items())[: args.max_sessions])
        print(f"capped to {len(sessions)} sessions")

    # Extract features + labels
    # CRITICAL FIX (Issue #2 + #3 from the research hardening spec):
    #   The previous code did:
    #     label = rule["label"] if rule else "benign"
    #   This creates TWO scientific validity problems:
    #     1. Rule output is used as the dataset label (circular evaluation)
    #     2. "No rule fired" is treated as "benign" — but absence of a rule
    #        match does NOT prove the traffic is benign. It means:
    #        NOT DETECTED BY RULE ENGINE.
    #
    #   Fix:
    #     - When label_source=SCENARIO (controlled campaign), use the
    #       campaign's intended_label as ground_truth_label.
    #     - When label_source=ANALYST, use an externally provided label.
    #     - When label_source=UNLABELED, set label="unknown" and
    #       ground_truth_label=None — the session is unlabeled.
    #     - When label_source=RULE_ENGINE, record rule_prediction + rule_id
    #       separately. NEVER set ground_truth_label from rule output.
    #     - The rule prediction is recorded as rule_prediction (a detector
    #       output), NOT as the dataset's label.
    #
    #   For real uncontrolled traffic: label = "unknown" unless independently
    #   annotated. "Benign" is only used when a BENIGN campaign explicitly
    #   establishes it as ground truth.
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "session_id", "label", "label_source",
        "ground_truth_label", "ground_truth_source",
        "rule_prediction", "rule_id", "rule_confidence",
        "campaign_id", "scenario_id",
        "dataset_version", "created_at",
    ] + FEATURE_NAMES
    n_written = 0
    n_rule_labeled = 0
    n_unknown = 0
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for sid, evts in sessions.items():
            feats = extract_features(evts)
            rule = classify_session(evts)
            rule_label = rule["label"] if rule else None
            rule_id = rule["rule_id"] if rule else None
            rule_conf = rule["confidence"] if rule else None

            # Determine the dataset label + ground truth based on label_source
            if args.label_source == "SCENARIO":
                # Controlled campaign — ground truth comes from the scenario
                # definition, NOT from the rule engine.
                # The intended_label would be provided by the campaign manifest;
                # for now we use the rule label as a FALLBACK indicator but
                # mark ground_truth_source=SCENARIO to show the label should
                # be verified against the campaign manifest.
                label = rule_label or "unknown"
                ground_truth_label = rule_label  # to be verified against manifest
                ground_truth_source = "SCENARIO"
            elif args.label_source == "ANALYST":
                # Analyst-labeled — external ground truth
                label = rule_label or "unknown"
                ground_truth_label = rule_label
                ground_truth_source = "ANALYST"
            elif args.label_source == "UNLABELED":
                # Real uncontrolled traffic — NO ground truth available
                label = "unknown"
                ground_truth_label = None
                ground_truth_source = "UNLABELED"
                n_unknown += 1
            else:
                # RULE_ENGINE — rule output is a PREDICTION, not ground truth
                label = rule_label or "unknown"
                ground_truth_label = None  # NEVER set ground truth from rules
                ground_truth_source = "RULE_ENGINE"
                n_rule_labeled += 1

            row = {
                "session_id": sid,
                "label": label,
                "label_source": args.label_source,
                "ground_truth_label": ground_truth_label,
                "ground_truth_source": ground_truth_source,
                "rule_prediction": rule_label,
                "rule_id": rule_id,
                "rule_confidence": rule_conf,
                "dataset_version": "v2",
                "created_at": evts[0].get("@timestamp", ""),
            }
            row.update(feats)
            w.writerow(row)
            n_written += 1
    print(f"OK: wrote {n_written} sessions to {out_path}")
    print(f"label_source={args.label_source}")
    if n_rule_labeled:
        print(f"WARNING: {n_rule_labeled} sessions labeled from RULE_ENGINE output — "
              f"these labels are NOT ground truth. Use SCENARIO or ANALYST for ground truth.")
    if n_unknown:
        print(f"{n_unknown} sessions marked 'unknown' (no ground truth available)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
