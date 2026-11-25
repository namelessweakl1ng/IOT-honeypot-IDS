"""Learned, session-level behavioural anomaly detection and RL response policy.

The detector learns a benign event distribution from explicitly labelled control
experiments. A contextual Q-learning policy then selects a reversible response
profile for anomalous sessions. No signature or threshold rule catalog is used.
"""

from __future__ import annotations

import math
import random
import statistics
from collections import defaultdict
from hashlib import sha256
from typing import Any

MODEL_VERSION = "adaptive-behaviour-v1"
POLICY_VERSION = "contextual-q-v1"
DETECTION_TYPE = "BEHAVIOURAL_ANOMALY"
SUPPORTED_DETECTION_TYPES = frozenset({DETECTION_TYPE})

FEATURE_NAMES = (
    "protocol_ssh", "protocol_telnet", "protocol_http", "protocol_mqtt", "protocol_tcp",
    "category_authentication", "category_network", "category_web", "category_process",
    "outcome_failure", "outcome_success",
    "action_login", "action_command", "action_connect", "action_subscribe", "action_publish",
    "malformed", "payload_size", "path_depth", "command_length", "topic_depth",
    "session_volume", "event_rate", "service_fanout", "protocol_fanout",
    "auth_failure_ratio", "unique_paths", "command_count", "mqtt_operation_count",
)

MIN_BASELINE_SAMPLES = 8
MIN_CALIBRATION_SCORES = 4
MAX_BASELINE_SAMPLES = 2048
MAX_CALIBRATION_SCORES = 2048
CALIBRATION_QUANTILE = 0.975
RESPONSE_PROFILES = ("observe", "guarded", "restrictive")


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return min(high, max(low, float(value)))


def _log_scale(value: Any, maximum: float) -> float:
    try:
        number = max(0.0, float(value))
    except (TypeError, ValueError):
        number = 0.0
    return _clamp(math.log1p(number) / math.log1p(maximum))


def _path_depth(path: str) -> int:
    return len([part for part in path.split("/") if part])


def event_features(envelope: dict[str, Any]) -> dict[str, float]:
    """Encode a normalized telemetry event as a bounded numeric vector."""
    event = envelope.get("event", {})
    network = envelope.get("network", {})
    service = envelope.get("service", {})
    mqtt = envelope.get("mqtt", {})
    url = envelope.get("url", {})
    http = envelope.get("http", {})
    process = envelope.get("process", {})

    protocol = str(network.get("protocol") or "").lower()
    category = str(event.get("category") or "").lower()
    outcome = str(event.get("outcome") or "").lower()
    action = str(event.get("action") or "").lower()
    operation = str(mqtt.get("operation") or "").lower()

    path = str(url.get("path") or http.get("request", {}).get("referrer") or "")
    command = str(process.get("command_line") or "")
    topic = str(mqtt.get("topic") or "")
    message = str(envelope.get("message") or "")
    malformed = bool(
        envelope.get("malformed")
        or envelope.get("error")
        or mqtt.get("malformed")
        or event.get("type") == "error"
    )

    values = {
        "protocol_ssh": float(protocol == "ssh"),
        "protocol_telnet": float(protocol == "telnet"),
        "protocol_http": float(protocol in {"http", "https"}),
        "protocol_mqtt": float(protocol == "mqtt"),
        "protocol_tcp": float(protocol == "tcp"),
        "category_authentication": float(category == "authentication"),
        "category_network": float(category == "network"),
        "category_web": float(category in {"web", "http"}),
        "category_process": float(category == "process"),
        "outcome_failure": float(outcome in {"failure", "blocked", "denied"}),
        "outcome_success": float(outcome == "success"),
        "action_login": float(action in {"login", "login_attempt", "authenticate"}),
        "action_command": float(action in {"command", "exec", "shell"}),
        "action_connect": float(action in {"connect", "connection"}),
        "action_subscribe": float(operation == "subscribe"),
        "action_publish": float(operation == "publish"),
        "malformed": float(malformed),
        "payload_size": _log_scale(len(message.encode("utf-8", errors="replace")), 4096),
        "path_depth": _log_scale(_path_depth(path), 24),
        "command_length": _log_scale(len(command), 512),
        "topic_depth": _log_scale(len([part for part in topic.split("/") if part]), 16),
    }
    return {name: float(values.get(name, 0.0)) for name in FEATURE_NAMES}


def session_features(session: dict[str, Any]) -> dict[str, float]:
    events = session.get("events", [])
    count = max(1, len(events))
    duration = max(0.0, float(session.get("duration") or 0.0))
    auth = [item for item in events if item.get("event", {}).get("category") == "authentication"]
    failed = sum(item.get("event", {}).get("outcome") == "failure" for item in auth)
    paths = {
        item.get("url", {}).get("path")
        for item in events
        if item.get("url", {}).get("path")
    }
    commands = [
        item.get("process", {}).get("command_line")
        for item in events
        if item.get("process", {}).get("command_line")
    ]
    mqtt_operations = [
        item.get("mqtt", {}).get("operation")
        for item in events
        if item.get("mqtt", {}).get("operation")
    ]
    services = set(session.get("services_touched", []))
    protocols = set(session.get("protocols", []))
    return {
        "session_volume": _log_scale(count, 256),
        "event_rate": _log_scale(count / max(duration, 1.0), 32),
        "service_fanout": _log_scale(len(services), 8),
        "protocol_fanout": _log_scale(len(protocols), 8),
        "auth_failure_ratio": failed / max(1, len(auth)),
        "unique_paths": _log_scale(len(paths), 64),
        "command_count": _log_scale(len(commands), 64),
        "mqtt_operation_count": _log_scale(len(mqtt_operations), 64),
    }


def _vector_for_event(event: dict[str, Any], session_vector: dict[str, float]) -> dict[str, float]:
    vector = event_features(event)
    for name in ("session_volume", "event_rate", "service_fanout", "protocol_fanout",
                 "auth_failure_ratio", "unique_paths", "command_count", "mqtt_operation_count"):
        vector[name] = session_vector[name]
    return vector


def _quantile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower))


class RobustBenignBaseline:
    """Rolling robust feature distribution with a data-derived conformal limit."""

    def __init__(self, state: dict[str, Any] | None = None) -> None:
        state = state or {}
        self.samples: list[dict[str, float]] = [
            {name: float(vector.get(name, 0.0)) for name in FEATURE_NAMES}
            for vector in state.get("samples", [])
            if isinstance(vector, dict)
        ][-MAX_BASELINE_SAMPLES:]
        self.calibration_scores: list[float] = [
            float(value) for value in state.get("calibration_scores", [])
            if isinstance(value, (int, float)) and math.isfinite(float(value))
        ][-MAX_CALIBRATION_SCORES:]

    @property
    def threshold(self) -> float | None:
        if len(self.samples) < MIN_BASELINE_SAMPLES or len(self.calibration_scores) < MIN_CALIBRATION_SCORES:
            return None
        # The limit is learned from the upper tail of held-out benign scores.
        return _quantile(self.calibration_scores, CALIBRATION_QUANTILE)

    def score_one(self, vector: dict[str, float]) -> float | None:
        if len(self.samples) < MIN_BASELINE_SAMPLES:
            return None
        deviations = []
        for name in FEATURE_NAMES:
            values = [sample[name] for sample in self.samples]
            center = statistics.median(values)
            absolute = [abs(value - center) for value in values]
            mad = statistics.median(absolute)
            variance = statistics.pvariance(values) if len(values) > 1 else 0.0
            scale = max(1.4826 * mad, math.sqrt(variance) * 0.5, 0.08)
            z_score = abs(vector.get(name, 0.0) - center) / scale
            deviations.append(z_score / (z_score + 3.0))
        strongest = sorted(deviations, reverse=True)[:6]
        return float(statistics.fmean(strongest))

    def score_session(self, session: dict[str, Any]) -> tuple[float | None, dict[str, float]]:
        summary = session_features(session)
        events = session.get("events", [])
        vectors = [_vector_for_event(event, summary) for event in events]
        vectors.append({name: float(summary.get(name, 0.0)) for name in FEATURE_NAMES})
        scores = [score for vector in vectors if (score := self.score_one(vector)) is not None]
        if not scores:
            return None, summary
        # Preserve short, high-intensity bursts rather than averaging them away.
        return float(0.7 * max(scores) + 0.3 * statistics.fmean(scores)), summary

    def learn_benign(self, session: dict[str, Any]) -> int:
        summary = session_features(session)
        vectors = [_vector_for_event(event, summary) for event in session.get("events", [])]
        vectors.append({name: float(summary.get(name, 0.0)) for name in FEATURE_NAMES})
        learned = 0
        for vector in vectors:
            previous_score = self.score_one(vector)
            if previous_score is not None:
                self.calibration_scores.append(previous_score)
            self.samples.append(vector)
            learned += 1
        self.samples = self.samples[-MAX_BASELINE_SAMPLES:]
        self.calibration_scores = self.calibration_scores[-MAX_CALIBRATION_SCORES:]
        return learned

    def to_state(self) -> dict[str, Any]:
        return {"samples": self.samples, "calibration_scores": self.calibration_scores}


class ContextualQPolicy:
    """One-step contextual Q-learning over reversible sensor response profiles."""

    def __init__(self, state: dict[str, Any] | None = None, seed: int = 17) -> None:
        state = state or {}
        raw = state.get("q_values", {})
        self.q_values: dict[str, dict[str, float]] = {}
        for context, values in raw.items():
            if isinstance(values, dict):
                self.q_values[str(context)] = {
                    action: float(values.get(action, 0.0))
                    for action in RESPONSE_PROFILES
                }
        self.alpha = float(state.get("alpha", 0.25))
        self.epsilon = float(state.get("epsilon", 0.08))
        self.random = random.Random(seed)
        self.updates = int(state.get("updates", 0))
        self.last_reward: float | None = state.get("last_reward")

    @staticmethod
    def context(features: dict[str, float], score: float, threshold: float) -> str:
        ratio = score / max(threshold, 0.01)
        score_band = min(4, max(0, int(ratio)))
        volume_band = min(3, int(features.get("session_volume", 0.0) * 4))
        fanout_band = min(3, int(features.get("service_fanout", 0.0) * 4))
        auth_band = min(2, int(features.get("auth_failure_ratio", 0.0) * 3))
        return f"{score_band}:{volume_band}:{fanout_band}:{auth_band}"

    def choose(self, context: str) -> tuple[str, dict[str, float]]:
        # A small guarded prior gives the first observed anomaly a real, reversible
        # response. Subsequent choices are learned from experiment rewards.
        values = self.q_values.setdefault(
            context, {"observe": 0.0, "guarded": 0.15, "restrictive": 0.0}
        )
        if self.random.random() < self.epsilon:
            action = self.random.choice(RESPONSE_PROFILES)
        else:
            action = max(RESPONSE_PROFILES, key=lambda candidate: values[candidate])
        return action, dict(values)

    def learn(self, context: str, action: str, reward: float) -> float:
        if action not in RESPONSE_PROFILES:
            return 0.0
        values = self.q_values.setdefault(
            context, {"observe": 0.0, "guarded": 0.15, "restrictive": 0.0}
        )
        current = values[action]
        updated = current + self.alpha * (float(reward) - current)
        values[action] = updated
        self.updates += 1
        self.last_reward = float(reward)
        return updated

    def to_state(self) -> dict[str, Any]:
        return {
            "q_values": self.q_values,
            "alpha": self.alpha,
            "epsilon": self.epsilon,
            "updates": self.updates,
            "last_reward": self.last_reward,
        }


class AdaptiveEngine:
    def __init__(self, state: dict[str, Any] | None = None) -> None:
        state = state or {}
        self.baseline = RobustBenignBaseline(state.get("baseline"))
        self.policy = ContextualQPolicy(state.get("policy"))
        self.last_score: float | None = None
        self.last_action = "observe"

    def evaluate(self, session: dict[str, Any]) -> dict[str, Any]:
        score, features = self.baseline.score_session(session)
        threshold = self.baseline.threshold
        session_id = str(session.get("session_id") or "unknown")
        event_ids = list(session.get("event_ids", []))
        timestamp = session.get("end_time")
        ready = score is not None and threshold is not None
        anomalous = bool(ready and score > threshold)
        context = None
        action = "observe"
        q_values: dict[str, float] = {}
        if ready:
            context = self.policy.context(features, float(score), float(threshold))
            if anomalous:
                action, q_values = self.policy.choose(context)
            else:
                q_values = dict(self.policy.q_values.get(
                    context, {"observe": 0.0, "guarded": 0.15, "restrictive": 0.0}
                ))
        self.last_score = score
        self.last_action = action

        decision = {
            "decision_id": "DEC-" + sha256(f"{session_id}:{MODEL_VERSION}".encode()).hexdigest()[:16],
            "session_id": session_id,
            "source_ip": session.get("source_ip"),
            "timestamp": timestamp,
            "model_version": MODEL_VERSION,
            "policy_version": POLICY_VERSION,
            "status": "alert" if anomalous else "normal" if ready else "warming_up",
            "anomalous": anomalous,
            "anomaly_score": score,
            "anomaly_threshold": threshold,
            "baseline_samples": len(self.baseline.samples),
            "calibration_samples": len(self.baseline.calibration_scores),
            "policy_state": context,
            "policy_action": action,
            "q_values": q_values,
            "features": features,
            "evidence_event_ids": event_ids,
        }
        detection = None
        if anomalous:
            severity = {"observe": "low", "guarded": "medium", "restrictive": "high"}[action]
            detection = {
                "detection_id": "DET-" + sha256(f"{session_id}:{MODEL_VERSION}".encode()).hexdigest()[:16],
                "session_id": session_id,
                "source_ip": session.get("source_ip"),
                "type": DETECTION_TYPE,
                "severity": severity,
                "timestamp": timestamp,
                "evidence_end_time": timestamp,
                "reason": (
                    f"Learned behavioural score {score:.4f} exceeded the calibrated "
                    f"benign limit {threshold:.4f}; the response policy selected '{action}'."
                ),
                "evidence_event_ids": event_ids,
                "anomaly_score": score,
                "anomaly_threshold": threshold,
                "baseline_samples": len(self.baseline.samples),
                "model_version": MODEL_VERSION,
                "policy_version": POLICY_VERSION,
                "policy_action": action,
                "policy_state": context,
            }
        return {"decision": decision, "detection": detection}

    def learn_control(self, session: dict[str, Any]) -> int:
        return self.baseline.learn_benign(session)

    def learn_reward(self, decision: dict[str, Any], trial_kind: str, result: str) -> float | None:
        context = decision.get("policy_state")
        action = decision.get("policy_action")
        if not context or action not in RESPONSE_PROFILES:
            return None
        if trial_kind == "control":
            reward = 0.5 if result == "TN" else -1.25 if result == "FP" else 0.0
        else:
            reward = 1.0 if result == "TP" else -1.0 if result == "FN" else 0.0
        # Penalize unnecessary containment so the policy learns the least
        # restrictive action that still earns positive detection outcomes.
        reward -= {"observe": 0.0, "guarded": 0.05, "restrictive": 0.2}[action]
        return self.policy.learn(str(context), str(action), reward)

    def to_state(self) -> dict[str, Any]:
        return {
            "model_version": MODEL_VERSION,
            "policy_version": POLICY_VERSION,
            "baseline": self.baseline.to_state(),
            "policy": self.policy.to_state(),
        }

    def status(self) -> dict[str, Any]:
        return {
            "model_version": MODEL_VERSION,
            "policy_version": POLICY_VERSION,
            "training_state": "ready" if self.baseline.threshold is not None else "calibrating",
            "baseline_samples": len(self.baseline.samples),
            "calibration_samples": len(self.baseline.calibration_scores),
            "policy_contexts": len(self.policy.q_values),
            "policy_updates": self.policy.updates,
            "last_reward": self.policy.last_reward,
            "last_anomaly_score": self.last_score,
            "last_action": self.last_action,
            "response_profiles": list(RESPONSE_PROFILES),
            "coverage": ["camera", "router", "iot-service", "mqtt"],
        }
