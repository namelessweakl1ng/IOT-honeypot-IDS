export type ServiceState = "healthy" | "running" | "configured" | "stopped" | "unreachable" | "unavailable" | string;

export interface SystemStatus {
  backend?: ServiceState;
  elasticsearch?: ServiceState;
  logstash?: ServiceState;
  pi?: ServiceState;
  kibana_url?: string;
  honeypots?: Record<string, ServiceState>;
  counts?: { events?: number | null; sessions?: number | null; detections?: number | null; experiments?: number | null };
  processor?: { last_run?: string | null };
}

export interface Scenario { id: string; name: string; description: string; kind: "attack" | "control"; expected_detection: string; severity: string; target_honeypots: string[]; target_services: string[]; step_count: number; manifest_sha256: string; }

export interface EvaluationRow { scenario_id: string; kind: string; expected_detection: string; run_count: number; scored_count: number; inconclusive_count: number; tp?: number; fn?: number; tn?: number; fp?: number; detection_rate?: number | null; false_positive_rate?: number | null }
export interface RuleEvaluation { detection_type: string; tp: number; fn: number; fp: number; tn: number; precision: number | null; recall: number | null; f1: number | null; specificity: number | null; false_positive_rate: number | null }
export interface EvaluationCohort { cohort_id: string; overall: Record<string, number | null>; per_scenario: EvaluationRow[]; per_detection_type: RuleEvaluation[]; latency: Record<string, { count: number; mean: number | null; p95: number | null }>; controls: { runs: number; tn: number; fp: number } }
export interface EvaluationSummary { cohorts: EvaluationCohort[]; most_recent_cohort_id: string | null; legacy_incomplete_count: number }

export interface Experiment {
  experiment_id: string;
  name: string;
  description?: string;
  scenario_id: string;
  target_honeypots: string[];
  attacker_ip: string;
  target_ip: string;
  expected_detection: string;
  status: string;
  result?: string | null;
  observed_detection?: boolean | null;
  detection_latency_seconds?: number | null;
  evidence_latency_seconds?: number | null;
  processing_latency_seconds?: number | null;
  settle_wait_seconds?: number | null;
  result_reason?: string | null;
  ground_truth_valid?: boolean;
  runner_status?: string | null;
  run_id?: string | null;
  event_ids?: string[];
  session_ids?: string[];
  detection_ids?: string[];
}

export interface CountBucket { name: string; count: number }
export interface AnalyticsOverview {
  range_minutes: number;
  totals: { events: number; sessions: number; detections: number; unique_sources: number; failed_auth_attempts: number; multi_service_sessions: number };
  events_over_time: { time: string; count: number }[];
  honeypots: CountBucket[]; protocols: CountBucket[]; categories: CountBucket[]; actions: CountBucket[]; outcomes: CountBucket[];
  top_sources: CountBucket[]; auth_outcomes: CountBucket[]; detection_severity: CountBucket[]; detection_types: CountBucket[];
  source_honeypot_matrix: { source: string; honeypots: Record<string, number> }[];
  sessions: SessionSummary[]; recent_detections: DetectionSummary[]; recent_events: EventSummary[];
}

export interface SessionSummary {
  session_id?: string; source_ip?: string; start_time?: string; end_time?: string; duration?: number; event_count?: number;
  honeypots_touched?: string[]; protocols?: string[]; failed_authentication_attempts?: number;
}
export interface DetectionSummary { detection_id?: string; timestamp?: string; severity?: string; type?: string; source_ip?: string; session_id?: string; rule_id?: string; reason?: string }
export interface EventSummary {
  _id?: string; "@timestamp"?: string; source?: { ip?: string }; honeypot?: { id?: string };
  network?: { protocol?: string }; event?: { category?: string; action?: string; outcome?: string };
}
