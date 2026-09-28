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
