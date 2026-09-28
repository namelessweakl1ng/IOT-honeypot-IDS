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
