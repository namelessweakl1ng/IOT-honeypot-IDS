import { api, displayValue } from "@/lib/api";
import type { Experiment, SystemStatus } from "@/lib/types";

const honeypotNames: Record<string, string> = { cowrie: "Cowrie", camera: "Camera", "iot-service": "IoT Service", mqtt: "MQTT", router: "Router" };

function tone(value: unknown) {
  const state = String(value ?? "unknown").toLowerCase();
  if (["healthy", "running", "configured", "green", "yellow"].includes(state)) return "ok";
  if (["unreachable", "unavailable", "error", "red"].includes(state)) return "danger";
  return "warn";
}

export default async function Overview() {
  const [statusResult, experimentsResult] = await Promise.allSettled([
    api<SystemStatus>("/system/status"),
    api<Experiment[]>("/experiments"),
  ]);
  const status = statusResult.status === "fulfilled" ? statusResult.value : {};
  const experiments = experimentsResult.status === "fulfilled" ? experimentsResult.value : [];
  const honeypots = status.honeypots ?? {};
  const running = Object.values(honeypots).filter((state) => state === "running").length;
  const active = experiments.find((item) => item.status === "running");
  const health = [
    ["Backend", status.backend], ["Elasticsearch", status.elasticsearch], ["Logstash", status.logstash],
    ["Raspberry Pi", status.pi], ["Honeypots", `${running} / ${Object.keys(honeypots).length || 5} running`],
  ];
  const stats = [
    ["Total Events", status.counts?.events ?? 0], ["Attack Sessions", status.counts?.sessions ?? 0],
    ["Detections", status.counts?.detections ?? 0], ["Running Honeypots", running], ["Active Experiment", active?.name ?? "None"],
  ];

  return <>
    <header className="page-header split-header">
      <div><p className="eyebrow">Operations overview</p><h2>TRAPSIG Dashboard</h2><p className="lede">Raspberry Pi honeypot laboratory health, telemetry, and experiment control.</p></div>
      <a className="button secondary" href={status.kibana_url || "http://localhost:5601"} target="_blank" rel="noreferrer">Open Kibana <span>↗</span></a>
    </header>
    {statusResult.status === "rejected" && <p className="error">System health is temporarily unavailable. Other dashboard data may still be shown.</p>}
    {experimentsResult.status === "rejected" && <p className="notice">Experiment status could not be loaded. System health remains current.</p>}
    <section className="health-strip" aria-label="System health">
      {health.map(([label, value], index) => <div className="health-item" key={String(label)}><span className={`status-dot ${index === 4 ? (running ? "ok" : "warn") : tone(value)}`} /><div><small>{label}</small><strong>{index === 4 ? value : displayValue(value, "Unknown")}</strong></div></div>)}
    </section>
    <section><div className="section-heading"><div><p className="eyebrow">Live totals</p><h3>Security telemetry</h3></div></div><div className="metrics">{stats.map(([label, value]) => <div className="metric" key={String(label)}><small>{label}</small><strong>{displayValue(value, label === "Active Experiment" ? "None" : "0")}</strong></div>)}</div></section>
    <section className="panel honeypot-panel"><div className="section-heading"><div><p className="eyebrow">Fleet state</p><h3>Honeypot status</h3></div><span className="muted">Managed on Raspberry Pi</span></div><div className="honeypot-list">{Object.entries(honeypotNames).map(([id, name]) => { const state = honeypots[id]; return <div className="honeypot-row" key={id}><div><span className={`service-icon ${tone(state)}`}>{name.slice(0, 1)}</span><strong>{name}</strong></div><span className={`badge ${tone(state)}`}>{displayValue(state, "Unknown")}</span></div>; })}</div></section>
  </>;
}
