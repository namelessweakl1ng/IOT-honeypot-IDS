import Link from "next/link";
import { api, displayValue } from "@/lib/api";
import type { AnalyticsOverview, SystemStatus } from "@/lib/types";
import { EmptyChart, HorizontalBars, Matrix, Panel, SessionBars, Timeline } from "@/components/soc-charts";

const ranges = [[15, "15m"], [60, "1h"], [360, "6h"], [1440, "24h"], [10080, "7d"]] as const;
const severityColors = { critical: "#ef5362", high: "#dc6671", medium: "#d7a548", low: "#4b9bd5" };
const emptyAnalytics = (minutes: number): AnalyticsOverview => ({ range_minutes: minutes, totals: { events: 0, sessions: 0, detections: 0, unique_sources: 0, failed_auth_attempts: 0, multi_service_sessions: 0 }, events_over_time: [], honeypots: [], protocols: [], categories: [], actions: [], outcomes: [], top_sources: [], auth_outcomes: [], detection_severity: [], detection_types: [], source_honeypot_matrix: [], sessions: [], recent_detections: [], recent_events: [] });
const stateTone = (value: unknown) => ["healthy", "running", "configured", "green"].includes(String(value).toLowerCase()) ? "ok" : ["unavailable", "unreachable", "red", "error"].includes(String(value).toLowerCase()) ? "danger" : "warn";
const time = (value?: string) => value ? new Date(value).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "UNKNOWN";

export default async function Overview({ searchParams }: { searchParams: Promise<{ minutes?: string }> }) {
  const requested = Number((await searchParams).minutes || 60);
  const minutes = ranges.some(([value]) => value === requested) ? requested : 60;
  const [statusResult, analyticsResult] = await Promise.allSettled([api<SystemStatus>("/system/status"), api<AnalyticsOverview>(`/analytics/overview?minutes=${minutes}`)]);
  const status = statusResult.status === "fulfilled" ? statusResult.value : {};
  const analytics = analyticsResult.status === "fulfilled" ? analyticsResult.value : emptyAnalytics(minutes);
  const honeypotStates = status.honeypots ?? {};
  const running = Object.values(honeypotStates).filter((value) => value === "running").length;
  const sensorTotal = Object.keys(honeypotStates).length;
  const statuses = [["BACKEND", status.backend], ["ELASTICSEARCH", status.elasticsearch], ["LOGSTASH", status.logstash], ["PI", status.pi]];
  const metrics = [["EVENTS", analytics.totals.events], ["ATTACK SESSIONS", analytics.totals.sessions], ["DETECTIONS", analytics.totals.detections], ["UNIQUE SOURCES", analytics.totals.unique_sources], ["RUNNING HONEYPOTS", `${running}/${sensorTotal || 5}`], ["FAILED AUTH", analytics.totals.failed_auth_attempts], ["MULTI-SERVICE", analytics.totals.multi_service_sessions]];
  const honeypotNames = Array.from(new Set(analytics.honeypots.map((item) => item.name)));
  const kibana = status.kibana_url?.replace(/\/$/, "");
  const kibanaDashboard = (id: string) => kibana ? `${kibana}/app/dashboards#/view/${id}` : undefined;

  return <div className="soc-dashboard">
    <header className="soc-header"><div><h2>TRAPSIG</h2><p>IoT DECEPTION &amp; ATTACK ANALYSIS</p></div><div className="system-statuses">{statuses.map(([label, value]) => <span key={String(label)}><small>{label}</small><i className={stateTone(value)} />{displayValue(value, "UNKNOWN").toUpperCase()}</span>)}<span><small>HONEYPOTS</small><i className={running ? "ok" : "warn"} />{running}/{sensorTotal || 5}</span></div>{kibana ? <a className="kibana-action" href={kibanaDashboard("event-overview")} target="_blank" rel="noreferrer">DEEP ANALYSIS IN KIBANA ↗</a> : <span className="kibana-action disabled">KIBANA NOT AVAILABLE</span>}</header>
    <div className="control-bar"><span>ANALYSIS WINDOW</span><div>{ranges.map(([value, label]) => <Link className={minutes === value ? "active" : ""} href={`/?minutes=${value}`} key={value}>{label}</Link>)}</div><small>Health probes from sensor loopback are excluded from analytics.</small></div>
    {statusResult.status === "rejected" && <div className="inline-alert danger">SYSTEM STATUS UNAVAILABLE — ANALYTICS REQUESTED INDEPENDENTLY</div>}
    {analyticsResult.status === "rejected" && <div className="inline-alert danger">ANALYTICS UNAVAILABLE — PLATFORM HEALTH REMAINS INDEPENDENT</div>}
    <div className="metric-strip">{metrics.map(([label, value]) => <div key={String(label)}><small>{label}</small><strong>{displayValue(value, "0")}</strong></div>)}</div>
    <div className="dashboard-grid">
      <Panel title="EVENT ACTIVITY OVER TIME" wide action={kibana && <a href={kibanaDashboard("attack-timeline")} target="_blank" rel="noreferrer">KIBANA ↗</a>}><Timeline data={analytics.events_over_time} /></Panel>
      <Panel title="HONEYPOT ACTIVITY" action={kibana && <a href={kibanaDashboard("honeypot-activity")} target="_blank" rel="noreferrer">EXPLORE ↗</a>}><HorizontalBars data={analytics.honeypots} /></Panel>
      <Panel title="TOP SOURCES" action={kibana && <a href={kibanaDashboard("source-ip-analysis")} target="_blank" rel="noreferrer">EXPLORE ↗</a>}><HorizontalBars data={analytics.top_sources} /></Panel>
      <Panel title="PROTOCOL DISTRIBUTION" action={kibana && <a href={kibanaDashboard("protocol-distribution")} target="_blank" rel="noreferrer">EXPLORE ↗</a>}><HorizontalBars data={analytics.protocols} /></Panel>
      <Panel title="EVENT CATEGORIES"><HorizontalBars data={analytics.categories} /></Panel>
      <Panel title="SOURCE × HONEYPOT" wide><Matrix rows={analytics.source_honeypot_matrix} honeypots={honeypotNames} /></Panel>
      <Panel title="AUTHENTICATION ACTIVITY" action={kibana && <a href={kibanaDashboard("authentication-attempts")} target="_blank" rel="noreferrer">EXPLORE ↗</a>}><HorizontalBars data={analytics.auth_outcomes} colors={{ failure: "#ef5362", success: "#45bd91", unknown: "#73869a" }} /></Panel>
      <Panel title="DETECTION SEVERITY"><HorizontalBars data={analytics.detection_severity} colors={severityColors} /></Panel>
      <Panel title="DETECTION TYPES"><HorizontalBars data={analytics.detection_types} /></Panel>
      <Panel title="SESSION ACTIVITY"><SessionBars sessions={analytics.sessions} /></Panel>
      <Panel title="RECENT DETECTIONS" wide action={<Link href="/detections">VIEW QUEUE →</Link>}>{analytics.recent_detections.length ? <div className="soc-table"><div className="soc-row detection-row head"><span>TIME</span><span>SEVERITY</span><span>TYPE</span><span>SOURCE</span><span>SESSION</span><span>REASON</span></div>{analytics.recent_detections.map((item, index) => <div className="soc-row detection-row" key={item.detection_id || index}><span>{time(item.timestamp)}</span><span className={`severity-text ${item.severity || ""}`}>{displayValue(item.severity)}</span><span>{displayValue(item.type)}</span><span>{displayValue(item.source_ip)}</span><span className="mono">{displayValue(item.session_id)}</span><span>{displayValue(item.reason)}</span></div>)}</div> : <EmptyChart />}</Panel>
      <Panel title="LIVE EVENT STRIP" wide action={<Link href="/events">VIEW ALL EVENTS →</Link>}>{analytics.recent_events.length ? <div className="soc-table"><div className="soc-row event-row head"><span>TIME</span><span>SOURCE</span><span>HONEYPOT</span><span>PROTOCOL</span><span>ACTION</span></div>{analytics.recent_events.map((item, index) => <div className="soc-row event-row" key={item._id || index}><span>{time(item["@timestamp"])}</span><span>{displayValue(item.source?.ip)}</span><span>{displayValue(item.honeypot?.id)}</span><span>{displayValue(item.network?.protocol)}</span><span>{displayValue(item.event?.action)}</span></div>)}</div> : <EmptyChart />}</Panel>
    </div>
  </div>;
}
