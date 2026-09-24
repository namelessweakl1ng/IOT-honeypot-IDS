import { useEffect, useState } from "react";

type Page = "overview" | "sessions" | "detections" | "models" | "experiments" | "replay";

const API_URL = (import.meta.env.VITE_API_URL as string) || "http://localhost:8000";
const KIBANA_URL = (import.meta.env.VITE_KIBANA_URL as string) || "http://localhost:5601";

export default function App() {
  const [page, setPage] = useState<Page>("overview");
  const [health, setHealth] = useState<Record<string, string>>({});

  useEffect(() => {
    fetch(`${API_URL}/health`)
      .then((r) => r.json())
      .then(setHealth)
      .catch(() => setHealth({ status: "unreachable" }));
  }, []);

  return (
    <div className="app">
      <aside className="sidebar">
        <h2>IoT Honeypot IDS</h2>
        <NavItem active={page === "overview"}    onClick={() => setPage("overview")}    label="Overview" />
        <NavItem active={page === "sessions"}    onClick={() => setPage("sessions")}    label="Sessions" />
        <NavItem active={page === "detections"}  onClick={() => setPage("detections")}  label="Detections" />
        <NavItem active={page === "models"}      onClick={() => setPage("models")}      label="Models" />
        <NavItem active={page === "experiments"} onClick={() => setPage("experiments")} label="Experiments" />
        <NavItem active={page === "replay"}      onClick={() => setPage("replay")}      label="Replay" />

        <h2>External</h2>
        <a href={KIBANA_URL} target="_blank" rel="noreferrer">Kibana ↗</a>
        <a href={`${API_URL}/docs`} target="_blank" rel="noreferrer">API docs ↗</a>

        <h2>Health</h2>
        <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
          Status: {health.status || "..."}<br/>
          ES: {health.elasticsearch || "..."}<br/>
          Models: {health.models_dir || "..."}
        </div>
      </aside>

      <main className="main">
        {page === "overview"    && <Overview />}
        {page === "sessions"    && <Sessions />}
        {page === "detections"  && <Detections />}
        {page === "models"      && <Models />}
        {page === "experiments" && <Experiments />}
        {page === "replay"      && <Replay />}
      </main>
    </div>
  );
}

function NavItem({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return <a className={active ? "active" : ""} onClick={onClick}>{label}</a>;
}

function Overview() {
  return (
    <>
      <h1>Overview</h1>
      <div className="panel">
        <p style={{ color: "var(--text-dim)" }}>
          This is a lightweight companion dashboard. Kibana remains the primary
          visualization layer for raw event data. Use this dashboard for ML
          status, model comparison, and replay controls — things Kibana does
          not conveniently provide.
        </p>
      </div>
      <div className="stats">
        <Stat label="Total events"    value="—" hint="Open Kibana for live counts" />
        <Stat label="Unique attackers" value="—" />
        <Stat label="Active sessions"  value="—" />
        <Stat label="Detections (24h)" value="—" />
        <Stat label="Models"           value="—" />
      </div>
      <h2>Kibana dashboards</h2>
      <div className="panel">
        <p>Open the Kibana URL configured in <code>.env</code> to view:</p>
        <ul>
          <li>SOC overview (total events / attackers / sessions)</li>
          <li>Attack timeline</li>
          <li>Source IP analysis</li>
          <li>Attack types breakdown</li>
          <li>Per-device activity</li>
          <li>Session explorer</li>
        </ul>
      </div>
    </>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="stat">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {hint && <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

function useFetch<T>(url: string): [T | null, string, () => void] {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState("");
  const [reload, setReload] = useState(0);
  useEffect(() => {
    fetch(url)
      .then((r) => r.json())
      .then(setData)
      .catch((e) => setErr(String(e)));
  }, [url, reload]);
  return [data, err, () => setReload(reload + 1)];
}

function Sessions() {
  const [data] = useFetch<any>(`${API_URL}/sessions?size=50`);
  return (
    <>
      <h1>Reconstructed sessions</h1>
      <div className="panel">
        {data?.sessions?.length ? (
          <table>
            <thead>
              <tr><th>Session</th><th>Source</th><th>Device</th><th>Started</th><th>Events</th><th>Classification</th></tr>
            </thead>
            <tbody>
              {data.sessions.map((s: any) => (
                <tr key={s.session_id}>
                  <td><code>{s.session_id?.slice(0, 8)}</code></td>
                  <td>{s.source?.ip}</td>
                  <td>{s.device?.id}</td>
                  <td>{s.started_at}</td>
                  <td>{s.event_count}</td>
                  <td><span className="badge">{s.classification || "—"}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p style={{ color: "var(--text-dim)" }}>No sessions yet. Run an attack scenario to populate.</p>
        )}
      </div>
    </>
  );
}

function Detections() {
  const [data] = useFetch<any>(`${API_URL}/detections?size=50`);
  return (
    <>
      <h1>Detections</h1>
      <div className="panel">
        {data?.detections?.length ? (
          <table>
            <thead>
              <tr><th>Time</th><th>Session</th><th>Engine</th><th>Label</th><th>Confidence</th><th>Model</th></tr>
            </thead>
            <tbody>
              {data.detections.map((d: any) => (
                <tr key={d.detection_id}>
                  <td>{d["@timestamp"]}</td>
                  <td><code>{d.session_id?.slice(0, 8)}</code></td>
                  <td>{d.engine}</td>
                  <td><span className={`badge ${d.label === "anomaly" ? "danger" : ""}`}>{d.label}</span></td>
                  <td>{d.confidence?.toFixed(2) ?? "—"}</td>
                  <td>{d.model_version || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p style={{ color: "var(--text-dim)" }}>No detections yet. Run an attack scenario or replay.</p>
        )}
      </div>
    </>
  );
}

function Models() {
  const [data] = useFetch<any>(`${API_URL}/models`);
  return (
    <>
      <h1>Model registry</h1>
      <div className="panel">
        {data?.models?.length ? (
          <table>
            <thead>
              <tr><th>Model ID</th><th>Algorithm</th><th>Dataset</th><th>Status</th><th>F1 (in-sample)</th><th>Created</th></tr>
            </thead>
            <tbody>
              {data.models.map((m: any) => (
                <tr key={m.model_id}>
                  <td><code>{m.model_id}</code></td>
                  <td>{m.algorithm}</td>
                  <td>{m.dataset_version}</td>
                  <td><span className={`badge ${m.status === "active" ? "ok" : m.status === "retired" ? "danger" : "warn"}`}>{m.status}</span></td>
                  <td>{m.metrics?.in_sample_f1_macro?.toFixed(3) ?? "—"}</td>
                  <td>{m.created_at_iso}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p style={{ color: "var(--text-dim)" }}>No models trained yet. Run a training via the API or model-lab CLI.</p>
        )}
      </div>
    </>
  );
}

function Experiments() {
  const [data] = useFetch<any>(`${API_URL}/experiments`);
  return (
    <>
      <h1>Experiments</h1>
      <div className="panel">
        {data?.experiments?.length ? (
          <table>
            <thead>
              <tr><th>Experiment</th><th>Algorithm</th><th>Dataset</th><th>Seed</th><th>Accuracy</th><th>F1</th></tr>
            </thead>
            <tbody>
              {data.experiments.map((e: any) => (
                <tr key={e.experiment_id}>
                  <td><code>{e.experiment_id}</code></td>
                  <td>{e.algorithm}</td>
                  <td>{e.dataset_version}</td>
                  <td>{e.seed}</td>
                  <td>{e.metrics?.accuracy?.toFixed(3) ?? "—"}</td>
                  <td>{e.metrics?.f1_macro?.toFixed(3) ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p style={{ color: "var(--text-dim)" }}>No experiments recorded yet.</p>
        )}
      </div>
    </>
  );
}

function Replay() {
  const [scenario, setScenario] = useState("ssh-bruteforce");
  const [target, setTarget] = useState("");
  const [output, setOutput] = useState("");
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setOutput("launching replay...");
    try {
      const r = await fetch(`${API_URL}/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: scenario, target }),
      });
      const j = await r.json();
      if (!r.ok) {
        setOutput(`ERROR: ${j.detail || JSON.stringify(j)}`);
      } else {
        setOutput(`rc=${j.returncode}\n\n--- stdout ---\n${j.stdout_tail}\n\n--- stderr ---\n${j.stderr_tail}`);
      }
    } catch (e) {
      setOutput(`fetch error: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h1>Replay a scenario</h1>
      <div className="panel">
        <p style={{ color: "var(--text-dim)" }}>
          Triggers a controlled attacker scenario against the configured lab
          target. The API refuses targets outside the lab subnet.
        </p>
        <label>Scenario
          <select value={scenario} onChange={(e) => setScenario(e.target.value)}>
            <option value="ssh-bruteforce">ssh-bruteforce</option>
            <option value="camera-recon">camera-recon</option>
            <option value="camera-default-creds">camera-default-creds</option>
            <option value="http-enumeration">http-enumeration</option>
            <option value="iot-probe">iot-probe</option>
            <option value="multi-stage">multi-stage</option>
          </select>
        </label>
        <br />
        <label>Target IP
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="192.168.1.50" />
        </label>
        <br />
        <button disabled={busy || !target} onClick={run}>{busy ? "Running..." : "Run replay"}</button>
        <pre style={{ marginTop: 16, background: "#0a0c10", padding: 12, borderRadius: 6, overflow: "auto" }}>
{output || "(output will appear here)"}
        </pre>
      </div>
    </>
  );
}
