"use client";

import { FormEvent, useState } from "react";
import { api, displayValue, errorMessage } from "@/lib/api";
import type { Experiment, Scenario } from "@/lib/types";

export function ExperimentConsole({ initial, scenarios }: { initial: Experiment[]; scenarios: Scenario[] }) {
  const [selectedId, setSelectedId] = useState(scenarios[0]?.id ?? "");
  const selected = scenarios.find((scenario) => scenario.id === selectedId);
  const [items, setItems] = useState(initial);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(""); setBusy("create");
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const body = Object.fromEntries(form);
    try {
      const made = await api<Experiment>("/experiments", { method: "POST", body: JSON.stringify(body) });
      setItems((current) => [made, ...current]); formElement.reset();
    } catch (caught) { setError(errorMessage(caught, "Could not create experiment")); }
    finally { setBusy(""); }
  }

  async function transition(id: string, verb: "start" | "finish" | "cancel") {
    setError(""); setBusy(`${id}-${verb}`);
    try {
      const changed = await api<Experiment>(`/experiments/${id}/${verb}`, { method: "POST" });
      setItems((current) => current.map((item) => item.experiment_id === id ? changed : item));
    } catch (caught) { setError(errorMessage(caught, `Could not ${verb} experiment`)); }
    finally { setBusy(""); }
  }

  return <>
    <form onSubmit={create} className="panel experiment-form">
      <div className="section-heading"><div><p className="eyebrow">New run</p><h3>Create an experiment</h3></div><span className="muted">All fields marked * are required</span></div>
      <fieldset><legend>Experiment details</legend><div className="form-grid"><label>Name *<input name="name" required placeholder="e.g. SSH baseline run" /></label><label>Scenario *<select name="scenario_id" required value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>{scenarios.map((scenario) => <option key={scenario.id} value={scenario.id}>{scenario.name}</option>)}</select></label><label className="wide">Description<textarea name="description" rows={3} placeholder="Purpose, assumptions, or notes for this run" /></label></div></fieldset>
      <fieldset><legend>Scenario contract</legend><div className="result-grid"><div><small>Description</small><p>{selected?.description ?? "Select a scenario"}</p></div><div><small>Expected detection</small><p>{selected?.expected_detection ?? "—"}</p></div><div><small>Derived targets</small><p>{selected?.target_honeypots.join(", ") ?? "—"}</p></div></div></fieldset>
      <fieldset><legend>Lab route</legend><div className="form-grid"><label>Attacker IP *<input name="attacker_ip" required placeholder="192.168.50.20" /></label><label>Target Pi IP *<input name="target_ip" required placeholder="192.168.50.10" /></label></div></fieldset>
      {error && <p className="error" role="alert">{error}</p>}
      <div className="form-actions"><button disabled={busy === "create"}>{busy === "create" ? "Creating…" : "Create experiment"}</button></div>
    </form>
    <section className="experiments-section"><div className="section-heading"><div><p className="eyebrow">Run history</p><h3>Experiments</h3></div><span className="count-label">{items.length} total</span></div>
      {!items.length ? <div className="empty"><span>＋</span><h3>No experiments yet</h3><p>Create the first controlled scenario above. It will appear here ready to start.</p></div> : <div className="experiment-list">{items.map((item) => <article className="experiment-card" key={item.experiment_id}><header><div><p className="mono">{item.experiment_id}</p><h3>{displayValue(item.name, "Untitled experiment")}</h3></div><span className={`badge ${item.status === "running" ? "ok" : item.status === "completed" ? "neutral" : "warn"}`}>{displayValue(item.status)}</span></header><div className="experiment-meta"><div><small>Scenario</small><strong>{displayValue(item.scenario_id)}</strong></div><div><small>Targets</small><strong>{displayValue(item.target_honeypots, "None")}</strong></div><div><small>Route</small><strong>{displayValue(item.attacker_ip)} <span className="muted">→</span> {displayValue(item.target_ip)}</strong></div></div><div className="experiment-counters"><span><b>{item.event_ids?.length || 0}</b> EVENTS</span><span><b>{item.session_ids?.length || 0}</b> SESSIONS</span><span><b>{item.detection_ids?.length || 0}</b> DETECTIONS</span></div><div className="result-grid"><div><small>Expected detection</small><p>{displayValue(item.expected_detection, "Not available")}</p></div><div><small>Observed result</small><p>{displayValue(item.result, item.observed_detection === null || item.observed_detection === undefined ? "Not available" : item.observed_detection ? "Detected" : "Not detected")}</p></div><div><small>Result reason</small><p>{displayValue(item.result_reason, "—")}</p></div><div><small>Ground truth</small><p>{item.ground_truth_valid ? "VALID" : item.runner_status ? "INVALID/FAILED" : "WAITING"}{item.run_id ? ` · ${item.run_id}` : ""}</p></div><div><small>Evidence / detection / processing latency</small><p>{[item.evidence_latency_seconds, item.detection_latency_seconds, item.processing_latency_seconds].map((value) => value == null ? "—" : `${value}s`).join(" / ")}</p></div><div><small>Telemetry settle time</small><p>{item.settle_wait_seconds == null ? "—" : `${item.settle_wait_seconds.toFixed(2)}s`}</p></div></div>{(item.status === "created" || item.status === "running") && <div className="actions">{item.status === "created" && <button disabled={Boolean(busy)} onClick={() => transition(item.experiment_id, "start")}>Start experiment</button>}{item.status === "running" && <button disabled={Boolean(busy)} onClick={() => transition(item.experiment_id, "finish")}>Finish & correlate</button>}<button disabled={Boolean(busy)} onClick={() => transition(item.experiment_id, "cancel")}>Cancel</button></div>}</article>)}</div>}
    </section>
  </>;
}
