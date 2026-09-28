"use client";

import { FormEvent, useState } from "react";
import { api, displayValue, errorMessage } from "@/lib/api";
import type { Experiment } from "@/lib/types";

const scenarios = ["ssh-bruteforce", "camera-default-creds", "router-default-creds", "http-enumeration", "mqtt-recon", "cross-service-recon", "multi-honeypot-attack"];
const honeypots = [{ id: "cowrie", name: "Cowrie" }, { id: "camera", name: "Camera" }, { id: "iot-service", name: "IoT Service" }, { id: "mqtt", name: "MQTT" }, { id: "router", name: "Router" }];

export function ExperimentConsole({ initial }: { initial: Experiment[] }) {
  const [items, setItems] = useState(initial);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(""); setBusy("create");
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const body = Object.fromEntries(form);
    if (!form.getAll("target_honeypots").length) {
      setError("Choose at least one target honeypot."); setBusy(""); return;
    }
    try {
      const made = await api<Experiment>("/experiments", { method: "POST", body: JSON.stringify({ ...body, target_honeypots: form.getAll("target_honeypots") }) });
      setItems((current) => [made, ...current]); formElement.reset();
    } catch (caught) { setError(errorMessage(caught, "Could not create experiment")); }
    finally { setBusy(""); }
  }

  async function transition(id: string, verb: "start" | "finish") {
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
      <fieldset><legend>Experiment details</legend><div className="form-grid"><label>Name *<input name="name" required placeholder="e.g. SSH baseline run" /></label><label>Scenario *<select name="scenario_id" required>{scenarios.map((scenario) => <option key={scenario}>{scenario}</option>)}</select></label><label className="wide">Description<textarea name="description" rows={3} placeholder="Purpose, assumptions, or notes for this run" /></label></div></fieldset>
      <fieldset><legend>Targets</legend><div className="form-grid"><div className="wide"><span className="field-label">Target honeypots *</span><div className="check-grid">{honeypots.map(({ id, name }) => <label className="check-chip" key={id}><input type="checkbox" name="target_honeypots" value={id} /><span>{name}</span></label>)}</div></div><label>Attacker IP *<input name="attacker_ip" required placeholder="192.0.2.10" /></label><label>Target Pi IP *<input name="target_ip" required placeholder="192.0.2.20" /></label></div></fieldset>
      <fieldset><legend>Detection</legend><label>Expected detection *<input name="expected_detection" required placeholder="e.g. SSH brute-force threshold exceeded" /></label></fieldset>
      {error && <p className="error" role="alert">{error}</p>}
      <div className="form-actions"><button disabled={busy === "create"}>{busy === "create" ? "Creating…" : "Create experiment"}</button></div>
    </form>
    <section className="experiments-section"><div className="section-heading"><div><p className="eyebrow">Run history</p><h3>Experiments</h3></div><span className="count-label">{items.length} total</span></div>
      {!items.length ? <div className="empty"><span>＋</span><h3>No experiments yet</h3><p>Create the first controlled scenario above. It will appear here ready to start.</p></div> : <div className="experiment-list">{items.map((item) => <article className="experiment-card" key={item.experiment_id}><header><div><p className="mono">{item.experiment_id}</p><h3>{displayValue(item.name, "Untitled experiment")}</h3></div><span className={`badge ${item.status === "running" ? "ok" : item.status === "completed" ? "neutral" : "warn"}`}>{displayValue(item.status)}</span></header><div className="experiment-meta"><div><small>Scenario</small><strong>{displayValue(item.scenario_id)}</strong></div><div><small>Targets</small><strong>{displayValue(item.target_honeypots, "None")}</strong></div><div><small>Route</small><strong>{displayValue(item.attacker_ip)} <span className="muted">→</span> {displayValue(item.target_ip)}</strong></div></div><div className="result-grid"><div><small>Expected detection</small><p>{displayValue(item.expected_detection, "Not available")}</p></div><div><small>Observed result</small><p>{displayValue(item.result, item.observed_detection === null || item.observed_detection === undefined ? "Not available" : item.observed_detection ? "Detected" : "Not detected")}</p></div><div><small>Detection latency</small><p>{item.detection_latency_seconds === null || item.detection_latency_seconds === undefined ? "Not available" : `${item.detection_latency_seconds}s`}</p></div></div>{(item.status === "created" || item.status === "running") && <div className="actions">{item.status === "created" && <button disabled={Boolean(busy)} onClick={() => transition(item.experiment_id, "start")}>Start experiment</button>}{item.status === "running" && <button disabled={Boolean(busy)} onClick={() => transition(item.experiment_id, "finish")}>Finish & correlate</button>}</div>}</article>)}</div>}
    </section>
  </>;
}
