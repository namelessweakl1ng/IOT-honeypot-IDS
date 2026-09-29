import { api } from "@/lib/api";
import type { EvaluationSummary } from "@/lib/types";

const metric = (value: number | null | undefined) => value == null ? "—" : `${(value * 100).toFixed(1)}%`;
const number = (value: number | null | undefined) => value == null ? "Not measured" : value.toFixed(3);

export default async function Evaluation({ searchParams }: { searchParams: Promise<{ config?: string }> }) {
  let data: EvaluationSummary = { cohorts: [], most_recent_evaluation_config_fingerprint: null, legacy_incomplete_count: 0 };
  try { data = await api<EvaluationSummary>("/evaluation/summary"); } catch { /* explicit unavailable/no-data state */ }
  const requested = (await searchParams).config;
  const cohort = data.cohorts.find((item) => item.evaluation_config_fingerprint === requested) ?? data.cohorts.find((item) => item.evaluation_config_fingerprint === data.most_recent_evaluation_config_fingerprint);
  if (!cohort) return <><header className="page-header"><p className="eyebrow">RESEARCH MEASUREMENT</p><h2>Evaluation</h2></header><div className="empty"><strong>NO EVALUATION DATA</strong><p>Run controlled experiments to generate measured results.</p><p>Precision, recall, and resource performance are Not measured.</p></div></>;
  const overall = cohort.overall;
  return <div><header className="page-header"><p className="eyebrow">RESEARCH MEASUREMENT</p><h2>Evaluation</h2><p className="lede">Metrics are kept separate by configuration cohort. Null denominators are shown as Not measured.</p></header>
    {data.cohorts.length > 1 && <div className="notice">MULTIPLE CONFIGURATION COHORTS — results are not combined. {data.cohorts.map((item) => <a className="button" key={item.evaluation_config_fingerprint} href={`/evaluation?config=${item.evaluation_config_fingerprint}`}>{item.evaluation_config_fingerprint.slice(0, 12)}</a>)}</div>}
    <div className="actions"><a className="button" href={`/api/evaluation/export.csv?evaluation_config_fingerprint=${cohort.evaluation_config_fingerprint}`}>CSV EXPORT</a><a className="button" href={`/api/evaluation/export.json?evaluation_config_fingerprint=${cohort.evaluation_config_fingerprint}`}>JSON EXPORT</a></div>
    <div className="cards"><article><h3>Evaluation cohort</h3><p className="mono">{cohort.evaluation_config_fingerprint}</p></article><article><h3>Scored runs</h3><strong>{overall.scored_experiments}</strong></article><article><h3>Inconclusive runs</h3><strong>{overall.inconclusive_experiments}</strong></article></div>
    <section className="experiments-section"><h3>Confusion matrix</h3><div className="metric-strip">{["TP", "FN", "FP", "TN"].map((key) => <div key={key}><small>{key}</small><strong>{overall[key]}</strong></div>)}</div></section>
    <section className="experiments-section"><h3>Metrics</h3><div className="metric-strip">{["precision", "recall", "f1", "specificity", "false_positive_rate", "accuracy"].map((key) => <div key={key}><small>{key.replaceAll("_", " ")}</small><strong>{metric(overall[key])}</strong></div>)}</div></section>
    <section className="experiments-section"><h3>Latency summary</h3><div className="cards">{["detection_latency", "processing_latency", "ingestion_latency_event_samples", "telemetry_step_coverage"].map((key) => <article key={key}><h3>{key.replaceAll("_", " ")}</h3><p>Mean: {number(cohort.latency[key]?.mean)}</p><p>P95: {number(cohort.latency[key]?.p95)}</p></article>)}</div></section>
    <section className="experiments-section"><h3>Controls</h3><p>TN {cohort.controls.tn} / FP {cohort.controls.fp}</p></section>
    <section className="experiments-section"><h3>Per-scenario</h3><div className="table"><div className="row head"><span>SCENARIO</span><span>KIND</span><span>RUNS</span><span>SCORED</span><span>RESULT</span></div>{cohort.per_scenario.map((row) => <div className="row" key={row.scenario_id}><span>{row.scenario_id}</span><span>{row.trial_kind.toUpperCase()}</span><span>{row.run_count}</span><span>{row.scored_count}</span><span>{row.trial_kind === "control" ? `TN ${row.tn} / FP ${row.fp}` : `TP ${row.tp} / FN ${row.fn}`}</span></div>)}</div></section>
    <section className="experiments-section"><h3>Per-detection-type (positive-vs-control)</h3><div className="table"><div className="row head"><span>TYPE</span><span>TP / FN</span><span>FP / TN</span><span>PRECISION</span><span>RECALL</span></div>{cohort.per_detection_type.map((row) => <div className="row" key={row.detection_type}><span>{row.detection_type}</span><span>{row.tp} / {row.fn}</span><span>{row.fp} / {row.tn}</span><span>{metric(row.precision)}</span><span>{metric(row.recall)}</span></div>)}</div></section>
  </div>;
}
