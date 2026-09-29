import { ExperimentConsole } from "@/components/experiment-console";
import { api, errorMessage } from "@/lib/api";
import type { Experiment, Scenario } from "@/lib/types";

export default async function Page() {
  const [experimentResult, scenarioResult] = await Promise.allSettled([
    api<Experiment[]>("/experiments"),
    api<Scenario[]>("/scenarios"),
  ]);
  const data = experimentResult.status === "fulfilled" ? experimentResult.value : [];
  const scenarios = scenarioResult.status === "fulfilled" ? scenarioResult.value : [];
  const historyError = experimentResult.status === "rejected"
    ? errorMessage(experimentResult.reason, "Unable to load experiment history") : "";
  const catalogError = scenarioResult.status === "rejected"
    ? errorMessage(scenarioResult.reason, "Unable to load scenario catalog; experiment creation is unavailable") : "";

  return <>
    <header className="page-header"><p className="eyebrow">Controlled validation</p><h2>Experiments</h2><p className="lede">Create, run, and correlate repeatable attack scenarios against the honeypot fleet.</p></header>
    {historyError && <p className="error">{historyError}</p>}
    <ExperimentConsole initial={data} scenarios={scenarios} catalogError={catalogError} />
  </>;
}
