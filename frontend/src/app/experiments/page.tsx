import { ExperimentConsole } from "@/components/experiment-console";
import { api, errorMessage } from "@/lib/api";
import type { Experiment, Scenario } from "@/lib/types";

export default async function Page() {
  let data: Experiment[] = [];
  let scenarios: Scenario[] = [];
  let error = "";
  try { [data, scenarios] = await Promise.all([api<Experiment[]>("/experiments"), api<Scenario[]>("/scenarios")]); }
  catch (caught) { error = errorMessage(caught, "Unable to load experiment catalog"); }
  return <>
    <header className="page-header"><p className="eyebrow">Controlled validation</p><h2>Experiments</h2><p className="lede">Create, run, and correlate repeatable attack scenarios against the honeypot fleet.</p></header>
    {error && <p className="error">{error}</p>}
    <ExperimentConsole initial={data} scenarios={scenarios} />
  </>;
}
