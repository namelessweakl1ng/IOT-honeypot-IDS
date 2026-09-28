import { HoneypotGrid } from "@/components/honeypot-grid";
import { api } from "@/lib/api";

export default async function Page() {
  let data: Parameters<typeof HoneypotGrid>[0]["initial"] = [];
  let error = "";
  try {
    data = await api("/honeypots");
  } catch (caught) {
    error = String(caught);
  }
  return <><header className="page-header"><p className="eyebrow">Sensor fleet</p><h2>HONEYPOTS</h2><p className="lede">Service state, observed event volume, and constrained Raspberry Pi controls.</p></header>{error ? <p className="error">Unable to load Pi status: {error}</p> : <HoneypotGrid initial={data}/>}</>;
}
