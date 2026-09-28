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
  return <><h2>Honeypots</h2><p className="lede">Explicit start, stop, and restart operations are sent through the constrained Pi management service.</p>{error ? <p className="error">Unable to load Pi status: {error}</p> : <HoneypotGrid initial={data}/>}</>;
}
