import type { CountBucket } from "@/lib/types";

export const EmptyChart = () => <div className="chart-empty">NO DATA IN SELECTED TIME RANGE</div>;

export function Panel({ title, children, wide = false, action }: { title: string; children: React.ReactNode; wide?: boolean; action?: React.ReactNode }) {
  return <section className={`soc-panel ${wide ? "wide-panel" : ""}`}><header><h3>{title}</h3>{action}</header><div className="panel-body">{children}</div></section>;
}

export function HorizontalBars({ data, colors }: { data: CountBucket[]; colors?: Record<string, string> }) {
  if (!data.length) return <EmptyChart />;
  const maximum = Math.max(...data.map((item) => item.count), 1);
  return <div className="bar-chart">{data.map((item) => <div className="bar-row" key={item.name}><span title={item.name}>{item.name}</span><div className="bar-track"><i style={{ width: `${(item.count / maximum) * 100}%`, background: colors?.[item.name.toLowerCase()] }} /></div><b>{item.count}</b></div>)}</div>;
}

export function Timeline({ data }: { data: { time: string; count: number }[] }) {
  if (!data.length) return <EmptyChart />;
  const width = 700, height = 172, max = Math.max(...data.map((item) => item.count), 1);
  const points = data.map((item, index) => `${data.length === 1 ? width / 2 : index * width / (data.length - 1)},${height - item.count / max * (height - 20)}`).join(" ");
  const area = `0,${height} ${points} ${width},${height}`;
  return <div className="timeline"><svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="Events over time"><line x1="0" y1={height / 2} x2={width} y2={height / 2} /><polygon points={area} /><polyline points={points} /></svg><div className="axis"><span>{new Date(data[0].time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span><span>PEAK {max}</span><span>{new Date(data.at(-1)!.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span></div></div>;
}

export function Matrix({ rows, honeypots }: { rows: { source: string; honeypots: Record<string, number> }[]; honeypots: string[] }) {
  if (!rows.length || !honeypots.length) return <EmptyChart />;
  const maximum = Math.max(1, ...rows.flatMap((row) => Object.values(row.honeypots)));
  return <div className="matrix" style={{ gridTemplateColumns: `minmax(110px,1.6fr) repeat(${honeypots.length},1fr)` }}><span />{honeypots.map((name) => <b key={name}>{name.replace("-01", "")}</b>)}{rows.flatMap((row) => [<strong key={`${row.source}-label`}>{row.source}</strong>, ...honeypots.map((name) => { const count = row.honeypots[name] || 0; return <i key={`${row.source}-${name}`} style={{ "--intensity": count / maximum } as React.CSSProperties}>{count || "·"}</i>; })])}</div>;
}

export function SessionBars({ sessions }: { sessions: { session_id?: string; event_count?: number; duration?: number }[] }) {
  const data = sessions.filter((session) => session.event_count).map((session) => ({ name: session.session_id?.slice(0, 10) || "session", count: session.event_count || 0 }));
  return <HorizontalBars data={data} />;
}
