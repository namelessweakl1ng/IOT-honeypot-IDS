"use client";
import { useState } from "react";
import { api } from "@/lib/api";

type Honeypot={id:string;name:string;protocol:string;port:string|number;description:string;status:string;event_count:number};
export function HoneypotGrid({initial}:{initial:Honeypot[]}){
 const [items,setItems]=useState(initial);const [error,setError]=useState("");const [busy,setBusy]=useState("");
 async function action(id:string,verb:string){setBusy(`${id}-${verb}`);setError("");try{await api(`/honeypots/${id}/${verb}`,{method:"POST"});setItems(items.map(item=>item.id===id?{...item,status:verb==="stop"?"stopped":"running"}:item));}catch(e){setError(e instanceof Error?e.message:"Action failed");}finally{setBusy("")}}
 return <>{error&&<p className="error">{error}</p>}<div className="cards">{items.map(item=><article key={item.id}><header><h3>{item.name}</h3><span className={`status ${item.status}`}>{item.status}</span></header><p>{item.description}</p><dl><dt>Protocol / port</dt><dd>{item.protocol} / {item.port}</dd><dt>Events</dt><dd>{item.event_count}</dd></dl><div className="actions">{["start","stop","restart"].map(verb=><button key={verb} disabled={Boolean(busy)} onClick={()=>action(item.id,verb)}>{busy===`${item.id}-${verb}`?"Working…":verb}</button>)}</div></article>)}</div></>
}
