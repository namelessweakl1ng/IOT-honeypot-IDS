import Link from "next/link";
const links=[["Overview","/"],["Honeypots","/honeypots"],["Live Events","/events"],["Attack Sessions","/sessions"],["Detections","/detections"],["Experiments","/experiments"],["System","/system"]];
export function Nav(){return <aside><h1>TRAPSIG</h1><p className="muted">IoT security laboratory</p><nav>{links.map(([name,path])=><Link key={path} href={path}>{name}</Link>)}</nav></aside>}
