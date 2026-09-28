"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  ["Overview", "/", "01"],
  ["Honeypots", "/honeypots", "02"],
  ["Live Events", "/events", "03"],
  ["Attack Sessions", "/sessions", "04"],
  ["Detections", "/detections", "05"],
  ["Experiments", "/experiments", "06"],
  ["System", "/system", "07"],
] as const;

export function Nav() {
  const pathname = usePathname();
  return (
    <aside className="sidebar">
      <div className="brand"><h1>TRAPSIG</h1><p>IoT SECURITY LAB</p></div>
      <div className="nav-label">Operations</div>
      <nav>
        {links.map(([name, path, index]) => {
          const active = path === "/" ? pathname === path : pathname.startsWith(path);
          return <Link key={path} href={path} className={active ? "active" : ""}><span>{index}</span>{name}</Link>;
        })}
      </nav>
      <div className="sidebar-foot"><span className="pulse" /> Laboratory console</div>
    </aside>
  );
}
