'use client'

// TRAPSIG — SOC console shell.
// Navigation: OVERVIEW → HONEYPOTS → LIVE EVENTS → ATTACK SESSIONS → DETECTIONS → ML / MODELS
// No Repository. No ZIP. No file browser. This is a security product.

import { useEffect, useState, useCallback } from 'react'
import {
  ShieldAlert, Activity, Boxes, Cpu, Radio, Network,
  ChevronRight, type LucideIcon,
} from 'lucide-react'
import { OverviewPage } from '@/components/ids/overview-page'
import { LiveEventsPage } from '@/components/ids/live-events-page'
import { SessionsPage } from '@/components/ids/sessions-page'
import { DetectionsPage } from '@/components/ids/detections-page'
import { ModelsPage } from '@/components/ids/models-page'
import { HoneypotsPage } from '@/components/ids/honeypots-page'

type PageId = 'overview' | 'honeypots' | 'events' | 'sessions' | 'detections' | 'models'

interface NavItem { id: PageId; label: string; icon: LucideIcon }
const NAV: NavItem[] = [
  { id: 'overview',   label: 'OVERVIEW',        icon: ShieldAlert },
  { id: 'honeypots',  label: 'HONEYPOTS',       icon: Network },
  { id: 'events',     label: 'LIVE EVENTS',     icon: Activity },
  { id: 'sessions',   label: 'ATTACK SESSIONS', icon: Boxes },
  { id: 'detections', label: 'DETECTIONS',      icon: Radio },
  { id: 'models',     label: 'ML / MODELS',     icon: Cpu },
]

interface Health { status: string; sessions_loaded: number; models_loaded: number }
interface SystemStatus {
  mode: string
  pi_reachable: boolean
  pi_configured: boolean
  pi_status: string  // authoritative enum — preserved verbatim
  fastapi_reachable: boolean
  elasticsearch: string
  components: { name: string; status: string; detail: string }[]
}

// Presentation-only type for the mode displayed in the header.
// The backend has exactly EMPTY/DEMO/LIVE. The UI may show UNKNOWN
// when the backend is unreachable — this is a presentation state,
// NOT a runtime mode that enters scheduler/materialization logic.
type DisplayMode = 'EMPTY' | 'DEMO' | 'LIVE' | 'UNKNOWN'

export default function Home() {
  const [page, setPage] = useState<PageId>('overview')
  const [health, setHealth] = useState<Health | null>(null)
  const [sysStatus, setSysStatus] = useState<SystemStatus | null>(null)
  const [displayMode, setDisplayMode] = useState<DisplayMode>('UNKNOWN')
  const [loading, setLoading] = useState(true)

  const fetchHealth = useCallback(async () => {
    try {
      // Fetch authoritative mode from backend via the Next.js API route.
      // This route calls syncModeFromBackend() server-side and returns:
      //   { ok: true, mode: 'EMPTY'|'DEMO'|'LIVE' }  on success
      //   { ok: false, error: 'BACKEND_UNREACHABLE: ...' }  on failure (503)
      const modeResp = await fetch('/api/ids/mode', { cache: 'no-store' })
        .then(r => r.json().catch(() => null))
        .catch(() => null)

      // Determine the authoritative display mode from the mode route response.
      // If the mode route succeeds (ok=true), use the backend's mode.
      // If the mode route fails (ok=false / null), display UNKNOWN —
      // do NOT fall back to stale getHealth().mode.
      let authoritativeMode: DisplayMode = 'UNKNOWN'
      if (modeResp && modeResp.ok === true) {
        authoritativeMode = modeResp.mode as DisplayMode
      }
      // If modeResp is null or ok=false, authoritativeMode stays 'UNKNOWN'.
      // This means: backend is unreachable, we cannot confirm the mode.
      // The UI shows UNKNOWN — NOT a stale LIVE or DEMO.

      const [h, s] = await Promise.all([
        fetch('/api/ids/health').then(r => r.json()).catch(() => null),
        fetch('/api/ids/pi/status').then(r => r.json()).catch(() => null),
      ])
      setHealth(h)
      setSysStatus(s)
      setDisplayMode(authoritativeMode)
    } catch (e) { console.error('health fetch failed:', e) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { fetchHealth(); const i = setInterval(fetchHealth, 10000); return () => clearInterval(i) }, [fetchHealth])

  const mode = displayMode
  const modeColor = mode === 'LIVE' ? 'text-emerald-400' : mode === 'DEMO' ? 'text-amber-400' : mode === 'UNKNOWN' ? 'text-rose-400' : 'text-slate-500'
  // Preserve the authoritative pi_status enum — do NOT collapse to CONNECTED/OFFLINE.
  // The backend distinguishes NOT_CONFIGURED, AUTH_FAILED, HOST_KEY_UNKNOWN,
  // HOST_KEY_CHANGED, TIMEOUT, etc. — each carries operational meaning.
  const piStatus = sysStatus?.pi_status || 'UNCHECKED'
  const piColor = piStatus === 'CONNECTED' ? 'text-emerald-400'
    : piStatus === 'DEMO' || piStatus === 'UNCHECKED' || piStatus === 'NOT_CONFIGURED' || piStatus === 'HOST_KEY_UNKNOWN' ? 'text-amber-400'
    : 'text-rose-400'
  const esStatus = sysStatus?.elasticsearch === 'ok' ? 'OK' : sysStatus?.elasticsearch === 'demo' ? 'DEMO' : 'OFFLINE'
  const esColor = sysStatus?.elasticsearch === 'ok' ? 'text-emerald-400' : sysStatus?.elasticsearch === 'demo' ? 'text-amber-400' : 'text-rose-400'
  const mlStatus = sysStatus?.components?.find((c: any) => c.name === 'ML Engine')?.status || 'no model'
  const mlColor = mlStatus === 'ready' ? 'text-emerald-400' : 'text-slate-500'

  return (
    <div className="h-screen flex flex-col bg-background text-foreground overflow-hidden">
      {/* SOC header */}
      <header className="border-b border-border bg-card flex-shrink-0">
        <div className="flex items-center h-9 px-3">
          <span className="text-xs font-semibold tracking-wider text-foreground">TRAPSIG</span>
          <span className="text-[10px] font-mono text-muted-foreground ml-2 hidden sm:inline">IoT DECEPTION & IDS</span>
          <div className="w-px h-4 bg-border mx-3" />
          <div className="hidden md:flex items-center gap-4 text-[10px] font-mono uppercase tracking-wider">
            <span className="flex items-center gap-1.5">
              <span className="text-muted-foreground">MODE:</span>
              <span className={modeColor}>{mode}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="text-muted-foreground">PI:</span>
              <span className={piColor}>{piStatus}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="text-muted-foreground">ES:</span>
              <span className={esColor}>{esStatus}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="text-muted-foreground">ML:</span>
              <span className={mlColor}>{mlStatus.toUpperCase()}</span>
            </span>
          </div>
          <div className="ml-auto text-[10px] font-mono text-muted-foreground">
            {loading ? '...' : health ? `${health.sessions_loaded} SESSIONS` : 'OFFLINE'}
          </div>
        </div>
      </header>

      {/* Body: sidebar + main */}
      <div className="flex flex-1 overflow-hidden">
        <aside className="w-40 border-r border-border bg-sidebar flex-shrink-0 overflow-y-auto flex flex-col">
          <nav className="flex-1 py-2">
            {NAV.map((item) => {
              const Icon = item.icon
              const isActive = page === item.id
              return (
                <button
                  key={item.id}
                  onClick={() => setPage(item.id)}
                  className={`w-full flex items-center gap-2 px-3 py-1.5 text-left text-[11px] font-mono uppercase tracking-wider border-l-2 transition-colors ${
                    isActive
                      ? 'border-l-foreground bg-accent/20 text-foreground'
                      : 'border-l-transparent text-muted-foreground hover:bg-muted/30 hover:text-foreground'
                  }`}
                >
                  <Icon className="w-3 h-3 flex-shrink-0" />
                  <span className="truncate">{item.label}</span>
                </button>
              )
            })}
          </nav>
          {/* Pipeline status at sidebar bottom */}
          {sysStatus && (
            <div className="border-t border-sidebar-border p-2 space-y-1 flex-shrink-0">
              <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">PIPELINE</div>
              {sysStatus.components.slice(0, 9).map(c => (
                <div key={c.name} className="flex items-center justify-between text-[9px] font-mono">
                  <span className="text-muted-foreground truncate">{c.name.toUpperCase()}</span>
                  <span className={c.status === 'connected' || c.status === 'running' || c.status === 'ready' || c.status === 'online' ? 'text-emerald-400' : c.status === 'offline' || c.status === 'stopped' || c.status === 'no model' ? 'text-rose-400' : 'text-amber-400'}>
                    {c.status === 'connected' || c.status === 'running' || c.status === 'ready' || c.status === 'online' ? 'OK' : c.status === 'offline' || c.status === 'stopped' ? 'DOWN' : c.status === 'no model' ? 'NONE' : c.status.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </aside>

        <main className="flex-1 overflow-y-auto">
          {page === 'overview'   && <OverviewPage onNavigate={setPage} />}
          {page === 'honeypots'  && <HoneypotsPage />}
          {page === 'events'     && <LiveEventsPage />}
          {page === 'sessions'   && <SessionsPage />}
          {page === 'detections' && <DetectionsPage />}
          {page === 'models'     && <ModelsPage />}
        </main>
      </div>
    </div>
  )
}
