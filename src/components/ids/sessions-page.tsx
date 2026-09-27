'use client'

import { useEffect, useState, useCallback } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { ChevronLeft } from 'lucide-react'
import { Panel, LabelBadge } from './shared'

interface SessionRow {
  session_id: string
  label: string
  label_source: string
  campaign_id: string
  scenario_id: string
  dataset_version: string
  created_at: string
  features: Record<string, number>
}

const LEAKY = ['contains_path_traversal', 'contains_command_injection', 'contains_default_credentials']

export function SessionsPage() {
  const [sessions, setSessions] = useState<SessionRow[]>([])
  const [mode, setMode] = useState<string>('EMPTY')
  const [loading, setLoading] = useState(true)
  const [backendUnavailable, setBackendUnavailable] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const [detail, setDetail] = useState<SessionRow | null>(null)
  const [demoLoading, setDemoLoading] = useState(false)

  const fetchSessions = useCallback(async () => {
    try {
      const response = await fetch('/api/ids/sessions?size=100')
      const d = await response.json()
      setSessions(d.sessions || [])
      setMode(d.mode || 'EMPTY')
      setBackendUnavailable(!response.ok || Boolean(d?.error))
    } catch (e) { console.error(e); setBackendUnavailable(true) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void Promise.resolve().then(fetchSessions) }, [fetchSessions])

  useEffect(() => {
    if (!selected) return
    let cancelled = false
    const load = async () => {
      try {
        const d = await fetch(`/api/ids/sessions/${encodeURIComponent(selected)}`).then(r => r.json())
        if (!cancelled) setDetail(d)
      } catch (e) { console.error(e) }
    }
    load()
    return () => { cancelled = true }
  }, [selected])

  const loadDemo = async () => {
    setDemoLoading(true)
    try {
      await fetch('/api/ids/demo/load', { method: 'POST' })
      await fetchSessions()
    } catch (e) { console.error(e) }
    finally { setDemoLoading(false) }
  }

  if (loading) return <div className="p-4"><Skeleton className="h-6 w-48" /></div>

  if (selected && detail) {
    return <SessionDetail detail={detail} onBack={() => { setSelected(null); setDetail(null) }} />
  }

  const noLiveTelemetry = mode === 'LIVE' && sessions.length === 0 && !backendUnavailable
  const isEmpty = mode === 'EMPTY' || (mode === 'DEMO' && sessions.length === 0)

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-baseline gap-3 border-b border-border pb-2">
        <h2 className="text-sm font-semibold tracking-wider text-foreground">ATTACK SESSIONS</h2>
        <span className="text-[10px] font-mono text-muted-foreground ml-auto">{sessions.length} SESSIONS · {mode}</span>
      </div>

      {backendUnavailable ? (
        <Panel title="SESSION INVESTIGATION"><div className="py-8 text-center text-sm font-mono text-rose-400">BACKEND UNAVAILABLE</div></Panel>
      ) : noLiveTelemetry ? (
        <Panel title="SESSION INVESTIGATION"><div className="py-8 text-center text-sm font-mono text-muted-foreground">NO LIVE TELEMETRY</div></Panel>
      ) : isEmpty ? (
        <Panel title="SESSION INVESTIGATION">
          <div className="py-8 text-center">
            <div className="text-sm font-mono text-muted-foreground mb-2">NO ACTIVE ATTACK SESSIONS</div>
            <div className="text-[11px] font-mono text-muted-foreground/60 mb-4">
              Sessions are reconstructed when honeypot telemetry is processed by the FastAPI + ML pipeline.
            </div>
            <button
              onClick={loadDemo}
              disabled={demoLoading}
              className="px-4 py-1.5 border border-border bg-muted/30 text-[11px] font-mono uppercase tracking-wider text-foreground hover:bg-muted/50 disabled:opacity-50"
            >
              {demoLoading ? 'LOADING...' : 'LOAD DEMO DATA'}
            </button>
          </div>
        </Panel>
      ) : (
        <>
          {mode === 'DEMO' && (
            <div className="border border-amber-800 bg-amber-950/30 px-3 py-1.5 text-[10px] font-mono text-amber-300">
              DEMO MODE — SYNTHETIC DATASET ROWS, NOT LIVE SESSIONS
            </div>
          )}
          <Panel title="SESSION INVESTIGATION" right="CLICK ROW FOR DETAILS">
            <div className="overflow-x-auto">
              <table className="w-full text-[11px] font-mono">
                <thead className="border-b border-border">
                  <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    <th className="text-left py-1.5 pr-3">SESSION</th>
                    <th className="text-left py-1.5 pr-3">LABEL</th>
                    <th className="text-left py-1.5 pr-3">SOURCE</th>
                    <th className="text-left py-1.5 pr-3">CAMPAIGN</th>
                    <th className="text-right py-1.5 pr-3">EVENTS</th>
                    <th className="text-right py-1.5 pr-3">DURATION</th>
                    <th className="text-right py-1.5 pr-3">AUTH</th>
                    <th className="text-left py-1.5">CREATED</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map(s => (
                    <tr
                      key={s.session_id}
                      onClick={() => setSelected(s.session_id)}
                      className="border-b border-border/30 hover:bg-muted/20 cursor-pointer"
                    >
                      <td className="py-1 pr-3 text-muted-foreground">{s.session_id.slice(-16)}</td>
                      <td className="py-1 pr-3"><LabelBadge label={s.label} /></td>
                      <td className="py-1 pr-3 text-muted-foreground">{s.label_source}</td>
                      <td className="py-1 pr-3 text-muted-foreground">{s.campaign_id}</td>
                      <td className="py-1 pr-3 text-right text-foreground tabular-nums">{s.features.event_count?.toFixed(0) || '—'}</td>
                      <td className="py-1 pr-3 text-right text-foreground tabular-nums">{s.features.duration_s?.toFixed(1) || '—'}s</td>
                      <td className="py-1 pr-3 text-right text-foreground tabular-nums">{s.features.auth_attempts > 0 ? s.features.auth_attempts.toFixed(0) : '—'}</td>
                      <td className="py-1 text-muted-foreground">{s.created_at?.slice(0, 19) || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}
    </div>
  )
}

function SessionDetail({ detail, onBack }: { detail: SessionRow; onBack: () => void }) {
  const features = Object.entries(detail.features).sort(([a], [b]) => a.localeCompare(b))
  return (
    <div className="p-4 space-y-3">
      <Button variant="ghost" size="sm" onClick={onBack} className="text-muted-foreground hover:text-foreground h-7 text-[11px] font-mono">
        <ChevronLeft className="w-3 h-3 mr-1" /> BACK
      </Button>
      <div className="flex items-baseline gap-3 border-b border-border pb-2">
        <h2 className="text-sm font-semibold tracking-wider text-foreground">SESSION DETAIL</h2>
        <code className="text-[11px] text-muted-foreground font-mono">{detail.session_id}</code>
        <LabelBadge label={detail.label} />
        <span className="text-[10px] font-mono text-muted-foreground ml-auto">SOURCE: {detail.label_source}</span>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <Panel title="METADATA">
          <div className="space-y-0.5 text-[11px] font-mono">
            <DetailRow label="SESSION_ID" value={detail.session_id} />
            <DetailRow label="LABEL" value={detail.label} />
            <DetailRow label="LABEL_SOURCE" value={detail.label_source} />
            <DetailRow label="CAMPAIGN_ID" value={detail.campaign_id} />
            <DetailRow label="SCENARIO_ID" value={detail.scenario_id} />
            <DetailRow label="DATASET" value={detail.dataset_version} />
            <DetailRow label="CREATED_AT" value={detail.created_at} />
          </div>
        </Panel>
        <Panel title="FEATURE VECTOR" right={`V1 · ${features.length} FEATURES`} className="lg:col-span-2">
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[11px] font-mono">
            {features.map(([name, value]) => {
              const max = Math.max(...features.map(([, v]) => Math.abs(v)), 1)
              const pct = (Math.abs(value) / max) * 100
              const isBool = value === 0 || value === 1
              const isLeaky = LEAKY.includes(name)
              return (
                <div key={name} className="flex items-center gap-2 py-0.5">
                  <span className={`w-40 truncate ${isLeaky ? 'text-rose-400' : 'text-muted-foreground'}`} title={isLeaky ? '⚠ LEAKY' : ''}>
                    {isLeaky && '⚠ '}{name}
                  </span>
                  <div className="flex-1 h-2 bg-muted/30 border border-border/30 relative">
                    <div className={`h-full ${isLeaky ? 'bg-rose-600/60' : isBool ? (value === 1 ? 'bg-amber-600/60' : 'bg-slate-700') : 'bg-blue-600/50'}`} style={{ width: `${Math.max(pct, 1)}%` }} />
                  </div>
                  <span className="w-16 text-right text-foreground tabular-nums">
                    {Number.isInteger(value) ? value.toFixed(0) : value.toFixed(3)}
                  </span>
                </div>
              )
            })}
          </div>
        </Panel>
      </div>
    </div>
  )
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-2 py-0.5 border-b border-border/20">
      <span className="text-muted-foreground text-[10px] uppercase tracking-wider">{label}</span>
      <span className="text-foreground text-right truncate">{value || '—'}</span>
    </div>
  )
}
