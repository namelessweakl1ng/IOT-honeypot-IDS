'use client'

import { useEffect, useState, useCallback } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { Panel } from './shared'

interface Stats {
  status: string
  mode: string
  total_sessions?: number
  total_events?: number
  total_detections?: number
  unique_attackers?: number
  anomalies?: number
  known_attacks?: number
  label_distribution?: Record<string, number>
  model_version?: string | null
  model_status?: string | null
  note?: string
  data_source?: string
}

interface SystemStatus {
  mode: string
  pi_reachable: boolean
  fastapi_reachable: boolean
  elasticsearch: string
  components: { name: string; status: string; detail: string }[]
}

export function OverviewPage({ onNavigate }: { onNavigate: (p: any) => void }) {
  const [stats, setStats] = useState<Stats | null>(null)
  const [sysStatus, setSysStatus] = useState<SystemStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [demoLoading, setDemoLoading] = useState(false)

  const fetchAll = useCallback(async () => {
    try {
      const [s, ss] = await Promise.all([
        fetch('/api/ids/stats').then(r => r.json()),
        fetch('/api/ids/pi/status').then(r => r.json()),
      ])
      setStats(s)
      setSysStatus(ss)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { fetchAll() }, [fetchAll])

  const loadDemo = async () => {
    setDemoLoading(true)
    try {
      await fetch('/api/ids/demo/load', { method: 'POST' })
      await fetchAll()
    } catch (e) { console.error(e) }
    finally { setDemoLoading(false) }
  }

  if (loading) {
    return (
      <div className="p-4 space-y-3">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-32" />
      </div>
    )
  }

  const isEmpty = stats?.mode === 'EMPTY' || stats?.status === 'empty'

  return (
    <div className="p-4 space-y-3">
      {/* Page header */}
      <div className="flex items-baseline gap-3 border-b border-border pb-2">
        <h2 className="text-sm font-semibold tracking-wider text-foreground">SOC OVERVIEW</h2>
        <span className="text-[10px] font-mono text-muted-foreground ml-auto">MODE: {stats?.mode || 'EMPTY'}</span>
      </div>

      {/* System status */}
      {sysStatus && (
        <Panel title="SYSTEM STATUS" right={`${sysStatus.components.filter(c => c.status === 'connected' || c.status === 'running' || c.status === 'ready' || c.status === 'online').length}/${sysStatus.components.length} OK`}>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-0">
            {sysStatus.components.map(c => (
              <div key={c.name} className="flex items-center justify-between py-1 border-b border-border/30 text-[11px] font-mono">
                <span className="text-muted-foreground truncate">{c.name.toUpperCase()}</span>
                <span className={c.status === 'connected' || c.status === 'running' || c.status === 'ready' || c.status === 'online' ? 'text-emerald-400' : c.status === 'offline' || c.status === 'stopped' || c.status === 'no model' ? 'text-rose-400' : 'text-amber-400'}>
                  {c.status.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Threat activity */}
      <Panel title="THREAT ACTIVITY">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-x-6 gap-y-2">
          <Metric label="EVENTS" value={isEmpty ? 0 : (stats?.total_events ?? 0)} />
          <Metric label="SESSIONS" value={isEmpty ? 0 : (stats?.total_sessions ?? 0)} onClick={() => onNavigate('sessions')} />
          <Metric label="ATTACKERS" value={isEmpty ? 0 : (stats?.unique_attackers ?? 0)} />
          <Metric label="DETECTIONS" value={isEmpty ? 0 : (stats?.total_detections ?? 0)} onClick={() => onNavigate('detections')} />
          <Metric label="ANOMALIES" value={isEmpty ? 0 : (stats?.anomalies ?? 0)} />
        </div>
      </Panel>

      {/* Empty state — NO TELEMETRY */}
      {isEmpty ? (
        <Panel title="TELEMETRY">
          <div className="py-8 text-center">
            <div className="text-sm font-mono text-muted-foreground mb-2">NO TELEMETRY RECEIVED</div>
            <div className="text-[11px] font-mono text-muted-foreground/60 mb-4">
              {sysStatus?.pi_reachable
                ? 'System is connected and waiting for honeypot activity.'
                : 'Pi is offline. Connect the Raspberry Pi to begin.'}
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
          {/* Label distribution (DEMO mode) */}
          {stats?.label_distribution && (
            <Panel title="ATTACK CLASSIFICATIONS" right="DEMO DATASET">
              <div className="space-y-1">
                {Object.entries(stats.label_distribution)
                  .sort((a, b) => b[1] - a[1])
                  .map(([label, count]) => {
                    const pct = (count / (stats.total_sessions || 1)) * 100
                    return (
                      <div key={label} className="flex items-center gap-2 text-[11px] font-mono">
                        <span className="w-40 text-muted-foreground uppercase tracking-wider truncate">{label.replace('_', ' ')}</span>
                        <div className="flex-1 h-3 bg-muted/30 border border-border/50 relative">
                          <div className="h-full bg-chart-2/60" style={{ width: `${pct}%` }} />
                        </div>
                        <span className="w-10 text-right text-foreground tabular-nums">{count}</span>
                      </div>
                    )
                  })}
              </div>
            </Panel>
          )}

          {/* Model status */}
          <Panel title="ML MODEL">
            <div className="text-[11px] font-mono">
              {stats?.model_version ? (
                <div className="flex items-center gap-4">
                  <span className="text-foreground">{stats.model_version}</span>
                  <span className={stats.model_status === 'active' ? 'text-emerald-400' : 'text-amber-400'}>{stats.model_status?.toUpperCase()}</span>
                  <button onClick={() => onNavigate('models')} className="ml-auto text-[10px] text-muted-foreground hover:text-foreground">VIEW MODELS →</button>
                </div>
              ) : (
                <span className="text-muted-foreground">NO MODEL TRAINED</span>
              )}
            </div>
          </Panel>

          {/* Clear demo data */}
          <div className="flex justify-end">
            <button
              onClick={async () => { await fetch('/api/ids/demo/clear', { method: 'POST' }); fetchAll() }}
              className="px-3 py-1 border border-border text-[10px] font-mono uppercase tracking-wider text-muted-foreground hover:text-foreground hover:bg-muted/30"
            >
              CLEAR DEMO DATA
            </button>
          </div>
        </>
      )}
    </div>
  )
}

function Metric({ label, value, onClick }: { label: string; value: number; onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      disabled={!onClick}
      className={`text-left py-1 border-b border-border/40 ${onClick ? 'hover:bg-muted/20 cursor-pointer' : 'cursor-default'}`}
    >
      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold font-mono tabular-nums text-foreground">{value.toLocaleString()}</div>
    </button>
  )
}
