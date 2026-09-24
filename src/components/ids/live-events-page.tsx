'use client'

import { useEffect, useState, useCallback } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { Panel, LabelBadge } from './shared'

interface HoneypotEvent {
  event_id: string
  session_id: string
  '@timestamp': string
  ingested_at?: string
  source: { ip: string; port: number }
  destination?: { ip: string; port: number }
  device: { id: string; type: string; hostname?: string; container?: string }
  protocol: string
  event: { type: string; category?: string; action?: string; note?: string }
  honeypot: { name: string; container?: string }
  http?: {
    method?: string; uri?: string; status?: number;
    user_agent?: string; bytes_in?: number; bytes_out?: number;
  }
  attack?: {
    session_id?: string; stage?: string;
    classification?: string | null; confidence?: number;
  }
}

interface EventsResponse {
  mode: string
  events: HoneypotEvent[]
  total: number
  error?: string
}

interface Stats { mode: string; status: string; total_events?: number }

function formatTime(iso: string): string {
  if (!iso) return '—'
  try {
    const d = new Date(iso.replace('Z', '+00:00'))
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch { return iso }
}

export function LiveEventsPage() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [eventsData, setEventsData] = useState<EventsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [demoLoading, setDemoLoading] = useState(false)

  const fetchAll = useCallback(async () => {
    try {
      const [s, e] = await Promise.all([
        fetch('/api/ids/stats').then(r => r.json()).catch(() => null),
        fetch('/api/ids/events?size=100').then(r => r.json()).catch(() => null),
      ])
      setStats(s)
      setEventsData(e)
    } catch (err) { console.error('fetch failed:', err) }
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

  if (loading) return <div className="p-4"><Skeleton className="h-6 w-48" /></div>

  const mode = stats?.mode || eventsData?.mode || 'EMPTY'
  const isEmpty = mode === 'EMPTY'
  const isDemo = mode === 'DEMO'
  const isLive = mode === 'LIVE'
  const hasError = eventsData?.error
  const events = eventsData?.events || []
  const total = eventsData?.total || 0

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-baseline gap-3 border-b border-border pb-2">
        <h2 className="text-sm font-semibold tracking-wider text-foreground">LIVE EVENTS</h2>
        <span className="text-[10px] font-mono text-muted-foreground ml-auto">
          {mode} · {isLive ? `${total} EVENTS` : ''}
        </span>
      </div>

      {isEmpty ? (
        <Panel title="EVENT STREAM">
          <div className="py-8 text-center">
            <div className="text-sm font-mono text-muted-foreground mb-2">NO TELEMETRY RECEIVED</div>
            <div className="text-[11px] font-mono text-muted-foreground/60 mb-4">
              Events will appear here when honeypot telemetry reaches Elasticsearch via Filebeat → Logstash.
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
      ) : isDemo ? (
        <>
          <div className="border border-amber-800 bg-amber-950/30 px-3 py-1.5 text-[10px] font-mono text-amber-300">
            DEMO MODE — DATA FROM SYNTHETIC DATASET, NOT LIVE TELEMETRY
          </div>
          <Panel title="EVENT STREAM" right="DEMO DATASET">
            <div className="py-8 text-center text-[11px] font-mono text-muted-foreground">
              DEMO DATASET CONTAINS SESSION-LEVEL FEATURES ONLY.<br />
              LIVE EVENT STREAMS REQUIRE ELASTICSEARCH + FASTAPI CONNECTED TO THE PI.
            </div>
          </Panel>
        </>
      ) : isLive && hasError ? (
        <Panel title="EVENT STREAM" right="LIVE">
          <div className="py-8 text-center">
            <div className="text-sm font-mono text-rose-400 mb-2">BACKEND UNAVAILABLE</div>
            <div className="text-[11px] font-mono text-muted-foreground/60 mb-2">
              Cannot fetch events from FastAPI / Elasticsearch.
            </div>
            <div className="text-[10px] font-mono text-muted-foreground/40">
              {eventsData?.error}
            </div>
          </div>
        </Panel>
      ) : isLive && events.length === 0 ? (
        <Panel title="EVENT STREAM" right="LIVE">
          <div className="py-8 text-center">
            <div className="text-sm font-mono text-muted-foreground mb-2">0 EVENTS</div>
            <div className="text-[11px] font-mono text-muted-foreground/60">
              Pi is connected but no attacker activity has produced telemetry yet.
            </div>
          </div>
        </Panel>
      ) : isLive ? (
        <Panel title="EVENT STREAM" right={`${total} EVENTS`}>
          <div className="overflow-x-auto">
            <table className="w-full text-[11px] font-mono">
              <thead className="border-b border-border">
                <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
                  <th className="text-left py-1.5 pr-3">TIME</th>
                  <th className="text-left py-1.5 pr-3">SOURCE</th>
                  <th className="text-left py-1.5 pr-3">DESTINATION</th>
                  <th className="text-left py-1.5 pr-3">HONEYPOT</th>
                  <th className="text-left py-1.5 pr-3">PROTOCOL</th>
                  <th className="text-left py-1.5 pr-3">EVENT</th>
                  <th className="text-left py-1.5 pr-3">SESSION</th>
                  <th className="text-left py-1.5">CLASSIFICATION</th>
                </tr>
              </thead>
              <tbody>
                {events.map(ev => (
                  <tr key={ev.event_id} className="border-b border-border/30 hover:bg-muted/20">
                    <td className="py-1.5 pr-3 text-muted-foreground whitespace-nowrap">
                      {formatTime(ev['@timestamp'])}
                    </td>
                    <td className="py-1.5 pr-3 text-foreground">
                      {ev.source?.ip || '—'}:{ev.source?.port || '—'}
                    </td>
                    <td className="py-1.5 pr-3 text-muted-foreground">
                      {ev.destination?.ip || '—'}:{ev.destination?.port || '—'}
                    </td>
                    <td className="py-1.5 pr-3 text-foreground">{ev.honeypot?.name || '—'}</td>
                    <td className="py-1.5 pr-3 text-muted-foreground uppercase">{ev.protocol || '—'}</td>
                    <td className="py-1.5 pr-3 text-foreground">
                      {ev.event?.action || ev.event?.type || '—'}
                      {ev.http?.method && ev.http?.uri && (
                        <span className="text-muted-foreground ml-1">
                          {ev.http.method} {ev.http.uri}
                        </span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 text-muted-foreground text-[10px]">
                      {ev.session_id ? ev.session_id.slice(0, 8) : '—'}
                    </td>
                    <td className="py-1.5">
                      {ev.attack?.classification ? (
                        <LabelBadge label={ev.attack.classification} />
                      ) : (
                        <span className="text-muted-foreground text-[10px]">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}
    </div>
  )
}
