'use client'

import { useEffect, useState, useCallback } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { Panel, StatusIndicator } from './shared'

// ---- State contract ----
// These types mirror the backend pi_client.py enums. The frontend must
// preserve the authoritative pi_status — NEVER collapse to 'CONNECTED / OFFLINE'.
//
// pi_status enum (UPPERCASE — authoritative from backend):
//   CONNECTED | OFFLINE | AUTH_FAILED | HOST_KEY_UNKNOWN |
//   HOST_KEY_CHANGED | TIMEOUT | SSH_NOT_INSTALLED |
//   NOT_CONFIGURED | ERROR | BACKEND_UNREACHABLE | UNCHECKED | DEMO
//
// honeypot.state (lowercase — container state from backend):
//   running | stopped | exited | missing | offline | not_configured | unknown | demo

interface SystemStatus {
  mode: string
  pi_reachable: boolean
  pi_configured: boolean
  pi_status: string  // authoritative enum — preserved verbatim
  fastapi_reachable: boolean
  elasticsearch: string
  components: { name: string; status: string; detail: string }[]
}

interface Honeypot {
  id: string
  name: string
  type: string
  container: string
  port: number
  configured: boolean
  container_exists: boolean
  state: string  // canonical field (NOT 'status')
  docker_status: string
}

interface HoneypotsResponse {
  mode: string
  pi_status: string
  pi_reachable: boolean
  pi_configured: boolean
  honeypots: Honeypot[]
}

// Color coding for the authoritative pi_status enum.
// Distinct colors for distinct states — no collapsing.
function piStatusColor(pi_status: string): string {
  switch (pi_status) {
    case 'CONNECTED': return 'text-emerald-400'
    case 'DEMO': return 'text-amber-400'
    case 'UNCHECKED': return 'text-slate-400'
    case 'NOT_CONFIGURED': return 'text-amber-400'
    case 'OFFLINE': return 'text-rose-400'
    case 'AUTH_FAILED': return 'text-rose-400'
    case 'HOST_KEY_UNKNOWN': return 'text-amber-400'
    case 'HOST_KEY_CHANGED': return 'text-rose-400'
    case 'TIMEOUT': return 'text-rose-400'
    case 'SSH_NOT_INSTALLED': return 'text-rose-400'
    case 'BACKEND_UNREACHABLE': return 'text-rose-400'
    case 'BACKEND_ERROR':
    case 'BACKEND_TIMEOUT': return 'text-rose-400'
    case 'ERROR': return 'text-rose-400'
    default: return 'text-slate-400'
  }
}

// Human-readable explanation for each pi_status — helps the operator understand
// WHAT failed, not just that something failed.
function piStatusExplanation(pi_status: string): string {
  switch (pi_status) {
    case 'CONNECTED': return 'SSH probe succeeded — Pi is reachable and authenticated'
    case 'DEMO': return 'Demo mode — no Pi interaction'
    case 'UNCHECKED': return 'No Pi probe has been attempted yet (EMPTY mode)'
    case 'NOT_CONFIGURED': return 'PI_IP / PI_SSH_USER not set in backend .env — cannot probe'
    case 'OFFLINE': return 'Pi was configured but network unreachable / connection refused'
    case 'AUTH_FAILED': return 'SSH authentication failed — check PI_SSH_KEY / PI_SSH_USER'
    case 'HOST_KEY_UNKNOWN': return 'Pi host key not in known_hosts — run ssh-keyscan to seed it'
    case 'HOST_KEY_CHANGED': return 'Pi host key MISMATCH — possible MITM or Pi reflash'
    case 'TIMEOUT': return 'SSH connection timed out — Pi may be down or firewall blocking'
    case 'SSH_NOT_INSTALLED': return 'ssh binary not found on the FastAPI host'
    case 'BACKEND_UNREACHABLE': return 'FastAPI backend itself is down — cannot probe Pi'
    case 'BACKEND_ERROR':
    case 'BACKEND_TIMEOUT': return 'FastAPI /honeypots endpoint returned an error'
    case 'ERROR': return 'Unexpected error during SSH probe'
    default: return `Unknown pi_status: ${pi_status}`
  }
}

// Honeypot container state → color
function honeypotStateColor(state: string): string {
  switch (state) {
    case 'running': return 'text-emerald-400'
    case 'stopped':
    case 'exited': return 'text-slate-400'
    case 'missing': return 'text-amber-400'
    case 'offline': return 'text-rose-400'
    case 'not_configured': return 'text-amber-400'
    case 'demo': return 'text-amber-400'
    case 'unknown': return 'text-slate-500'
    default: return 'text-slate-500'
  }
}

export function HoneypotsPage() {
  const [sysStatus, setSysStatus] = useState<SystemStatus | null>(null)
  const [honeypots, setHoneypots] = useState<HoneypotsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [actionMsg, setActionMsg] = useState<string | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)

  const fetchAll = useCallback(async () => {
    try {
      const [ss, h] = await Promise.all([
        fetch('/api/ids/pi/status').then(r => r.json()).catch(() => null),
        fetch('/api/ids/pi/honeypots').then(r => r.json()).catch(() => null),
      ])
      setSysStatus(ss)
      // Defensive: ensure honeypots.honeypots is ALWAYS an array.
      // If the response is malformed, fall back to empty array rather than
      // crashing on .map().
      if (h && Array.isArray(h.honeypots)) {
        setHoneypots(h)
      } else {
        setHoneypots({
          mode: ss?.mode ?? 'EMPTY',
          pi_status: ss?.pi_status ?? 'UNCHECKED',
          pi_reachable: false,
          pi_configured: false,
          honeypots: [],
        })
      }
    } catch (e) { console.error('honeypots fetch failed:', e) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void Promise.resolve().then(fetchAll) }, [fetchAll])

  const honeypotAction = async (id: string, action: 'start' | 'stop' | 'restart') => {
    setActionLoading(`${id}-${action}`)
    setActionMsg(null)
    try {
      const resp = await fetch(`/api/ids/pi/honeypots/${id}/${action}`, { method: 'POST' })
      const data = await resp.json().catch(() => ({ message: 'Request failed' }))
      setActionMsg(data.message || data.detail || `${action} returned ${resp.status}`)
      await fetchAll()
    } catch (e) {
      setActionMsg('Request failed')
    } finally {
      setActionLoading(null)
      setTimeout(() => setActionMsg(null), 5000)
    }
  }

  if (loading) {
    return (
      <div className="p-4 space-y-3">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-64" />
      </div>
    )
  }

  // Authoritative pi_status from either source (honeypots response preferred
  // because it's the most recent probe; fall back to sysStatus).
  const piStatus = honeypots?.pi_status || sysStatus?.pi_status || 'UNCHECKED'
  const piConfigured = honeypots?.pi_configured ?? sysStatus?.pi_configured ?? false
  const piReachable = honeypots?.pi_reachable ?? sysStatus?.pi_reachable ?? false
  const fastapiReachable = sysStatus?.fastapi_reachable ?? false
  const esStatus = sysStatus?.elasticsearch ?? 'offline'

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-baseline gap-3 border-b border-border pb-2">
        <h2 className="text-sm font-semibold tracking-wider text-foreground">HONEYPOTS</h2>
        <span className={`text-[10px] font-mono ml-auto ${piStatusColor(piStatus)}`}>
          PI: {piStatus}
        </span>
      </div>

      {/* Pi connection — render authoritative pi_status, NOT collapsed */}
      <Panel title="RASPBERRY PI">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-0 text-[11px] font-mono">
          <DetailRow
            label="PI_STATUS"
            value={piStatus}
            color={piStatusColor(piStatus)}
          />
          <DetailRow
            label="CONFIGURED"
            value={piConfigured ? 'YES' : 'NO'}
            color={piConfigured ? 'text-emerald-400' : 'text-amber-400'}
          />
          <DetailRow
            label="FASTAPI"
            value={fastapiReachable ? 'ONLINE' : 'OFFLINE'}
            color={fastapiReachable ? 'text-emerald-400' : 'text-rose-400'}
          />
          <DetailRow
            label="ES"
            value={esStatus.toUpperCase()}
            color={esStatus === 'ok' ? 'text-emerald-400' : esStatus === 'demo' ? 'text-amber-400' : 'text-rose-400'}
          />
        </div>
        {/* Always show the explanation — helps operator understand WHAT failed */}
        <div className={`mt-2 pt-2 border-t border-border/30 text-[10px] font-mono ${piStatusColor(piStatus)}`}>
          {piStatusExplanation(piStatus)}
        </div>
        {/* Only show container controls when the backend is reachable AND Pi is CONNECTED */}
        {!fastapiReachable && (
          <div className="mt-1 text-[10px] font-mono text-muted-foreground">
            FASTAPI BACKEND UNREACHABLE — HONEYPOT CONTROLS DISABLED
          </div>
        )}
        {fastapiReachable && !piReachable && piStatus !== 'NOT_CONFIGURED' && piStatus !== 'UNCHECKED' && (
          <div className="mt-1 text-[10px] font-mono text-amber-400">
            PI NOT CONNECTED — HONEYPOT CONTROLS DISABLED UNTIL SSH SUCCEEDS
          </div>
        )}
      </Panel>

      {/* Pi resources — only show when actually CONNECTED (not just reachable) */}
      {piStatus === 'CONNECTED' && (
        <Panel title="PI RESOURCES">
          <div className="grid grid-cols-3 gap-x-6 text-[11px] font-mono">
            {/* Resource values are UNKNOWN — we do not probe Pi RAM/CPU.
                Showing fabricated values would violate the "no fake health" rule.
                A future pass could add a lightweight /pi/resources endpoint
                that reads /proc/meminfo and /proc/loadavg via SSH. */}
            <DetailRow label="RAM" value="UNKNOWN" color="text-slate-500" />
            <DetailRow label="CPU" value="UNKNOWN" color="text-slate-500" />
            <DetailRow label="CONTAINERS" value="UNKNOWN" color="text-slate-500" />
          </div>
          <div className="mt-1 text-[10px] font-mono text-muted-foreground">
            RESOURCE VALUES UNKNOWN — NO PI RESOURCE PROBE IMPLEMENTED. ADDING ONE REQUIRES A LIGHTWEIGHT SSH READ OF /proc/meminfo + /proc/loadavg.
          </div>
        </Panel>
      )}

      {/* Honeypot services — always render, but state reflects actual backend probe */}
      <Panel title="HONEYPOT SERVICES" right="START / STOP / RESTART">
        <table className="w-full text-[11px] font-mono">
          <thead className="border-b border-border">
            <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
              <th className="text-left py-1.5 pr-3">SERVICE</th>
              <th className="text-left py-1.5 pr-3">TYPE</th>
              <th className="text-left py-1.5 pr-3">CONTAINER</th>
              <th className="text-right py-1.5 pr-3">PORT</th>
              <th className="text-left py-1.5 pr-3">STATE</th>
              <th className="text-right py-1.5">CONTROLS</th>
            </tr>
          </thead>
          <tbody>
            {(honeypots?.honeypots ?? []).map(h => (
              <tr key={h.id} className="border-b border-border/30">
                <td className="py-1.5 pr-3 text-foreground">{h.name}</td>
                <td className="py-1.5 pr-3 text-muted-foreground">{h.type}</td>
                <td className="py-1.5 pr-3 text-muted-foreground">{h.container}</td>
                <td className="py-1.5 pr-3 text-right text-foreground tabular-nums">{h.port}</td>
                <td className={`py-1.5 pr-3 ${honeypotStateColor(h.state)}`}>
                  {h.state.toUpperCase()}
                </td>
                <td className="py-1.5 text-right">
                  {/* Only enable controls when Pi is CONNECTED */}
                  <div className="flex justify-end gap-1">
                    <button
                      onClick={() => honeypotAction(h.id, 'start')}
                      disabled={actionLoading === `${h.id}-start` || piStatus !== 'CONNECTED'}
                      className="px-1.5 py-0.5 border border-border text-[9px] font-mono uppercase text-muted-foreground hover:text-emerald-400 hover:border-emerald-700 disabled:opacity-30"
                    >START</button>
                    <button
                      onClick={() => honeypotAction(h.id, 'stop')}
                      disabled={actionLoading === `${h.id}-stop` || piStatus !== 'CONNECTED'}
                      className="px-1.5 py-0.5 border border-border text-[9px] font-mono uppercase text-muted-foreground hover:text-rose-400 hover:border-rose-700 disabled:opacity-30"
                    >STOP</button>
                    <button
                      onClick={() => honeypotAction(h.id, 'restart')}
                      disabled={actionLoading === `${h.id}-restart` || piStatus !== 'CONNECTED'}
                      className="px-1.5 py-0.5 border border-border text-[9px] font-mono uppercase text-muted-foreground hover:text-amber-400 hover:border-amber-700 disabled:opacity-30"
                    >RESTART</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {actionMsg && (
          <div className="mt-2 pt-2 border-t border-border/30 text-[10px] font-mono text-amber-400">
            {actionMsg}
          </div>
        )}
        {piStatus !== 'CONNECTED' && (
          <div className="mt-2 text-[10px] font-mono text-muted-foreground">
            HONEYPOT CONTROLS REQUIRE PI_STATUS=CONNECTED — CURRENT: {piStatus}
          </div>
        )}
      </Panel>

      {/* Hardening checklist */}
      <Panel title="CONTAINER HARDENING">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-0.5 text-[11px] font-mono">
          {[
            'cap_drop: ALL',
            'security_opt: no-new-privileges',
            'read_only filesystem where practical',
            'mem_limit + cpus + pids_limit',
            'Non-root user',
            'Isolated honeynet network',
            'Docker.sock never exposed',
            '--privileged never used',
            'Log rotation',
            'Health checks + restart policy',
          ].map(item => (
            <div key={item} className="flex items-center gap-2 py-0.5">
              <span className="text-emerald-400">●</span>
              <span className="text-muted-foreground">{item}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}

function DetailRow({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="flex items-center justify-between py-1 border-b border-border/30">
      <span className="text-muted-foreground text-[10px] uppercase tracking-wider">{label}</span>
      <span className={`text-foreground ${color || ''}`}>{value}</span>
    </div>
  )
}
