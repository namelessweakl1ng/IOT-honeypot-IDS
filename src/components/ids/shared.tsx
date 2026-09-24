'use client'

// Shared SOC primitives — sharp corners, flat colors, monospace technical fields.
// No gradients. No glassmorphism. No rounded pills.

export function formatTimeAgo(iso: string): string {
  if (!iso) return '—'
  const ts = new Date(iso.replace('Z', '+00:00')).getTime()
  if (isNaN(ts)) return iso
  const diff = Date.now() - ts
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s`
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h`
  return `${Math.floor(diff / 86_400_000)}d`
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m${Math.floor(seconds % 60)}s`
  return `${Math.floor(seconds / 3600)}h${Math.floor((seconds % 3600) / 60)}m`
}

// Sharp 1px-border labels — no rounded pills
const LABEL_STYLES: Record<string, string> = {
  brute_force: 'border-rose-700 text-rose-300 bg-rose-950/40',
  default_credentials: 'border-orange-700 text-orange-300 bg-orange-950/40',
  reconnaissance: 'border-blue-700 text-blue-300 bg-blue-950/40',
  command_injection: 'border-fuchsia-800 text-fuchsia-300 bg-fuchsia-950/40',
  command_abuse: 'border-fuchsia-800 text-fuchsia-300 bg-fuchsia-950/40',
  path_traversal: 'border-purple-800 text-purple-300 bg-purple-950/40',
  anomaly: 'border-amber-700 text-amber-300 bg-amber-950/40',
  unknown: 'border-amber-700 text-amber-300 bg-amber-950/40',
  benign: 'border-emerald-700 text-emerald-300 bg-emerald-950/40',
  web_enumeration: 'border-blue-700 text-blue-300 bg-blue-950/40',
  file_retrieval: 'border-purple-800 text-purple-300 bg-purple-950/40',
  credential_attack: 'border-rose-700 text-rose-300 bg-rose-950/40',
}

const ENGINE_STYLES: Record<string, string> = {
  rule_engine: 'border-blue-700 text-blue-300 bg-blue-950/40',
  ml_classifier: 'border-emerald-700 text-emerald-300 bg-emerald-950/40',
  anomaly_detector: 'border-amber-700 text-amber-300 bg-amber-950/40',
}

export function LabelBadge({ label }: { label: string }) {
  const style = LABEL_STYLES[label] || 'border-slate-600 text-slate-400 bg-slate-900/40'
  return (
    <span className={`inline-block px-1.5 py-0 border text-[10px] font-mono uppercase tracking-wider ${style}`}>
      {label}
    </span>
  )
}

export function EngineBadge({ engine }: { engine: string }) {
  const style = ENGINE_STYLES[engine] || 'border-slate-600 text-slate-400 bg-slate-900/40'
  return (
    <span className={`inline-block px-1.5 py-0 border text-[10px] font-mono uppercase tracking-wider ${style}`}>
      {engine.replace('_', ' ')}
    </span>
  )
}

// Status indicator — small colored square + label
export function StatusIndicator({ status }: { status: string }) {
  const color = status === 'online' || status === 'connected' || status === 'ok' ? 'bg-emerald-500' :
                status === 'offline' || status === 'down' || status === 'error' ? 'bg-rose-500' :
                status === 'warning' || status === 'degraded' ? 'bg-amber-500' :
                'bg-slate-500' // synthetic / unknown
  return (
    <span className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-400">
      <span className={`inline-block w-1.5 h-1.5 ${color}`} />
      {status}
    </span>
  )
}

// Technical metric row — label on left, value on right, thin divider
export function Metric({ label, value, mono = true }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between py-1 border-b border-border/40 last:border-b-0">
      <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
      <span className={`text-xs text-foreground ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}

// Section header — thin rule under the title
export function SectionHeader({ title, right }: { title: string; right?: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between border-b border-border pb-1 mb-2">
      <h3 className="text-[11px] font-semibold uppercase tracking-widest text-foreground">{title}</h3>
      {right && <span className="text-[10px] font-mono text-muted-foreground">{right}</span>}
    </div>
  )
}

// Panel — 1px border, square corners, section header
export function Panel({ title, right, children, className = '' }: { title?: string; right?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <div className={`border border-border bg-card ${className}`}>
      {title && (
        <div className="flex items-baseline justify-between px-3 py-1.5 border-b border-border">
          <h3 className="text-[11px] font-semibold uppercase tracking-widest text-foreground">{title}</h3>
          {right && <span className="text-[10px] font-mono text-muted-foreground">{right}</span>}
        </div>
      )}
      <div className="p-3">{children}</div>
    </div>
  )
}
