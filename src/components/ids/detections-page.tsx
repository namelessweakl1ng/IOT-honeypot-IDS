'use client'

import { useEffect, useState, useCallback } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { Panel } from './shared'
import { Radio, ChevronRight } from 'lucide-react'

interface DetectionRow {
  detection_id: string
  session_id: string
  campaign_id?: string
  '@timestamp': string
  engine: string
  detector_version?: string
  rule_id?: string
  label: string
  classification: string
  severity: string
  confidence: number
  anomaly_score?: number
  threshold?: number
  model_id?: string | null
  model_version?: string | null
  feature_schema_version?: string | null
  persisted?: boolean
  explanation: string
  source?: { ip: string }
  device?: { id: string }
}

interface Lineage {
  detection: DetectionRow & { evidence?: any }
  session?: any
  events?: any[]
  features?: any
  campaign?: any
  model?: any
}

export function DetectionsPage() {
  const [detections, setDetections] = useState<DetectionRow[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [lineage, setLineage] = useState<Lineage | null>(null)
  const [loading, setLoading] = useState(true)
  const [mode, setMode] = useState<string>('EMPTY')
  const [backendUnavailable, setBackendUnavailable] = useState(false)

  const fetchAll = useCallback(async () => {
    try {
      const response = await fetch('/api/ids/detections?size=100')
      const d = await response.json()
      setDetections(d?.detections || [])
      setMode(d?.mode || 'EMPTY')
      setBackendUnavailable(!response.ok || Boolean(d?.error))
    } catch (e) { console.error(e); setBackendUnavailable(true) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void Promise.resolve().then(fetchAll) }, [fetchAll])

  useEffect(() => {
    if (!selected) return
    let cancelled = false
    fetch(`/api/ids/detections/${encodeURIComponent(selected)}`)
      .then(r => r.json())
      .then(d => { if (!cancelled) setLineage(d?.lineage || null) })
      .catch(() => { if (!cancelled) setLineage(null) })
    return () => { cancelled = true }
  }, [selected])

  if (loading) {
    return (
      <div className="p-4 space-y-3">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-64" />
      </div>
    )
  }

  const severityColor = (s: string) => s === 'critical' || s === 'high' ? 'text-rose-400'
    : s === 'medium' ? 'text-amber-400' : s === 'low' ? 'text-blue-400' : 'text-muted-foreground'
  const engineColor = (e: string) => e === 'rule_engine' ? 'text-blue-400'
    : e === 'anomaly_detector' ? 'text-amber-400'
    : e === 'hybrid' ? 'text-emerald-400' : 'text-muted-foreground'

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-baseline gap-3 border-b border-border pb-2">
        <h2 className="text-sm font-semibold tracking-wider text-foreground">DETECTIONS</h2>
        <span className="text-[10px] font-mono text-muted-foreground ml-auto">{mode} · {detections.length} DETECTIONS</span>
      </div>

      {backendUnavailable ? (
        <Panel title="DETECTION QUEUE"><div className="py-8 text-center text-sm font-mono text-rose-400">BACKEND UNAVAILABLE</div></Panel>
      ) : detections.length === 0 ? (
        <Panel title="DETECTION QUEUE">
          <div className="py-8 text-center">
            <Radio className="w-4 h-4 text-muted-foreground mx-auto mb-2" />
            <div className="text-sm font-mono text-muted-foreground mb-2">{mode === 'LIVE' ? 'NO DETECTIONS RETURNED' : 'NO DETECTIONS'}</div>
            <div className="text-[11px] font-mono text-muted-foreground/60 mb-4">
              This result describes the current API response only. No detection is not proof that activity was benign.
            </div>
          </div>
        </Panel>
      ) : (
        <>
          <Panel title="DETECTION QUEUE" right={`${detections.length} DETECTIONS`}>
            <div className="overflow-x-auto">
              <table className="w-full text-[11px] font-mono">
                <thead className="border-b border-border">
                  <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    <th className="text-left py-1.5 pr-3">SEVERITY</th>
                    <th className="text-left py-1.5 pr-3">TIME</th>
                    <th className="text-left py-1.5 pr-3">SOURCE</th>
                    <th className="text-left py-1.5 pr-3">LABEL</th>
                    <th className="text-left py-1.5 pr-3">ENGINE</th>
                    <th className="text-right py-1.5 pr-3">CONF</th>
                    <th className="text-left py-1.5 pr-3">SESSION</th>
                    <th className="text-left py-1.5 pr-3">CAMPAIGN</th>
                    <th className="text-left py-1.5"></th>
                  </tr>
                </thead>
                <tbody>
                  {detections.map(d => (
                    <tr
                      key={d.detection_id}
                      className={`border-b border-border/30 cursor-pointer hover:bg-accent/10 ${selected === d.detection_id ? 'bg-accent/20' : ''}`}
                      onClick={() => setSelected(d.detection_id)}
                    >
                      <td className={`py-1.5 pr-3 ${severityColor(d.severity)}`}>{d.severity.toUpperCase()}</td>
                      <td className="py-1.5 pr-3 text-muted-foreground">{(d['@timestamp'] || '').slice(0, 19)}</td>
                      <td className="py-1.5 pr-3 text-foreground">{d.source?.ip || '—'}</td>
                      <td className="py-1.5 pr-3 text-foreground">{d.label}</td>
                      <td className={`py-1.5 pr-3 ${engineColor(d.engine)}`}>{d.engine}</td>
                      <td className="py-1.5 pr-3 text-right text-foreground tabular-nums">{(d.confidence || 0).toFixed(2)}</td>
                      <td className="py-1.5 pr-3 text-muted-foreground">{(d.session_id || '').slice(0, 12)}…</td>
                      <td className="py-1.5 pr-3 text-muted-foreground">{d.campaign_id ? (d.campaign_id as string).slice(0, 12) + '…' : '—'}</td>
                      <td className="py-1.5 text-right"><ChevronRight className="w-3 h-3 text-muted-foreground" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          {selected && lineage && (
            <Panel title="DETECTION LINEAGE" right={lineage.detection?.detection_id}>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-[11px] font-mono">
                <div className="space-y-1">
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">DETECTION</div>
                  <div className="text-foreground">label: <span className="text-emerald-400">{lineage.detection?.label}</span></div>
                  <div className="text-foreground">engine: <span className="text-blue-400">{lineage.detection?.engine}</span></div>
                  <div className="text-muted-foreground">detector_version: {lineage.detection?.detector_version || '—'}</div>
                  <div className="text-muted-foreground">model_id: {lineage.detection?.model_id || '<none>'}</div>
                  <div className="text-muted-foreground">model_version: {lineage.detection?.model_version || '<none>'}</div>
                  <div className="text-muted-foreground">feature_schema: {lineage.detection?.feature_schema_version || '—'}</div>
                  <div className="text-muted-foreground">persisted: {lineage.detection?.persisted === false ? <span className="text-rose-400">NO</span> : <span className="text-emerald-400">YES</span>}</div>
                  {lineage.detection?.evidence?.contributed_signals && (
                    <div className="mt-2 pt-2 border-t border-border/30">
                      <div className="text-[10px] uppercase text-muted-foreground">CONTRIBUTED SIGNALS</div>
                      <div className="text-emerald-400">{lineage.detection.evidence.contributed_signals.join(' + ')}</div>
                      {lineage.detection.evidence.supervised_model_id ? (
                        <div className="text-muted-foreground text-[10px]">supervised_model: {lineage.detection.evidence.supervised_model_id}</div>
                      ) : (
                        <div className="text-muted-foreground text-[10px]">supervised_model: <span className="text-amber-400">NOT USED</span></div>
                      )}
                    </div>
                  )}
                </div>
                <div className="space-y-1">
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">LINEAGE CHAIN</div>
                  <div className="text-foreground">detection → session → events → features → campaign → model</div>
                  <div className="text-muted-foreground">session: {lineage.detection?.session_id?.slice(0, 16) || '<none>'}…</div>
                  <div className="text-muted-foreground">events: {lineage.events?.length || 0}</div>
                  <div className="text-muted-foreground">feature_schema: {lineage.features?.feature_schema_version || 'NOT AVAILABLE'}</div>
                  <div className="text-muted-foreground">campaign: {lineage.detection?.campaign_id?.slice(0, 16) || 'NOT CORRELATED'}</div>
                  <div className="text-muted-foreground">model: {lineage.model?.model_id || lineage.model?.engine || 'NOT USED'}</div>
                  <div className="text-muted-foreground">ground_truth_label: {lineage.session?.ground_truth_label || 'NOT ATTACHED'}</div>
                  <div className="text-muted-foreground">ground_truth_source: {lineage.session?.ground_truth_source || 'CONTROLLED RUN SUMMARY REQUIRED'}</div>
                  <div className="text-amber-300">The detection label is a detector prediction; ground truth is separate evidence.</div>
                </div>
              </div>
            </Panel>
          )}
        </>
      )}

      <Panel title="DETECTION ENGINES">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[11px] font-mono">
          <div className="border border-border/50 p-2">
            <div className="text-blue-400 font-semibold mb-1">RULE_ENGINE</div>
            <div className="text-muted-foreground text-[10px]">Deterministic patterns. 5 rules: brute_force, default_creds, command_injection, path_traversal, recon.</div>
          </div>
          <div className="border border-border/50 p-2">
            <div className="text-emerald-400 font-semibold mb-1">SUPERVISED_MODEL</div>
            <div className="text-muted-foreground text-[10px]">Learned behavioral patterns. RandomForest. Active model only — fresh state has no model.</div>
          </div>
          <div className="border border-border/50 p-2">
            <div className="text-amber-400 font-semibold mb-1">ANOMALY_DETECTOR</div>
            <div className="text-muted-foreground text-[10px]">IsolationForest + threshold calibrated to 5% FPR on benign validation. Score is a SIGNAL, not a malicious verdict.</div>
          </div>
        </div>
      </Panel>

      <Panel title="HYBRID POLICY">
        <div className="text-[11px] font-mono text-muted-foreground space-y-1">
          <div>• KNOWN_ATTACK: strong rule (conf ≥ 0.85) OR supervised (prob ≥ 0.7)</div>
          <div>• NOVEL_BEHAVIOR: anomaly signal + no rule + no supervised</div>
          <div>• HYBRID_AGREEMENT: multiple independent signals agree → severity=high</div>
          <div>• NO_SIGNAL: no detection (no fabrication)</div>
          <div className="text-[10px] text-muted-foreground/70 mt-2">Anomaly score is never collapsed to malicious — it contributes as evidence only.</div>
        </div>
      </Panel>
    </div>
  )
}
