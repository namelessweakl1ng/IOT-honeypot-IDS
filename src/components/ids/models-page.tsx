'use client'

import { useEffect, useState, useCallback } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { Panel, LabelBadge } from './shared'

interface ModelMeta {
  model_id: string
  algorithm: string
  dataset_version: string
  feature_version: string
  features: string[]
  metrics: Record<string, any>
  seed: number
  status: string
  notes: string
  created_at_iso: string
  leaky_features_excluded?: string[]
}

interface Stats { mode: string; status: string; model_version?: string | null; model_status?: string | null }

const LEAKY = ['contains_path_traversal', 'contains_command_injection', 'contains_default_credentials']

export function ModelsPage() {
  const [models, setModels] = useState<ModelMeta[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)
  const [demoLoading, setDemoLoading] = useState(false)

  const fetchAll = useCallback(async () => {
    try {
      const [m, s] = await Promise.all([
        fetch('/api/ids/models').then(r => r.json()),
        fetch('/api/ids/stats').then(r => r.json()),
      ])
      setModels(m.models || [])
      setStats(s)
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

  if (loading) return <div className="p-4"><Skeleton className="h-6 w-48" /></div>

  const isEmpty = (stats?.mode === 'EMPTY' || stats?.status === 'empty') && models.length === 0

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-baseline gap-3 border-b border-border pb-2">
        <h2 className="text-sm font-semibold tracking-wider text-foreground">ML / MODELS</h2>
        <span className="text-[10px] font-mono text-muted-foreground ml-auto">{models.length} REGISTERED · {stats?.mode || 'EMPTY'}</span>
      </div>

      {isEmpty ? (
        <Panel title="ML MODEL">
          <div className="py-8 text-center">
            <div className="text-sm font-mono text-muted-foreground mb-2">NO MODEL TRAINED</div>
            <div className="text-[11px] font-mono text-muted-foreground/60 mb-4">
              Train a model after collecting honeypot telemetry. Use model-lab CLI or load demo data to see the model registry.
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
          {/* Active model */}
          {(() => {
            const active = models.find(m => m.status === 'active') || models[0]
            if (!active) return null
            const hasHeldOut = !!(active.metrics.accuracy || active.metrics.f1_macro)
            return (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                <Panel title={active.status === 'active' ? 'ACTIVE MODEL' : 'LATEST MODEL'} right={active.status.toUpperCase()}>
                  <div className="text-[11px] font-mono space-y-0.5">
                    <DetailRow label="MODEL_ID" value={active.model_id} />
                    <DetailRow label="ALGORITHM" value={active.algorithm} />
                    <DetailRow label="DATASET" value={active.dataset_version} />
                    <DetailRow label="FEATURE_VERSION" value={active.feature_version} />
                    <DetailRow label="FEATURES" value={`${active.features.length} dimensions`} />
                    {active.leaky_features_excluded && active.leaky_features_excluded.length > 0 && (
                      <DetailRow label="LEAKY_EXCLUDED" value={active.leaky_features_excluded.join(', ')} />
                    )}
                    <DetailRow label="TRAIN_SIZE" value={`${active.metrics.n_train ?? active.metrics.n_samples ?? '—'} sessions`} />
                    <DetailRow label="TEST_SIZE" value={active.metrics.n_test != null ? `${active.metrics.n_test} sessions` : '—'} />
                    <DetailRow label="SEED" value={String(active.seed)} />
                    <DetailRow label="CREATED" value={active.created_at_iso} />
                  </div>
                </Panel>
                <Panel title="METRICS">
                  {hasHeldOut ? (
                    <div className="mb-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-emerald-400 mb-1.5 border-b border-border/40 pb-1">HELD-OUT EVALUATION</div>
                      <div className="grid grid-cols-2 gap-2">
                        <MetricVal label="ACCURACY" value={active.metrics.accuracy} highlight />
                        <MetricVal label="F1 (MACRO)" value={active.metrics.f1_macro} highlight />
                        <MetricVal label="PRECISION" value={active.metrics.precision_macro} />
                        <MetricVal label="RECALL" value={active.metrics.recall_macro} />
                      </div>
                    </div>
                  ) : (
                    <div className="border border-amber-800 bg-amber-950/20 px-3 py-2 mb-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-amber-400">HELD-OUT EVALUATION</div>
                      <div className="text-sm font-mono text-amber-300 mt-0.5">NOT EVALUATED</div>
                    </div>
                  )}
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1.5 border-b border-border/40 pb-1">IN-SAMPLE (DIAGNOSTIC ONLY)</div>
                    <div className="grid grid-cols-2 gap-2 opacity-60">
                      <MetricVal label="ACCURACY" value={active.metrics.in_sample_accuracy ?? 0} />
                      <MetricVal label="F1 (MACRO)" value={active.metrics.in_sample_f1_macro ?? 0} />
                    </div>
                  </div>
                </Panel>
              </div>
            )
          })()}

          {/* Feature importances */}
          {models.find(m => m.status === 'active')?.metrics.feature_importances && (() => {
            const fi = models.find(m => m.status === 'active')!.metrics.feature_importances
            const entries = Object.entries(fi).sort((a: any, b: any) => b[1] - a[1]).slice(0, 12)
            const max = Number(entries[0]?.[1] || 1)
            return (
              <Panel title="FEATURE IMPORTANCES" right="RANDOM_FOREST">
                <div className="space-y-0.5">
                  {entries.map(([name, rawImportance]: any) => {
                    const imp = Number(rawImportance)
                    const isLeaky = LEAKY.includes(name)
                    return (
                      <div key={name} className="flex items-center gap-2 text-[11px] font-mono">
                        <span className={`w-44 truncate ${isLeaky ? 'text-rose-400' : 'text-muted-foreground'}`}>
                          {isLeaky && '⚠ '}{name}
                        </span>
                        <div className="flex-1 h-2 bg-muted/30 border border-border/30 relative">
                          <div className={`h-full ${isLeaky ? 'bg-rose-600/60' : 'bg-emerald-600/50'}`} style={{ width: `${(imp / max) * 100}%` }} />
                        </div>
                        <span className="w-12 text-right text-foreground tabular-nums">{(imp * 100).toFixed(1)}%</span>
                      </div>
                    )
                  })}
                </div>
              </Panel>
            )
          })()}

          {/* Model registry table */}
          <Panel title="MODEL REGISTRY">
            <div className="overflow-x-auto">
              <table className="w-full text-[11px] font-mono">
                <thead className="border-b border-border">
                  <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    <th className="text-left py-1.5 pr-3">MODEL</th>
                    <th className="text-left py-1.5 pr-3">ALGORITHM</th>
                    <th className="text-left py-1.5 pr-3">DATASET</th>
                    <th className="text-left py-1.5 pr-3">FEAT_VER</th>
                    <th className="text-left py-1.5 pr-3">STATUS</th>
                    <th className="text-right py-1.5 pr-3">HELD-OUT F1</th>
                    <th className="text-right py-1.5 pr-3">IN-SAMPLE F1</th>
                    <th className="text-left py-1.5">CREATED</th>
                  </tr>
                </thead>
                <tbody>
                  {models.map(m => (
                    <tr key={m.model_id} className="border-b border-border/30 hover:bg-muted/20">
                      <td className="py-1.5 pr-3 text-foreground">{m.model_id}</td>
                      <td className="py-1.5 pr-3 text-muted-foreground">{m.algorithm}</td>
                      <td className="py-1.5 pr-3 text-muted-foreground">{m.dataset_version}</td>
                      <td className="py-1.5 pr-3 text-muted-foreground">{m.feature_version}</td>
                      <td className="py-1.5 pr-3">
                        <span className={`px-1.5 py-0 border text-[9px] uppercase ${
                          m.status === 'active' ? 'border-emerald-700 text-emerald-300 bg-emerald-950/40' :
                          m.status === 'retired' ? 'border-rose-700 text-rose-300 bg-rose-950/40' :
                          m.status === 'validated' ? 'border-blue-700 text-blue-300 bg-blue-950/40' :
                          'border-amber-700 text-amber-300 bg-amber-950/40'
                        }`}>{m.status}</span>
                      </td>
                      <td className="py-1.5 pr-3 text-right text-foreground tabular-nums">
                        {m.metrics.f1_macro != null ? `${(m.metrics.f1_macro * 100).toFixed(1)}%` : <span className="text-amber-400">NOT_EVAL</span>}
                      </td>
                      <td className="py-1.5 pr-3 text-right text-muted-foreground tabular-nums">
                        {m.metrics.in_sample_f1_macro != null ? `${(m.metrics.in_sample_f1_macro * 100).toFixed(1)}%` : '—'}
                      </td>
                      <td className="py-1.5 text-muted-foreground">{m.created_at_iso?.slice(0, 19)}</td>
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

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-2 py-0.5 border-b border-border/20">
      <span className="text-muted-foreground text-[10px] uppercase tracking-wider">{label}</span>
      <span className="text-foreground text-right truncate">{value || '—'}</span>
    </div>
  )
}

function MetricVal({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div className={`border px-2 py-1 ${highlight ? 'border-emerald-800 bg-emerald-950/20' : 'border-border/50 bg-muted/10'}`}>
      <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className={`text-sm font-mono tabular-nums ${highlight ? 'text-emerald-300' : 'text-foreground'}`}>
        {(value * 100).toFixed(1)}%
      </div>
    </div>
  )
}
