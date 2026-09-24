'use client'

import { useEffect, useState } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { Panel, LabelBadge } from './shared'

interface Experiment {
  experiment_id: string
  model_id?: string
  algorithm?: string
  dataset_version?: string
  feature_version?: string
  seed?: number
  metrics?: Record<string, any>
  notes?: string
  type?: string
  split?: { train_size?: number; test_size?: number; test_ratio?: number }
}

interface Dataset {
  version: string
  path: string
  rows: number
  label_source: string
  feature_version: string
  created_at: string
  description: string
  label_distribution: Record<string, number>
}

interface Scenario {
  id: string
  name: string
  description: string
  protocol: string
  severity: string
  expected_behavior: string[]
}

export function ExperimentsPage() {
  const [experiments, setExperiments] = useState<Experiment[]>([])
  const [datasets, setDatasets] = useState<Dataset[]>([])
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      fetch('/api/ids/experiments').then(r => r.json()),
      fetch('/api/ids/datasets').then(r => r.json()),
      fetch('/api/ids/scenarios').then(r => r.json()),
    ])
      .then(([e, d, s]) => { setExperiments(e.experiments || []); setDatasets(d.datasets || []); setScenarios(s.scenarios || []) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="p-4 space-y-3">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-64" />
      </div>
    )
  }

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-baseline gap-3 border-b border-border pb-2">
        <h2 className="text-sm font-semibold tracking-wider text-foreground">EXPERIMENTS</h2>
        <span className="text-[10px] font-mono text-muted-foreground ml-auto">{experiments.length} RECORDED</span>
      </div>

      {/* Datasets */}
      {datasets.length > 0 && (
        <Panel title="DATASETS">
          <table className="w-full text-[11px] font-mono">
            <thead className="border-b border-border">
              <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="text-left py-1.5 pr-3">VERSION</th>
                <th className="text-left py-1.5 pr-3">PATH</th>
                <th className="text-right py-1.5 pr-3">ROWS</th>
                <th className="text-left py-1.5 pr-3">SOURCE</th>
                <th className="text-left py-1.5 pr-3">FEAT_VER</th>
                <th className="text-left py-1.5">LABELS</th>
              </tr>
            </thead>
            <tbody>
              {datasets.map(d => (
                <tr key={d.version} className="border-b border-border/30 hover:bg-muted/20">
                  <td className="py-1.5 pr-3 text-foreground">{d.version}</td>
                  <td className="py-1.5 pr-3 text-muted-foreground">{d.path}</td>
                  <td className="py-1.5 pr-3 text-right text-foreground tabular-nums">{d.rows}</td>
                  <td className="py-1.5 pr-3">
                    <span className={`px-1.5 py-0 border text-[9px] uppercase ${
                      d.label_source === 'SYNTHETIC' ? 'border-slate-600 text-slate-400 bg-slate-900/40' :
                      d.label_source === 'REAL CAPTURE' ? 'border-emerald-700 text-emerald-300 bg-emerald-950/40' :
                      'border-amber-700 text-amber-300 bg-amber-950/40'
                    }`}>{d.label_source}</span>
                  </td>
                  <td className="py-1.5 pr-3 text-muted-foreground">{d.feature_version}</td>
                  <td className="py-1.5 text-[10px] text-muted-foreground">{Object.entries(d.label_distribution).map(([k, v]) => `${k}=${v}`).join(' ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {/* Scenarios */}
      {scenarios.length > 0 && (
        <Panel title="ATTACKER SCENARIOS" right="LAB-SUBNET SAFETY ENFORCED">
          <table className="w-full text-[11px] font-mono">
            <thead className="border-b border-border">
              <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="text-left py-1.5 pr-3">ID</th>
                <th className="text-left py-1.5 pr-3">NAME</th>
                <th className="text-left py-1.5 pr-3">PROTOCOL</th>
                <th className="text-left py-1.5 pr-3">SEVERITY</th>
                <th className="text-left py-1.5">DESCRIPTION</th>
              </tr>
            </thead>
            <tbody>
              {scenarios.map(s => (
                <tr key={s.id} className="border-b border-border/30 hover:bg-muted/20">
                  <td className="py-1.5 pr-3 text-amber-300">{s.id}</td>
                  <td className="py-1.5 pr-3 text-foreground">{s.name}</td>
                  <td className="py-1.5 pr-3 text-muted-foreground">{s.protocol}</td>
                  <td className="py-1.5 pr-3">
                    <span className={`px-1.5 py-0 border text-[9px] uppercase ${
                      s.severity === 'high' ? 'border-rose-700 text-rose-300 bg-rose-950/40' :
                      s.severity === 'medium' ? 'border-amber-700 text-amber-300 bg-amber-950/40' :
                      'border-blue-700 text-blue-300 bg-blue-950/40'
                    }`}>{s.severity}</span>
                  </td>
                  <td className="py-1.5 text-muted-foreground text-[10px]">{s.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {/* Experiments log */}
      <Panel title="EXPERIMENT LOG" right="REPRODUCIBLE">
        {experiments.length === 0 ? (
          <div className="py-8 text-center text-[11px] font-mono text-muted-foreground">
            NO EXPERIMENTS RECORDED. RUN <span className="text-foreground">python -m model_lab.train</span>
          </div>
        ) : (
          <table className="w-full text-[11px] font-mono">
            <thead className="border-b border-border">
              <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="text-left py-1.5 pr-3">EXPERIMENT</th>
                <th className="text-left py-1.5 pr-3">MODEL</th>
                <th className="text-left py-1.5 pr-3">ALGORITHM</th>
                <th className="text-left py-1.5 pr-3">DATASET</th>
                <th className="text-left py-1.5 pr-3">FEAT_VER</th>
                <th className="text-right py-1.5 pr-3">SEED</th>
                <th className="text-right py-1.5 pr-3">TRAIN</th>
                <th className="text-right py-1.5 pr-3">TEST</th>
                <th className="text-right py-1.5 pr-3">F1</th>
                <th className="text-right py-1.5 pr-3">ACC</th>
              </tr>
            </thead>
            <tbody>
              {experiments.map(e => (
                <tr key={e.experiment_id} className="border-b border-border/30 hover:bg-muted/20">
                  <td className="py-1.5 pr-3 text-muted-foreground">{e.experiment_id?.slice(0, 28)}</td>
                  <td className="py-1.5 pr-3 text-foreground">{e.model_id || '—'}</td>
                  <td className="py-1.5 pr-3 text-muted-foreground">{e.algorithm || '—'}</td>
                  <td className="py-1.5 pr-3 text-muted-foreground">{e.dataset_version || '—'}</td>
                  <td className="py-1.5 pr-3 text-muted-foreground">{e.feature_version || '—'}</td>
                  <td className="py-1.5 pr-3 text-right text-muted-foreground tabular-nums">{e.seed ?? '—'}</td>
                  <td className="py-1.5 pr-3 text-right text-muted-foreground tabular-nums">{e.split?.train_size ?? e.metrics?.n_train ?? e.metrics?.n_samples ?? '—'}</td>
                  <td className="py-1.5 pr-3 text-right text-muted-foreground tabular-nums">{e.split?.test_size ?? e.metrics?.n_test ?? '—'}</td>
                  <td className="py-1.5 pr-3 text-right text-foreground tabular-nums">
                    {e.metrics?.f1_macro != null ? `${(e.metrics.f1_macro * 100).toFixed(1)}%` :
                     e.metrics?.in_sample_f1_macro != null ? `${(e.metrics.in_sample_f1_macro * 100).toFixed(1)}%` : '—'}
                  </td>
                  <td className="py-1.5 pr-3 text-right text-foreground tabular-nums">
                    {e.metrics?.accuracy != null ? `${(e.metrics.accuracy * 100).toFixed(1)}%` :
                     e.metrics?.in_sample_accuracy != null ? `${(e.metrics.in_sample_accuracy * 100).toFixed(1)}%` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}
