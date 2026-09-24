/**
 * TRAPSIG — IDS data adapter.
 *
 * ARCHITECTURE:
 * - Default state: EMPTY (zero data, zero models, zero telemetry)
 * - DEMO mode: loaded ONLY when user explicitly clicks "LOAD DEMO DATA"
 * - LIVE mode: proxies to the canonical FastAPI at FASTAPI_URL
 *
 * The adapter NEVER automatically loads data. Fresh startup = empty.
 * Demo data requires an explicit POST /api/ids/demo/load action.
 *
 * State is stored on globalThis to persist across Next.js API route
 * invocations (Turbopack may create separate module instances).
 */

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { parse } from 'csv-parse/sync'

// ---- Types ----
export type Mode = 'EMPTY' | 'DEMO' | 'LIVE'
export type DetectionStatus = 'NEW' | 'INVESTIGATING' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'RESOLVED'

export interface AuditEntry {
  timestamp: string
  event: string
  detail?: string
}

export interface SessionRow {
  session_id: string
  label: string
  label_source: string
  campaign_id: string
  scenario_id: string
  dataset_version: string
  created_at: string
  features: Record<string, number>
}

export interface ModelMeta {
  model_id: string
  algorithm: string
  dataset_version: string
  feature_version: string
  features: string[]
  hyperparameters: Record<string, unknown>
  metrics: Record<string, any>
  seed: number
  status: string
  notes: string
  created_at: number
  created_at_iso: string
  leaky_features_excluded?: string[]
  provenance?: string  // 'legacy-demo' | 'production' | undefined
  provenance_note?: string
}

export interface Scenario {
  id: string
  name: string
  description: string
  protocol: string
  severity: string
  expected_behavior: string[]
}

// ---- Global state singleton ----
// Persists across Next.js API route invocations in the same process.
interface GlobalState {
  mode: Mode
  auditLog: AuditEntry[]
  detectionStatuses: Map<string, DetectionStatus>
}

const g = globalThis as unknown as { __trapsig_state?: GlobalState }
if (!g.__trapsig_state) {
  g.__trapsig_state = {
    mode: 'EMPTY',
    auditLog: [],
    detectionStatuses: new Map(),
  }
}
const _state = g.__trapsig_state

function getMode(): Mode { return _state.mode }
function setMode(mode: Mode): void { _state.mode = mode }

// ---- Audit log ----
const MAX_AUDIT_ENTRIES = 200

function auditLog(event: string, detail?: string): void {
  _state.auditLog.unshift({
    timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    event,
    detail,
  })
  if (_state.auditLog.length > MAX_AUDIT_ENTRIES) _state.auditLog.length = MAX_AUDIT_ENTRIES
}

export function getAuditLog(): { entries: AuditEntry[] } {
  return { entries: _state.auditLog }
}

// ---- Detection lifecycle ----
export function getDetectionStatus(detectionId: string): DetectionStatus {
  return _state.detectionStatuses.get(detectionId) || 'NEW'
}

export function setDetectionStatus(detectionId: string, status: DetectionStatus): { success: boolean; message: string } {
  const validTransitions: Record<DetectionStatus, DetectionStatus[]> = {
    NEW: ['INVESTIGATING', 'CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED'],
    INVESTIGATING: ['CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED'],
    CONFIRMED: ['RESOLVED'],
    FALSE_POSITIVE: ['RESOLVED'],
    RESOLVED: [],
  }
  const current = getDetectionStatus(detectionId)
  if (!validTransitions[current].includes(status)) {
    return { success: false, message: `Invalid transition: ${current} → ${status}` }
  }
  _state.detectionStatuses.set(detectionId, status)
  auditLog('DETECTION_STATUS_CHANGED', `${detectionId}: ${current} → ${status}`)
  return { success: true, message: `Detection ${detectionId} status: ${status}` }
}

// ---- Project root resolution ----
const FASTAPI_URL = process.env.FASTAPI_URL || 'http://localhost:8000'

function findProjectRoot(): string {
  if (process.env.IOT_HONEYPOT_IDS_ROOT) return process.env.IOT_HONEYPOT_IDS_ROOT
  for (const start of [typeof __dirname !== 'undefined' ? __dirname : process.cwd(), process.cwd()]) {
    let dir = start
    for (let i = 0; i < 10; i++) {
      if (existsSync(join(dir, 'iot-honeypot-ids', 'README.md'))) return join(dir, 'iot-honeypot-ids')
      const parent = join(dir, '..')
      if (parent === dir) break
      dir = parent
    }
  }
  return '/nonexistent/iot-honeypot-ids'
}

const REPO_ROOT = findProjectRoot()
const DATASET_CSV = join(REPO_ROOT, 'model-lab/datasets/v1/sessions.csv')
const MODELS_DIR = join(REPO_ROOT, 'model-lab/models')
const EXPERIMENTS_DIR = join(REPO_ROOT, 'model-lab/experiments')
const SCENARIOS_DIR = join(REPO_ROOT, 'attacker/scenarios')

const FEATURE_NAMES = [
  'event_count', 'duration_s', 'bytes_in_total', 'bytes_out_total',
  'auth_attempts', 'auth_successes', 'auth_failure_ratio', 'unique_usernames',
  'command_count', 'command_diversity', 'http_request_count', 'http_uri_diversity',
  'http_status_4xx_ratio', 'http_status_5xx_ratio', 'unique_protocols',
  'devices_touched', 'ports_touched', 'time_between_events_mean_s',
  'time_between_events_stdev_s', 'request_rate_per_min',
  'auth_failure_rate_per_min', 'contains_path_traversal',
  'contains_command_injection', 'contains_default_credentials', 'is_recon_only',
]

// ---- Demo data control ----
// The backend owns the authoritative mode. These functions are transactional:
// they call the backend FIRST, then set frontend cache ONLY on backend confirmation.
// If the backend is unreachable, they FAIL — no offline demo mode is permitted.
// This prevents frontend/backend mode divergence.

export async function loadDemoData(): Promise<{ success: boolean; message: string; count: number }> {
  // Step 1: Sync from backend — don't trust stale frontend cache
  const sync = await syncModeFromBackend()
  if (!sync.ok) {
    return { success: false, message: `Backend unreachable — cannot load demo data: ${sync.error}`, count: 0 }
  }

  // Step 2: Check backend-authoritative mode
  if (sync.mode === 'LIVE') {
    return { success: false, message: 'Cannot load demo data while in LIVE mode', count: 0 }
  }
  if (sync.mode === 'DEMO') {
    // Idempotent — already in DEMO. But verify local demo data is actually available.
    // If the local dataset is missing, this is an inconsistent state: backend says
    // DEMO but the demo payload is absent. Roll back to EMPTY.
    const rows = loadDatasetRows()
    if (rows.length === 0) {
      // Local demo data missing while backend is DEMO — attempt rollback to EMPTY.
      // CRITICAL: verify HTTP success before changing frontend mode.
      // fetch() does NOT throw for 401/403/500 — we must check response.ok
      // AND validate the response body confirms mode === EMPTY.
      const apiKey = getBackendApiKey()
      const headers: Record<string, string> = {}
      if (apiKey) headers['X-API-Key'] = apiKey
      try {
        const resetResp = await fetch(`${FASTAPI_URL}/mode/reset`, { method: 'POST', headers, signal: AbortSignal.timeout(5000) })
        if (!resetResp.ok) {
          // Reset failed (401/403/500/etc.) — backend is still DEMO.
          // Do NOT change frontend mode. Return explicit failure.
          return { success: false, message: `Backend is DEMO but local demo dataset is missing, and backend reset failed (HTTP ${resetResp.status})`, count: 0 }
        }
        // Reset returned 2xx — verify the response body confirms EMPTY
        const resetBody = await resetResp.json().catch(() => null)
        if (!resetBody || resetBody.mode !== 'EMPTY') {
          // Malformed response or mode !== EMPTY — backend state is uncertain.
          // Do NOT change frontend mode. Return explicit failure.
          return { success: false, message: 'Backend is DEMO but local demo dataset is missing, and backend reset response was malformed or did not confirm EMPTY', count: 0 }
        }
        // Backend confirmed EMPTY — safe to update frontend cache
        setMode('EMPTY')
      } catch {
        // Network error (fetch threw) — backend state is unknown.
        // Do NOT change frontend mode. Return explicit failure.
        return { success: false, message: 'Backend is DEMO but local demo dataset is missing, and backend reset failed (network error)', count: 0 }
      }
      return { success: false, message: 'Backend was DEMO but local demo dataset is missing — rolled back to EMPTY', count: 0 }
    }
    return { success: true, message: 'Demo data already loaded', count: rows.length }
  }

  // Step 3: backend is EMPTY — ask backend to transition to DEMO
  const apiKey = getBackendApiKey()
  const headers: Record<string, string> = {}
  if (apiKey) headers['X-API-Key'] = apiKey
  try {
    const resp = await fetch(`${FASTAPI_URL}/mode/demo`, {
      method: 'POST', headers, signal: AbortSignal.timeout(5000),
    })
    if (!resp.ok) {
      if (resp.status === 401 || resp.status === 403) {
        return { success: false, message: 'Backend rejected: auth failed', count: 0 }
      }
      if (resp.status === 409) {
        const body = await resp.json().catch(() => null)
        return { success: false, message: body?.detail || 'Backend rejected mode transition', count: 0 }
      }
      return { success: false, message: `Backend returned ${resp.status}`, count: 0 }
    }
  } catch (e) {
    // Backend unreachable — FAIL. Do NOT load demo locally. Do NOT set frontend mode.
    const msg = e instanceof Error ? e.message : String(e)
    return { success: false, message: `Backend unreachable: ${msg}`, count: 0 }
  }

  // Step 4: Backend accepted DEMO — load local demo data
  const rows = loadDatasetRows()
  if (rows.length === 0) {
    // Demo data not found — roll back backend to EMPTY (transactional).
    // CRITICAL: verify HTTP success before reporting rollback.
    let rollbackConfirmed = false
    try {
      const resetResp = await fetch(`${FASTAPI_URL}/mode/reset`, { method: 'POST', headers, signal: AbortSignal.timeout(5000) })
      if (!resetResp.ok) {
        // Reset failed — backend state is uncertain (may still be DEMO).
        // Re-sync from backend to get the authoritative state.
        const resync = await syncModeFromBackend()
        if (resync.ok) setMode(resync.mode)
        return { success: false, message: `No synthetic dataset found on disk, and backend reset failed (HTTP ${resetResp.status})`, count: 0 }
      }
      const resetBody = await resetResp.json().catch(() => null)
      if (!resetBody || resetBody.mode !== 'EMPTY') {
        // Malformed response — backend state is uncertain.
        // Re-sync from backend to get the authoritative state.
        const resync = await syncModeFromBackend()
        if (resync.ok) setMode(resync.mode)
        return { success: false, message: 'No synthetic dataset found on disk, and backend reset response was malformed', count: 0 }
      }
      // Backend confirmed EMPTY — update frontend cache to match.
      setMode('EMPTY')
      rollbackConfirmed = true
    } catch {
      // Network error — backend state is unknown.
      // Re-sync from backend to get the authoritative state.
      const resync = await syncModeFromBackend()
      if (resync.ok) setMode(resync.mode)
      return { success: false, message: 'No synthetic dataset found on disk, and backend reset failed (network error)', count: 0 }
    }
    if (rollbackConfirmed) {
      return { success: false, message: 'No synthetic dataset found on disk — backend rolled back to EMPTY', count: 0 }
    }
    // Fallback (should not reach here, but for safety)
    return { success: false, message: 'No synthetic dataset found on disk', count: 0 }
  }

  // Step 5: Both backend DEMO and local data established — set frontend cache
  setMode('DEMO')
  auditLog('DEMO_DATA_LOADED', `${rows.length} sessions from synthetic dataset v1`)
  return { success: true, message: `Demo data loaded: ${rows.length} sessions from synthetic dataset v1`, count: rows.length }
}

export async function clearDemoData(): Promise<{ success: boolean; message: string }> {
  // Step 1: Ask backend to reset to EMPTY
  const apiKey = getBackendApiKey()
  const headers: Record<string, string> = {}
  if (apiKey) headers['X-API-Key'] = apiKey
  try {
    const resp = await fetch(`${FASTAPI_URL}/mode/reset`, {
      method: 'POST', headers, signal: AbortSignal.timeout(5000),
    })
    if (!resp.ok) {
      if (resp.status === 401 || resp.status === 403) {
        return { success: false, message: 'Backend rejected: auth failed' }
      }
      if (resp.status === 409) {
        const body = await resp.json().catch(() => null)
        return { success: false, message: body?.detail || 'Backend rejected mode transition' }
      }
      return { success: false, message: `Backend returned ${resp.status}` }
    }
    // HTTP 2xx — but we MUST validate the response body confirms mode == EMPTY.
    // fetch() does NOT throw for non-2xx; and a 200 with {mode:"DEMO"} or {}
    // would be a contract violation. We must NOT setMode('EMPTY') without
    // explicit backend confirmation.
    const body = await resp.json().catch(() => null)
    if (!body || body.mode !== 'EMPTY') {
      // Malformed response or mode != EMPTY — backend state is uncertain.
      // Do NOT change frontend mode. Return explicit failure.
      return { success: false, message: 'Backend reset response was malformed or did not confirm EMPTY' }
    }
  } catch (e) {
    // Backend unreachable — FAIL. Do NOT set frontend mode.
    const msg = e instanceof Error ? e.message : String(e)
    return { success: false, message: `Backend unreachable: ${msg}` }
  }

  // Step 2: Backend confirmed EMPTY (response.ok + body.mode === 'EMPTY') — set frontend cache
  if (getMode() === 'DEMO') auditLog('DEMO_DATA_CLEARED', 'Dashboard reset to empty state')
  setMode('EMPTY')
  return { success: true, message: 'Demo data cleared. Dashboard is now empty.' }
}

// ---- Pi connectivity ----
// IMPORTANT: The browser NEVER determines Pi connectivity itself.
// The backend (FastAPI) owns this. The browser only forwards the backend's
// `pi_status` field. Distinct states from the backend:
//   CONNECTED / OFFLINE / AUTH_FAILED / HOST_KEY_UNKNOWN / HOST_KEY_CHANGED /
//   TIMEOUT / SSH_NOT_INSTALLED / NOT_CONFIGURED / ERROR
// The browser does NOT infer Pi reachability from "FastAPI is alive" or
// "any honeypot is running" — it trusts the backend's explicit pi_status.
export async function checkPiConnectivity(): Promise<{
  pi_reachable: boolean
  pi_configured: boolean
  fastapi_reachable: boolean
  elasticsearch: string
  mode: Mode
  backend_status: string
  pi_status: string
  honeypots?: any[]
}> {
  if (getMode() === 'DEMO') {
    return {
      pi_reachable: false,
      pi_configured: false,
      fastapi_reachable: false,
      elasticsearch: 'demo',
      mode: getMode(),
      backend_status: 'demo',
      pi_status: 'demo',
    }
  }

  // Step 1: Check if FastAPI backend is alive
  let fastapi_reachable = false
  let elasticsearch = 'offline'
  let backend_health: any = null

  try {
    const resp = await fetch(`${FASTAPI_URL}/health`, { signal: AbortSignal.timeout(2000) })
    if (resp.ok) {
      fastapi_reachable = true
      backend_health = await resp.json()
      elasticsearch = backend_health.elasticsearch || 'unknown'
    }
  } catch {
    // FastAPI unreachable — Pi status is NOT_CONFIGURED (we can't ask the backend)
    return {
      pi_reachable: false,
      pi_configured: false,
      fastapi_reachable: false,
      elasticsearch: 'offline',
      mode: getMode(),
      backend_status: 'offline',
      pi_status: 'BACKEND_UNREACHABLE',
    }
  }

  // Step 2: Fetch honeypot fleet status — the backend's pi_status field is the
  // authoritative source. The browser does NOT infer pi_reachable from
  // honeypot states or env-var existence — only from the backend's explicit
  // pi_status: CONNECTED field.
  let pi_reachable = false
  let pi_configured = false
  let pi_status = 'unknown'
  let honeypots: any[] = []

  if (fastapi_reachable) {
    try {
      const hpResp = await fetch(`${FASTAPI_URL}/honeypots`, { signal: AbortSignal.timeout(3000) })
      if (hpResp.ok) {
        const hpData = await hpResp.json()
        // Trust the backend's pi_status enum directly — never infer.
        pi_status = hpData.pi_status || 'unknown'
        pi_reachable = hpData.pi_reachable === true
        pi_configured = hpData.pi_configured === true
        honeypots = hpData.honeypots || []
      } else {
        pi_status = 'BACKEND_ERROR'
      }
    } catch {
      pi_status = 'BACKEND_TIMEOUT'
    }
  }

  return {
    pi_reachable,
    pi_configured,
    fastapi_reachable,
    elasticsearch,
    mode: getMode(),
    backend_status: fastapi_reachable ? 'healthy' : 'offline',
    pi_status,
    honeypots,
  }
}

// ---- Data loaders ----
function loadDatasetRows(): any[] {
  if (!existsSync(DATASET_CSV)) return []
  return parse(readFileSync(DATASET_CSV, 'utf-8'), { columns: true, skip_empty_lines: true })
}

function listModelsFromDisk(): ModelMeta[] {
  const out: ModelMeta[] = []
  if (!existsSync(MODELS_DIR)) return out
  for (const entry of readdirSync(MODELS_DIR)) {
    if (entry === 'README.md') continue
    const metaPath = join(MODELS_DIR, entry, 'metadata.json')
    if (!existsSync(metaPath)) continue
    try {
      const meta = JSON.parse(readFileSync(metaPath, 'utf-8')) as ModelMeta
      // Defensively tag models under legacy-demo/ paths so the dashboard
      // cannot accidentally present them as active research evidence.
      // This is a fallback in case the metadata.json file itself lacks a
      // `provenance` field.
      if (entry === 'legacy-demo' || entry.startsWith('legacy-demo-')) {
        if (!meta.provenance) meta.provenance = 'legacy-demo'
      }
      out.push(meta)
    } catch {}
  }
  return out.sort((a, b) => (b.created_at_iso || '').localeCompare(a.created_at_iso || ''))
}

function toSessionRow(r: any): SessionRow {
  const features: Record<string, number> = {}
  for (const fn of FEATURE_NAMES) features[fn] = Number(r[fn] || 0)
  return {
    session_id: r.session_id, label: r.label, label_source: r.label_source || 'SYNTHETIC',
    campaign_id: r.campaign_id || '', scenario_id: r.scenario_id || '',
    dataset_version: r.dataset_version || 'v1', created_at: r.created_at || '', features,
  }
}

// ---- Public API ----

// LIVE mode helper — proxies to FastAPI. NEVER falls back to DEMO.
async function fetchLive<T>(path: string, init?: RequestInit): Promise<{ data?: T; error?: string }> {
  try {
    const resp = await fetch(`${FASTAPI_URL}${path}`, {
      ...init,
      signal: AbortSignal.timeout(5000),
    })
    if (!resp.ok) return { error: `FastAPI returned ${resp.status}` }
    return { data: await resp.json() as T }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return { error: `FastAPI unreachable: ${msg}` }
  }
}

export function getHealth() {
  const mode = getMode()
  return {
    status: mode === 'EMPTY' ? 'waiting' : 'ok',
    mode,
    pi_reachable: false,
    elasticsearch: mode === 'LIVE' ? 'connected' : mode === 'DEMO' ? 'demo' : 'offline',
    sessions_loaded: mode === 'DEMO' ? loadDatasetRows().length : 0,
    models_loaded: mode === 'DEMO' ? listModelsFromDisk().length : 0,
  }
}

export async function getStatsLive() {
  const mode = getMode()
  if (mode !== 'LIVE') return getStatsSync()
  const { data, error } = await fetchLive<any>('/stats')
  if (error) return { status: 'error', mode, error, note: 'LIVE backend unavailable — NO FALLBACK TO DEMO' }
  return { status: 'ok', mode, ...data }
}

export function getStatsSync() {
  const mode = getMode()
  if (mode === 'EMPTY') {
    return { status: 'empty', mode, total_events: 0, total_sessions: 0, total_detections: 0, unique_attackers: 0, anomalies: 0, known_attacks: 0, model_version: null, note: 'NO TELEMETRY RECEIVED' }
  }
  if (mode === 'DEMO') {
    const rows = loadDatasetRows()
    if (rows.length === 0) return { status: 'INSUFFICIENT DATA', mode }
    const labelDist: Record<string, number> = {}
    for (const r of rows) labelDist[r.label] = (labelDist[r.label] || 0) + 1
    const models = listModelsFromDisk()
    const activeModel = models.find(m => m.status === 'active') || models[0]
    return {
      status: 'ok', mode, data_source: 'demo_dataset_v1',
      total_sessions: rows.length, label_distribution: labelDist,
      features_per_session: FEATURE_NAMES.length,
      model_version: activeModel?.model_id || null,
      model_status: activeModel?.status || null,
      note: 'DEMO DATA — loaded from synthetic dataset v1 by explicit user action',
    }
  }
  return { status: 'live_pending', mode, note: 'LIVE mode — use getStatsLive() for real data' }
}

export async function getSessionsLive(opts: { size?: number; label?: string } = {}) {
  const mode = getMode()
  if (mode !== 'LIVE') return getSessionsSync(opts)
  const params = new URLSearchParams()
  if (opts.size) params.set('size', String(opts.size))
  if (opts.label) params.set('label', opts.label)
  const { data, error } = await fetchLive<any>(`/sessions?${params}`)
  if (error) return { mode, total: 0, sessions: [], error, note: 'LIVE backend unavailable — NO FALLBACK TO DEMO' }
  return { mode, ...data }
}

export function getSessionsSync(opts: { size?: number; label?: string } = {}) {
  const mode = getMode()
  if (mode !== 'DEMO') return { mode, total: 0, sessions: [] }
  const rows = loadDatasetRows()
  let out = rows
  if (opts.label) out = out.filter((r: any) => r.label === opts.label)
  const size = Math.min(opts.size ?? 50, 500)
  return { mode, data_source: 'demo_dataset_v1', total: out.length, sessions: out.slice(0, size).map(toSessionRow) }
}

export function getSessionDetail(sessionId: string): SessionRow | null {
  if (getMode() !== 'DEMO') return null
  const rows = loadDatasetRows()
  const row = rows.find((r: any) => r.session_id === sessionId)
  return row ? toSessionRow(row) : null
}

// ---- Live events (from FastAPI / Elasticsearch) ----
// LIVE mode: proxies to FastAPI /events which queries Elasticsearch.
// EMPTY/DEMO: returns empty events array (demo dataset has sessions, not events).
// NEVER falls back to demo data — if ES is down, returns error honestly.
export interface HoneypotEvent {
  event_id: string
  session_id: string
  '@timestamp': string
  ingested_at?: string
  timestamp_source?: string
  source: { ip: string; port: number }
  destination?: { ip: string; port: number }
  device: { id: string; type: string; hostname?: string; container?: string }
  protocol: string
  event: { type: string; category?: string; action?: string; note?: string }
  honeypot: { name: string; container?: string }
  authentication?: { attempted: boolean; username?: string; success?: boolean }
  http?: {
    method?: string; uri?: string; status?: number;
    user_agent?: string; bytes_in?: number; bytes_out?: number;
  }
  attack?: {
    session_id?: string; stage?: string;
    classification?: string | null; confidence?: number;
  }
}

export async function getEventsLive(opts: { size?: number; source_ip?: string; device?: string } = {}): Promise<{
  mode: Mode
  events: HoneypotEvent[]
  total: number
  error?: string
}> {
  const mode = getMode()
  if (mode !== 'LIVE') {
    return { mode, events: [], total: 0 }
  }
  const params = new URLSearchParams()
  if (opts.size) params.set('size', String(Math.min(opts.size, 500)))
  if (opts.source_ip) params.set('source_ip', opts.source_ip)
  if (opts.device) params.set('device', opts.device)
  const { data, error } = await fetchLive<any>(`/events?${params}`)
  if (error) {
    return { mode, events: [], total: 0, error, }
  }
  // FastAPI returns {events: [...], total: N} (normalized by es_client)
  const events: HoneypotEvent[] = Array.isArray(data?.events) ? data.events : []
  return {
    mode,
    events,
    total: data?.total ?? events.length,
  }
}

export function getModels(): { models: ModelMeta[] } {
  if (getMode() === 'EMPTY') return { models: [] }
  return { models: listModelsFromDisk() }
}

export function getModel(modelId: string): ModelMeta | null {
  if (getMode() === 'EMPTY') return null
  return listModelsFromDisk().find(m => m.model_id === modelId) || null
}

export function getExperiments(): { experiments: any[] } {
  if (getMode() === 'EMPTY') return { experiments: [] }
  const out: any[] = []
  if (!existsSync(EXPERIMENTS_DIR)) return { experiments: out }
  for (const entry of readdirSync(EXPERIMENTS_DIR)) {
    if (!entry.endsWith('.json')) continue
    try { out.push(JSON.parse(readFileSync(join(EXPERIMENTS_DIR, entry), 'utf-8'))) } catch {}
  }
  return { experiments: out.sort((a, b) => (b.experiment_id || '').localeCompare(a.experiment_id || '')) }
}

export function getFeatures() {
  const leaky = ['contains_path_traversal', 'contains_command_injection', 'contains_default_credentials']
  return { version: 'v1', count: FEATURE_NAMES.length, features: FEATURE_NAMES.map(name => ({ name, leaky: leaky.includes(name), description: '' })) }
}

export function getAttackTypes() {
  return {
    classifications: ['brute_force', 'default_credentials', 'reconnaissance', 'command_injection', 'path_traversal', 'anomaly', 'benign'],
    mitre_mapping: {
      brute_force: { tactic: 'Credential Access', technique: 'T1110' },
      default_credentials: { tactic: 'Credential Access', technique: 'T1078' },
      reconnaissance: { tactic: 'Discovery', technique: 'T1046' },
      command_injection: { tactic: 'Execution', technique: 'T1059' },
      path_traversal: { tactic: 'Collection', technique: 'T1005' },
    },
  }
}

// ---- Honeypot fleet contract ----
// Canonical honeypot object schema used across ALL modes (EMPTY/DEMO/LIVE).
// The backend pi_client.get_honeypot_fleet() returns this shape; the
// frontend adapter normalizes fallback responses to the SAME shape so the
// UI never has to handle two different schemas.
//
//   {
//     id: string, name: string, type: string,
//     container: string, port: number,
//     configured: boolean, container_exists: boolean,
//     state: 'running' | 'stopped' | 'exited' | 'missing' |
//            'offline' | 'not_configured' | 'unknown',
//     docker_status: string,
//   }
//
// `state` is the canonical field (matches backend pi_client.ContainerState).
// `status` is NOT used — it was a source of bugs because the fallback path
// used `status` while the backend used `state`.
//
// pi_status enum (UPPERCASE — authoritative from backend):
//   CONNECTED | OFFLINE | AUTH_FAILED | HOST_KEY_UNKNOWN |
//   HOST_KEY_CHANGED | TIMEOUT | SSH_NOT_INSTALLED |
//   NOT_CONFIGURED | ERROR | BACKEND_UNREACHABLE | UNCHECKED
//
// NEVER collapse these into 'CONNECTED / OFFLINE'. NOT_CONFIGURED is
// distinct from OFFLINE: NOT_CONFIGURED means no Pi config was provided;
// OFFLINE means the Pi was configured but the connection failed.

const HONEYPOT_DEFS: Array<{ id: string; name: string; type: string; container: string; port: number }> = [
  { id: 'cowrie-01', name: 'Cowrie SSH/Telnet', type: 'ssh', container: 'pi-cowrie', port: 2222 },
  { id: 'camera-01', name: 'Camera HTTP', type: 'http', container: 'pi-camera', port: 8080 },
  { id: 'iot-01', name: 'IoT TCP Service', type: 'iot_service', container: 'pi-iot-service', port: 9000 },
]

/**
 * Build a fallback honeypot array for a given pi_status.
 * Used when the backend is unreachable, not configured, or in DEMO/EMPTY mode.
 * The `state` field reflects what we actually know — NEVER fake 'running'.
 */
function fallbackHoneypots(
  pi_status: string,
  mode: Mode,
): Array<{
  id: string; name: string; type: string; container: string; port: number;
  configured: boolean; container_exists: boolean; state: string; docker_status: string;
}> {
  // Determine the per-honeypot state from the authoritative pi_status.
  // If we can't reach the backend, we can't know the container state → unknown.
  // If the Pi is not configured, every honeypot inherits not_configured.
  // If the Pi is configured but unreachable, every honeypot inherits offline.
  let state: string
  if (mode === 'DEMO') {
    state = 'demo'
  } else if (pi_status === 'NOT_CONFIGURED' || pi_status === 'UNCHECKED') {
    state = 'not_configured'
  } else if (pi_status === 'CONNECTED') {
    // Backend said CONNECTED but we have no fleet data — shouldn't happen,
    // but if it does, we don't know container states.
    state = 'unknown'
  } else if (pi_status === 'BACKEND_UNREACHABLE' || pi_status === 'BACKEND_ERROR' || pi_status === 'BACKEND_TIMEOUT') {
    // Backend is down — we cannot probe the Pi at all.
    state = 'unknown'
  } else {
    // OFFLINE, AUTH_FAILED, HOST_KEY_*, TIMEOUT, SSH_NOT_INSTALLED, ERROR
    // Pi was configured but unreachable → honeypots are offline (not not_configured).
    state = 'offline'
  }
  return HONEYPOT_DEFS.map(hp => ({
    ...hp,
    configured: true,
    container_exists: false,
    state,
    docker_status: `pi_status=${pi_status}`,
  }))
}

export async function getHoneypots() {
  const mode = getMode()

  // EMPTY mode — no probe has happened. Report UNCHECKED, NOT 'OFFLINE'.
  // 'OFFLINE' would imply we tried and failed; we didn't try at all.
  if (mode === 'EMPTY') {
    return {
      mode,
      pi_status: 'UNCHECKED',
      pi_reachable: false,
      pi_configured: false,
      honeypots: fallbackHoneypots('UNCHECKED', mode),
    }
  }

  // DEMO mode — no Pi interaction. Mark explicitly as DEMO.
  if (mode === 'DEMO') {
    return {
      mode,
      pi_status: 'DEMO',
      pi_reachable: false,
      pi_configured: false,
      honeypots: fallbackHoneypots('DEMO', mode),
    }
  }

  // LIVE mode — proxy to FastAPI /honeypots which SSH-probes the Pi.
  // The backend's pi_status enum is authoritative. We NEVER collapse it.
  const { data, error } = await fetchLive<any>('/honeypots')
  if (error) {
    // FastAPI unreachable — report BACKEND_UNREACHABLE, NOT 'offline'.
    // 'offline' would imply the Pi is offline; we don't know that —
    // the backend itself is down.
    const pi_status = 'BACKEND_UNREACHABLE'
    return {
      mode,
      pi_status,
      pi_reachable: false,
      pi_configured: false,
      error,
      honeypots: fallbackHoneypots(pi_status, mode),
    }
  }
  // Backend responded — normalize its honeypots to our canonical schema.
  // The backend already returns `state` (not `status`), so we pass through
  // but guarantee the array is always present + each honeypot has `state`.
  const backendHoneypots: any[] = Array.isArray(data?.honeypots) ? data.honeypots : []
  const normalizedHoneypots = backendHoneypots.map((h: any) => ({
    id: h.id ?? '',
    name: h.name ?? h.id ?? '',
    type: h.type ?? '',
    container: h.container ?? '',
    port: Number(h.port ?? 0),
    configured: h.configured ?? true,
    container_exists: h.container_exists ?? false,
    // Canonical field is `state`. Accept `status` as a legacy alias
    // but normalize to `state` so the UI has one field to read.
    state: h.state ?? h.status ?? 'unknown',
    docker_status: h.docker_status ?? '',
  }))
  return {
    mode,
    pi_status: data?.pi_status ?? 'unknown',
    pi_reachable: data?.pi_reachable === true,
    pi_configured: data?.pi_configured === true,
    honeypots: normalizedHoneypots.length > 0 ? normalizedHoneypots : fallbackHoneypots(data?.pi_status ?? 'unknown', mode),
  }
}

// ---- Honeypot management (proxies to FastAPI) ----
// The backend owns the Pi control plane. The browser only forwards the
// request and reports the backend's structured result. We DO NOT mark
// an action as successful based on HTTP 200 alone — we check the
// `success` field in the response body, because the backend may return
// 503 (Pi not configured / unreachable) or 500 (action ran but state
// verification failed) and we need to surface those honestly.
//
// AUTH BOUNDARY (fixed in Pass 4):
// The browser NEVER receives or sends API_SECRET_KEY. The Next.js
// server-side code reads it from process.env (server-only) and forwards
// it to FastAPI as the X-API-Key header. This keeps the secret server-side
// while satisfying FastAPI's require_api_key dependency.
//
// We use a single canonical server-side secret name: TRAPSIG_BACKEND_API_KEY.
// It is read by BOTH the Next.js server (to send) and the FastAPI backend
// (to verify, via its own env). We do NOT read process.env.NEXT_PUBLIC_*
// for the secret — that would leak it to the browser bundle.

/** Read the server-side backend API key. Server-only — never exposed to browser. */
function getBackendApiKey(): string {
  // Server-side only. process.env is NOT accessible from the browser in
  // Next.js Server Components / API routes (only NEXT_PUBLIC_* is inlined
  // into the browser bundle). This is safe.
  return process.env.TRAPSIG_BACKEND_API_KEY || process.env.API_SECRET_KEY || ''
}

async function honeypotAction(id: string, action: 'start' | 'stop' | 'restart'): Promise<{ success: boolean; message: string; verified_state?: string }> {
  // Validate inputs on the Next.js side too — defense in depth.
  // The backend also validates, but this prevents sending malformed requests.
  const VALID_IDS = new Set(['cowrie-01', 'camera-01', 'iot-01'])
  const VALID_ACTIONS = new Set(['start', 'stop', 'restart'])
  if (!VALID_IDS.has(id)) {
    return { success: false, message: `unknown honeypot: ${id}` }
  }
  if (!VALID_ACTIONS.has(action)) {
    return { success: false, message: `invalid action: ${action}` }
  }

  const apiKey = getBackendApiKey()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (apiKey) {
    headers['X-API-Key'] = apiKey
  }
  // If no API key is configured server-side, we still send the request —
  // FastAPI will reject with 401, and we surface that honestly. We do NOT
  // weaken FastAPI auth by removing require_api_key.

  try {
    const resp = await fetch(`${FASTAPI_URL}/honeypots/${id}/${action}`, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(20000),
    })
    // 200 with success=true is the only valid success path.
    if (resp.ok) {
      const data = await resp.json().catch(() => null)
      if (data && data.success === true) {
        auditLog(`HONEYPOT_${action.toUpperCase()}`, `${id}: verified=${data.verified_state || 'unknown'}`)
        return { success: true, message: data.message || `${id} ${action} succeeded`, verified_state: data.verified_state }
      }
      // 200 but no success=true — backend should not do this, but handle defensively
      return { success: false, message: data?.message || `${id} ${action}: backend returned 200 without success flag` }
    }
    // Non-200 — map known codes to honest messages.
    // NEVER include the API key value in any user-facing message.
    if (resp.status === 401 || resp.status === 403) {
      // This means the server-side API key is wrong or missing.
      // Surface a server-config diagnostic — NOT the key itself.
      return {
        success: false,
        message: `auth failed: backend rejected server-side API key (HTTP ${resp.status}). Check TRAPSIG_BACKEND_API_KEY on the Next.js server matches API_SECRET_KEY on FastAPI.`,
      }
    }
    if (resp.status === 404) {
      return { success: false, message: `unknown honeypot: ${id}` }
    }
    if (resp.status === 503) {
      // Pi not configured / unreachable — read detail from body if available
      const body = await resp.json().catch(() => null)
      const detail = body?.detail || 'Pi unavailable'
      return { success: false, message: `${id} ${action} blocked — ${detail}` }
    }
    if (resp.status === 500) {
      const body = await resp.json().catch(() => null)
      return { success: false, message: `${id} ${action} failed verification — ${body?.detail || 'state not verified'}` }
    }
    return { success: false, message: `FastAPI returned ${resp.status}` }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return { success: false, message: `FastAPI unreachable: ${msg}` }
  }
}

export async function startHoneypot(id: string): Promise<{ success: boolean; message: string }> {
  return honeypotAction(id, 'start')
}

export async function stopHoneypot(id: string): Promise<{ success: boolean; message: string }> {
  return honeypotAction(id, 'stop')
}

export async function restartHoneypot(id: string): Promise<{ success: boolean; message: string }> {
  return honeypotAction(id, 'restart')
}

// ---- System status ----
// Truthful component status. We only report a component as CONNECTED if we
// have actually verified it; otherwise we report UNKNOWN or OFFLINE.
// We never infer Logstash health from ES health, and we never infer Pi
// component health from FastAPI being alive — each component must be
// independently verifiable or marked UNKNOWN.
export async function getSystemStatus() {
  const conn = await checkPiConnectivity()
  const mode = getMode()
  const modelsCount = listModelsFromDisk().length

  // Honeypot component states — if backend returned honeypot fleet, use
  // the actual per-container state. Otherwise UNKNOWN.
  const honeypots = conn.honeypots || []
  const findHp = (id: string) => honeypots.find((h: any) => h.id === id)
  const hpState = (id: string) => {
    const hp = findHp(id)
    if (!hp) return 'unknown'
    return hp.state || 'unknown'
  }
  // Map backend container state to dashboard component status:
  //   running → connected ; stopped/exited → offline ; missing → not_configured ;
  //   offline (Pi offline) → offline ; not_configured (Pi not configured) → not_configured ;
  //   unknown → unknown
  const mapHpStatus = (state: string): string => {
    if (state === 'running') return 'connected'
    if (state === 'stopped' || state === 'exited') return 'offline'
    if (state === 'missing') return 'not_configured'
    if (state === 'offline') return 'offline'
    if (state === 'not_configured') return 'not_configured'
    return 'unknown'
  }

  // Filebeat / Logstash: we CANNOT verify these from the browser without
  // additional backend endpoints. The previous version inferred Logstash
  // from ES health, which was a lie. Now: UNKNOWN unless explicitly verified.
  // If the user wants real Filebeat/Logstash status, the FastAPI backend must
  // expose dedicated endpoints (e.g. /health/filebeat, /health/logstash).
  const filebeatStatus: string = mode === 'DEMO' ? 'demo'
    : conn.pi_configured ? (conn.pi_reachable ? 'unknown' : 'offline')
    : 'not_configured'
  const logstashStatus: string = mode === 'DEMO' ? 'demo'
    : conn.fastapi_reachable ? 'unknown'  // we don't have an endpoint to verify Logstash
    : 'offline'
  const esStatus: string = mode === 'DEMO' ? 'demo'
    : conn.elasticsearch === 'ok' ? 'connected'
    : conn.elasticsearch === 'offline' ? 'offline'
    : 'unknown'

  return {
    mode,
    pi_reachable: conn.pi_reachable,
    pi_configured: conn.pi_configured,
    pi_status: conn.pi_status,  // backend's authoritative enum — preserved verbatim
    fastapi_reachable: conn.fastapi_reachable,
    elasticsearch: conn.elasticsearch,
    components: [
      // Pi component — render the authoritative pi_status directly.
      // Do NOT collapse to 'connected'/'offline'. The distinct states
      // (NOT_CONFIGURED, AUTH_FAILED, HOST_KEY_UNKNOWN, HOST_KEY_CHANGED,
      //  TIMEOUT, etc.) carry operational meaning and must remain visible.
      {
        name: 'Pi',
        status: conn.pi_status,  // e.g. 'NOT_CONFIGURED', 'AUTH_FAILED', 'CONNECTED'
        detail: `pi_status=${conn.pi_status}${conn.pi_configured ? ' (configured)' : ' (not configured)'}`,
      },
      { name: 'Cowrie SSH', status: mapHpStatus(hpState('cowrie-01')), detail: 'port 2222 — backend-reported container state' },
      { name: 'Camera HTTP', status: mapHpStatus(hpState('camera-01')), detail: 'port 8080 — backend-reported container state' },
      { name: 'IoT TCP', status: mapHpStatus(hpState('iot-01')), detail: 'port 9000 — backend-reported container state' },
      { name: 'Filebeat', status: filebeatStatus, detail: 'requires Pi probe — not directly verifiable from browser' },
      { name: 'Logstash', status: logstashStatus, detail: 'no backend verification endpoint — UNKNOWN, not inferred from ES' },
      { name: 'Elasticsearch', status: esStatus, detail: conn.elasticsearch === 'ok' ? 'cluster healthy' : 'requires Docker / FastAPI' },
      { name: 'FastAPI', status: conn.fastapi_reachable ? 'connected' : 'offline', detail: conn.fastapi_reachable ? 'serving' : 'not running' },
      { name: 'ML Engine', status: mode !== 'EMPTY' && modelsCount > 0 ? 'ready' : 'no_model', detail: mode !== 'EMPTY' ? `${modelsCount} model(s) on disk` : 'not trained' },
    ],
  }
}

// ---- Explicit LIVE mode entry ----
// LIVE mode is NEVER auto-entered. The backend owns the authoritative mode.
// This function:
// 1. Syncs from backend (GET /mode) — does NOT trust stale frontend cache
// 2. If backend says DEMO → reject (must clear to EMPTY first)
// 3. If backend says LIVE → idempotent success
// 4. If backend says EMPTY → POST /mode/live
// 5. Only if backend confirms LIVE → set frontend cache to LIVE
// If backend is unreachable → FAIL. Do NOT enter LIVE locally.
export async function enterLiveMode(): Promise<{ success: boolean; message: string }> {
  // Step 1: Sync from backend — don't trust stale frontend cache
  const sync = await syncModeFromBackend()
  if (!sync.ok) {
    return { success: false, message: `Backend unreachable — cannot enter LIVE: ${sync.error}` }
  }

  // Step 2: Check backend-authoritative mode
  if (sync.mode === 'DEMO') {
    return { success: false, message: 'Cannot enter LIVE while DEMO is active — clear demo data first' }
  }
  if (sync.mode === 'LIVE') {
    return { success: true, message: 'Already in LIVE mode' }
  }

  // Step 3: backend is EMPTY — ask backend to transition to LIVE
  const apiKey = getBackendApiKey()
  const headers: Record<string, string> = {}
  if (apiKey) headers['X-API-Key'] = apiKey
  try {
    const resp = await fetch(`${FASTAPI_URL}/mode/live`, {
      method: 'POST', headers, signal: AbortSignal.timeout(5000),
    })
    if (resp.ok) {
      setMode('LIVE')
      auditLog('LIVE_MODE_ENTERED', 'explicit user action — backend confirmed')
      return { success: true, message: 'LIVE mode entered — backend telemetry will be polled' }
    }
    if (resp.status === 401 || resp.status === 403) {
      return { success: false, message: 'Backend rejected: auth failed (check TRAPSIG_BACKEND_API_KEY)' }
    }
    if (resp.status === 409) {
      const body = await resp.json().catch(() => null)
      return { success: false, message: body?.detail || 'Backend rejected mode transition' }
    }
    return { success: false, message: `Backend returned ${resp.status}` }
  } catch (e) {
    // Backend unreachable — FAIL. Do NOT set frontend mode.
    const msg = e instanceof Error ? e.message : String(e)
    return { success: false, message: `Backend unreachable: ${msg}` }
  }
}

// Sync frontend mode with backend mode.
// Returns an explicit result so callers can distinguish:
//   - successful sync (ok=true, mode from backend)
//   - backend unavailable (ok=false, mode=cached, error='BACKEND_UNREACHABLE')
// Callers MUST NOT treat the cached mode as authoritative when ok=false.
export interface ModeSyncResult {
  ok: boolean
  mode: Mode
  error?: string
}

export async function syncModeFromBackend(): Promise<ModeSyncResult> {
  try {
    const resp = await fetch(`${FASTAPI_URL}/mode`, { signal: AbortSignal.timeout(2000) })
    if (resp.ok) {
      const data = await resp.json()
      const backendMode = data.mode as Mode
      if (backendMode === 'LIVE' || backendMode === 'DEMO' || backendMode === 'EMPTY') {
        setMode(backendMode)
        return { ok: true, mode: backendMode }
      }
      return { ok: false, mode: getMode(), error: `backend returned unknown mode: ${backendMode}` }
    }
    return { ok: false, mode: getMode(), error: `backend returned ${resp.status}` }
  } catch (e) {
    // Backend unreachable — return cached mode but mark as NOT authoritative.
    // Callers must NOT use this mode to make decisions.
    const msg = e instanceof Error ? e.message : String(e)
    return { ok: false, mode: getMode(), error: `BACKEND_UNREACHABLE: ${msg}` }
  }
}

export function getDatasets() {
  if (getMode() === 'EMPTY') return { datasets: [] }
  const rows = loadDatasetRows()
  if (rows.length === 0) return { datasets: [] }
  const labelDist: Record<string, number> = {}
  for (const r of rows) labelDist[r.label] = (labelDist[r.label] || 0) + 1
  return { datasets: [{ version: 'v1', rows: rows.length, label_source: 'SYNTHETIC', label_distribution: labelDist }] }
}

export function getScenarios(): { scenarios: Scenario[] } {
  const out: Scenario[] = []
  if (!existsSync(SCENARIOS_DIR)) return { scenarios: out }
  for (const entry of readdirSync(SCENARIOS_DIR)) {
    if (!entry.endsWith('.yaml')) continue
    try {
      const text = readFileSync(join(SCENARIOS_DIR, entry), 'utf-8')
      const m: any = {}
      const lines = text.split('\n')
      let cur: string | null = null
      for (const line of lines) {
        if (/^\s*-\s/.test(line) && cur) { (m[cur] as any[]).push(line.replace(/^\s*-\s/, '').trim()) }
        else if (/^[\w_]+:/.test(line)) {
          const [k, ...rest] = line.split(':')
          const v = rest.join(':').trim()
          if (v === '') { m[k.trim()] = []; cur = k.trim() }
          else { m[k.trim()] = v.replace(/^["']|["']$/g, ''); cur = null }
        }
      }
      out.push(m as Scenario)
    } catch {}
  }
  return { scenarios: out }
}
