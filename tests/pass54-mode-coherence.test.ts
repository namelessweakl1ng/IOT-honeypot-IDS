/**
 * Pass 5.4: Frontend/backend mode coherence regression tests.
 *
 * Tests that the TypeScript transition functions (loadDemoData, clearDemoData,
 * enterLiveMode, syncModeFromBackend) obey the backend-authoritative contract:
 * - Backend unreachable → FAIL (no offline demo, no stale LIVE)
 * - Backend rejects → FAIL (frontend mode unchanged)
 * - Backend confirms → frontend cache updated
 * - syncModeFromBackend returns explicit ok/error
 *
 * Uses Bun's built-in test runner. Mocks fetch to simulate backend responses.
 * No live FastAPI required.
 */
import { describe, test, expect, mock, beforeEach, afterEach } from 'bun:test'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'

// ---- Test helpers ----

let capturedRequests: Array<{url: string, method: string, headers: Record<string, string>}> = []
let mockResponses: Record<string, {status: number, body: any}> = {}

function mockFetch(url: string | URL | Request, init?: RequestInit): Promise<Response> {
  const urlStr = typeof url === 'string' ? url : url.toString()
  const headers: Record<string, string> = {}
  if (init?.headers) {
    const h = init.headers
    if (h instanceof Headers) {
      h.forEach((v: string, k: string) => { headers[k] = v })
    } else if (Array.isArray(h)) {
      for (const [k, v] of h) headers[k] = v
    } else {
      Object.assign(headers, h as Record<string, string>)
    }
  }
  capturedRequests.push({ url: urlStr, method: init?.method || 'GET', headers })

  // Find matching mock response
  for (const [pattern, resp] of Object.entries(mockResponses)) {
    if (urlStr.includes(pattern)) {
      const r = {
        ok: resp.status >= 200 && resp.status < 300,
        status: resp.status,
        json: async () => resp.body,
        text: async () => JSON.stringify(resp.body),
      }
      return Promise.resolve(r as Response)
    }
  }
  // Default: simulate backend unreachable
  return Promise.reject(new TypeError('fetch failed — backend unreachable'))
}

const originalFetch = globalThis.fetch

function setMockResponse(pattern: string, status: number, body: any) {
  mockResponses[pattern] = { status, body }
}

function clearMockResponses() {
  mockResponses = {}
}

function resetEnv() {
  delete process.env.TRAPSIG_BACKEND_API_KEY
  delete process.env.API_SECRET_KEY
}

// ---- Tests ----

describe('Frontend/backend mode coherence (Pass 5.4)', () => {
  beforeEach(() => {
    capturedRequests = []
    mockResponses = {}
    globalThis.fetch = mockFetch as any
    resetEnv()
    // Reset frontend mode to EMPTY
    const g = globalThis as any
    if (g.__trapsig_state) g.__trapsig_state.mode = 'EMPTY'
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    clearMockResponses()
    resetEnv()
  })

  // ---- 20: loadDemoData() with backend unreachable MUST fail ----

  test('20. loadDemoData with backend unreachable MUST fail', async () => {
    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    expect(result.success).toBe(false)
    expect(result.message).toContain('Backend unreachable')
  })

  // ---- 21: loadDemoData() with backend unreachable MUST NOT set DEMO ----

  test('21. loadDemoData with backend unreachable MUST NOT set DEMO', async () => {
    const mod = await import('../src/lib/ids-data')
    await mod.loadDemoData()
    // Frontend mode must still be EMPTY (or whatever it was before — NOT DEMO)
    const health = mod.getHealth()
    expect(health.mode).not.toBe('DEMO')
  })

  // ---- 22: loadDemoData() with backend 401 MUST fail and not set DEMO ----

  test('22. loadDemoData with backend 401 MUST fail and not set DEMO', async () => {
    // GET /mode returns 401 → syncModeFromBackend fails → loadDemoData fails
    mockResponses['/mode'] = { status: 401, body: { detail: 'unauthorized' } }
    // Even if POST /mode/demo would succeed, syncModeFromBackend fails first
    mockResponses['/mode/demo'] = { status: 200, body: { mode: 'DEMO' } }

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    expect(result.success).toBe(false)
    const health = mod.getHealth()
    expect(health.mode).not.toBe('DEMO')
  })

  // ---- 23: loadDemoData() with backend 409 MUST fail and not set DEMO ----

  test('23. loadDemoData with backend 409 MUST fail and not set DEMO', async () => {
    // GET /mode returns EMPTY → sync succeeds
    // POST /mode/demo returns 409 (forbidden transition)
    // We need to match GET /mode but not POST /mode/demo
    // Use exact path matching
    mockResponses['/mode/live'] = { status: 409, body: { detail: 'forbidden' } }
    mockResponses['/mode/demo'] = { status: 409, body: { detail: 'Cannot enter DEMO while LIVE' } }
    mockResponses['/mode/reset'] = { status: 200, body: { mode: 'EMPTY' } }
    // Override the general /mode pattern for GET requests only
    const origMockFetch = globalThis.fetch
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      // GET /mode → 200 EMPTY
      if (method === 'GET' && urlStr.includes('/mode')) {
        return Promise.resolve({
          ok: true, status: 200,
          json: async () => ({ mode: 'EMPTY' }),
          text: async () => '{"mode":"EMPTY"}',
        } as Response)
      }
      // POST /mode/demo → 409
      if (method === 'POST' && urlStr.includes('/mode/demo')) {
        return Promise.resolve({
          ok: false, status: 409,
          json: async () => ({ detail: 'Cannot enter DEMO while LIVE' }),
          text: async () => '{"detail":"Cannot enter DEMO while LIVE"}',
        } as Response)
      }
      // Other requests → use default mock
      return mockFetch(url, init)
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origMockFetch

    expect(result.success).toBe(false)
    expect(result.message).toContain('Cannot enter DEMO')
    const health = mod.getHealth()
    expect(health.mode).not.toBe('DEMO')
  })

  // ---- 24: loadDemoData() only sets DEMO after backend confirmation ----
  // Deterministic: uses a path where the CSV DOES exist (the real repo path)
  // so the test proves that when backend accepts DEMO + local data exists → success

  test('24. loadDemoData only sets DEMO after backend confirms', async () => {
    // Derive the repo root from this test file's location (portable, no hardcoded path).
    // This test file is at: <repo_root>/tests/pass54-mode-coherence.test.ts
    // The CSV is at: <iot_honeypot_ids_root>/model-lab/datasets/v1/sessions.csv
    // So we need IOT_HONEYPOT_IDS_ROOT to point to the iot-honeypot-ids directory.
    const __filename_test = fileURLToPath(import.meta.url)
    // Walk up from tests/ to find iot-honeypot-ids
    const repoRoot = resolve(dirname(__filename_test), '..', 'iot-honeypot-ids')
    process.env.IOT_HONEYPOT_IDS_ROOT = repoRoot
    // Clear module cache so it picks up the new env var
    delete require.cache[require.resolve('../src/lib/ids-data')]

    // Use method-specific mock for GET /mode vs POST /mode/demo
    const origFetch = globalThis.fetch
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'GET' && urlStr.includes('/mode')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'EMPTY' }), text: async () => '{"mode":"EMPTY"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/demo')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      return Promise.reject(new TypeError('unexpected fetch'))
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    // With the real CSV path, backend accepts DEMO + local data exists → success
    expect(result.success).toBe(true)
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')

    // Clean up
    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })

  // ---- 25: demo dataset missing after backend DEMO causes rollback to EMPTY ----
  // Deterministic: uses a non-existent path so CSV is guaranteed missing

  test('25. demo dataset missing after backend DEMO causes rollback', async () => {
    // Point to a non-existent path so the CSV is guaranteed missing
    process.env.IOT_HONEYPOT_IDS_ROOT = '/nonexistent/path/for/test'
    delete require.cache[require.resolve('../src/lib/ids-data')]

    // Clear captured requests for this test
    capturedRequests = []

    const origFetch = globalThis.fetch
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      const headers: Record<string, string> = {}
      if (init?.headers) {
        const h = init.headers
        if (h instanceof Headers) { h.forEach((v: string, k: string) => { headers[k] = v }) }
        else if (Array.isArray(h)) { for (const [k, v] of h) headers[k] = v }
        else { Object.assign(headers, h as Record<string, string>) }
      }
      capturedRequests.push({ url: urlStr, method, headers })

      if (method === 'GET' && urlStr.includes('/mode')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'EMPTY' }), text: async () => '{"mode":"EMPTY"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/demo')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'EMPTY' }), text: async () => '{"mode":"EMPTY"}' } as Response)
      }
      return Promise.reject(new TypeError('unexpected fetch'))
    }) as any
    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    // CSV missing → failure
    expect(result.success).toBe(false)
    expect(result.message).toContain('No synthetic dataset')

    // Verify rollback was attempted (POST /mode/reset was called)
    const resetCall = capturedRequests.find(r => r.url.includes('/mode/reset'))
    expect(resetCall).toBeDefined()

    // Clean up
    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })

  // ---- 26: clearDemoData() with backend unreachable MUST fail ----

  test('26. clearDemoData with backend unreachable MUST fail', async () => {
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    expect(result.success).toBe(false)
    expect(result.message).toContain('Backend unreachable')
  })

  // ---- 27: clearDemoData() with backend error MUST fail and not set EMPTY ----

  test('27. clearDemoData with backend error MUST fail and not set EMPTY', async () => {
    // Set frontend mode to DEMO first
    const g = globalThis as any
    if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'

    mockResponses['/mode/reset'] = { status: 500, body: { detail: 'internal error' } }

    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    expect(result.success).toBe(false)
    // Mode should NOT have changed (still DEMO, not EMPTY)
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')
  })

  // ---- 28: clearDemoData() sets EMPTY only after backend confirmation ----

  test('28. clearDemoData sets EMPTY only after backend confirms', async () => {
    const g = globalThis as any
    if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'

    mockResponses['/mode/reset'] = { status: 200, body: { mode: 'EMPTY' } }

    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    expect(result.success).toBe(true)
    const health = mod.getHealth()
    expect(health.mode).toBe('EMPTY')
  })

  // ---- 29: enterLiveMode() with backend unreachable MUST fail and not set LIVE ----

  test('29. enterLiveMode with backend unreachable MUST fail', async () => {
    const mod = await import('../src/lib/ids-data')
    const result = await mod.enterLiveMode()
    expect(result.success).toBe(false)
    expect(result.message).toContain('Backend unreachable')
    const health = mod.getHealth()
    expect(health.mode).not.toBe('LIVE')
  })

  // ---- 30: enterLiveMode() from backend DEMO MUST fail and preserve DEMO ----

  test('30. enterLiveMode from backend DEMO MUST fail', async () => {
    mockResponses['/mode'] = { status: 200, body: { mode: 'DEMO' } }

    const mod = await import('../src/lib/ids-data')
    const result = await mod.enterLiveMode()
    expect(result.success).toBe(false)
    expect(result.message).toContain('Cannot enter LIVE while DEMO')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')
  })

  // ---- 31: enterLiveMode() only sets LIVE after backend confirmation ----

  test('31. enterLiveMode only sets LIVE after backend confirms', async () => {
    mockResponses['/mode'] = { status: 200, body: { mode: 'EMPTY' } }
    mockResponses['/mode/live'] = { status: 200, body: { mode: 'LIVE' } }

    const mod = await import('../src/lib/ids-data')
    const result = await mod.enterLiveMode()
    expect(result.success).toBe(true)
    const health = mod.getHealth()
    expect(health.mode).toBe('LIVE')
  })

  // ---- 32: backend restart from LIVE -> EMPTY reflected in frontend after sync ----

  test('32. backend restart LIVE->EMPTY reflected after sync', async () => {
    // First sync: backend says LIVE
    mockResponses['/mode'] = { status: 200, body: { mode: 'LIVE' } }
    const mod = await import('../src/lib/ids-data')
    let sync = await mod.syncModeFromBackend()
    expect(sync.ok).toBe(true)
    expect(sync.mode).toBe('LIVE')

    // Simulate backend restart: GET /mode now returns EMPTY
    mockResponses['/mode'] = { status: 200, body: { mode: 'EMPTY' } }
    sync = await mod.syncModeFromBackend()
    expect(sync.ok).toBe(true)
    expect(sync.mode).toBe('EMPTY')

    // Frontend mode should now be EMPTY (reconciled)
    const health = mod.getHealth()
    expect(health.mode).toBe('EMPTY')
  })

  // ---- syncModeFromBackend returns explicit result ----

  test('syncModeFromBackend returns ok=false when backend unreachable', async () => {
    const mod = await import('../src/lib/ids-data')
    const result = await mod.syncModeFromBackend()
    expect(result.ok).toBe(false)
    expect(result.error).toContain('BACKEND_UNREACHABLE')
  })

  test('syncModeFromBackend returns ok=true when backend reachable', async () => {
    mockResponses['/mode'] = { status: 200, body: { mode: 'EMPTY' } }
    const mod = await import('../src/lib/ids-data')
    const result = await mod.syncModeFromBackend()
    expect(result.ok).toBe(true)
    expect(result.mode).toBe('EMPTY')
  })

  // ---- No secrets in requests ----

  test('API key is forwarded via X-API-Key header, not in URL', async () => {
    process.env.TRAPSIG_BACKEND_API_KEY = 'test-secret-xyz'
    mockResponses['/mode'] = { status: 200, body: { mode: 'EMPTY' } }
    mockResponses['/mode/live'] = { status: 200, body: { mode: 'LIVE' } }

    const mod = await import('../src/lib/ids-data')
    await mod.enterLiveMode()

    // Check that the API key was sent as a header, not in the URL
    for (const req of capturedRequests) {
      expect(req.url).not.toContain('test-secret-xyz')
      expect(req.url).not.toContain('api_key')
    }
  })

  // ---- Stale-mode UI regression tests ----
  // These verify that syncModeFromBackend does NOT allow stale LIVE/DEMO
  // to be presented as authoritative when the backend is unreachable.

  test('S1. Backend reports LIVE then becomes unreachable — mode NOT authoritative', async () => {
    // First sync: backend says LIVE
    mockResponses['/mode'] = { status: 200, body: { mode: 'LIVE' } }
    const mod = await import('../src/lib/ids-data')
    let sync = await mod.syncModeFromBackend()
    expect(sync.ok).toBe(true)
    expect(sync.mode).toBe('LIVE')

    // Backend becomes unreachable (clear all mock responses)
    clearMockResponses()
    sync = await mod.syncModeFromBackend()
    expect(sync.ok).toBe(false)
    expect(sync.error).toContain('BACKEND_UNREACHABLE')
    // The cached mode is still 'LIVE' but ok=false means it's NOT authoritative
    expect(sync.mode).toBe('LIVE')  // cached, but NOT authoritative
  })

  test('S2. Backend reports DEMO then becomes unreachable — mode NOT authoritative', async () => {
    mockResponses['/mode'] = { status: 200, body: { mode: 'DEMO' } }
    const mod = await import('../src/lib/ids-data')
    let sync = await mod.syncModeFromBackend()
    expect(sync.ok).toBe(true)
    expect(sync.mode).toBe('DEMO')

    clearMockResponses()
    sync = await mod.syncModeFromBackend()
    expect(sync.ok).toBe(false)
    expect(sync.error).toContain('BACKEND_UNREACHABLE')
    expect(sync.mode).toBe('DEMO')  // cached, but NOT authoritative
  })

  test('S3. Backend restart LIVE→EMPTY reflected after sync', async () => {
    mockResponses['/mode'] = { status: 200, body: { mode: 'LIVE' } }
    const mod = await import('../src/lib/ids-data')
    let sync = await mod.syncModeFromBackend()
    expect(sync.ok).toBe(true)
    expect(sync.mode).toBe('LIVE')

    // Backend restarts → mode resets to EMPTY
    mockResponses['/mode'] = { status: 200, body: { mode: 'EMPTY' } }
    sync = await mod.syncModeFromBackend()
    expect(sync.ok).toBe(true)
    expect(sync.mode).toBe('EMPTY')
    const health = mod.getHealth()
    expect(health.mode).toBe('EMPTY')
  })

  test('S4. Backend returns malformed mode — frontend does not invent a mode', async () => {
    mockResponses['/mode'] = { status: 200, body: { mode: 'HACKED' } }
    const mod = await import('../src/lib/ids-data')
    const sync = await mod.syncModeFromBackend()
    expect(sync.ok).toBe(false)
    expect(sync.error).toContain('unknown mode')
    // Frontend mode should NOT have changed to 'HACKED'
    const health = mod.getHealth()
    expect(health.mode).not.toBe('HACKED')
  })

  test('S5. Backend returns 500 — frontend does not invent a mode', async () => {
    mockResponses['/mode'] = { status: 500, body: { detail: 'internal error' } }
    const mod = await import('../src/lib/ids-data')
    const sync = await mod.syncModeFromBackend()
    expect(sync.ok).toBe(false)
    expect(sync.error).toContain('500')
  })

  // ---- DEMO with missing local data (Issue 2 regression) ----

  test('D1. Backend DEMO + local dataset missing → FAIL + rollback to EMPTY', async () => {
    // Point to a non-existent path so CSV is guaranteed missing
    process.env.IOT_HONEYPOT_IDS_ROOT = '/nonexistent/path/for/test'
    delete require.cache[require.resolve('../src/lib/ids-data')]

    const origFetch = globalThis.fetch
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'GET' && urlStr.includes('/mode')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'EMPTY' }), text: async () => '{"mode":"EMPTY"}' } as Response)
      }
      return Promise.reject(new TypeError('unexpected fetch'))
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    // Backend is DEMO but local data is missing → FAIL
    expect(result.success).toBe(false)
    expect(result.message).toContain('demo dataset is missing')
    expect(result.count).toBe(0)

    // Clean up
    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })

  // ---- Rollback failure scenarios (Issue 2 from Pass 5.6) ----
  // These test that loadDemoData() does NOT change frontend mode when the
  // rollback POST /mode/reset returns non-2xx or a malformed body.

  test('R1. Reset returns 401 → frontend stays DEMO, loadDemoData fails', async () => {
    // Backend says DEMO, local CSV missing, reset returns 401
    process.env.IOT_HONEYPOT_IDS_ROOT = '/nonexistent/path/for/test'
    delete require.cache[require.resolve('../src/lib/ids-data')]

    // Set frontend cache to DEMO (simulating stale state matching backend)
    const g = globalThis as any
    if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'

    const origFetch = globalThis.fetch
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'GET' && urlStr.includes('/mode')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        return Promise.resolve({ ok: false, status: 401, json: async () => ({ detail: 'unauthorized' }), text: async () => '{"detail":"unauthorized"}' } as Response)
      }
      return Promise.reject(new TypeError('unexpected fetch'))
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    // Reset failed (401) — frontend mode must NOT have changed to EMPTY
    expect(result.success).toBe(false)
    expect(result.message).toContain('reset failed')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')  // unchanged — NOT EMPTY

    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })

  test('R2. Reset returns 500 → frontend stays DEMO, loadDemoData fails', async () => {
    process.env.IOT_HONEYPOT_IDS_ROOT = '/nonexistent/path/for/test'
    delete require.cache[require.resolve('../src/lib/ids-data')]

    const g = globalThis as any
    if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'

    const origFetch = globalThis.fetch
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'GET' && urlStr.includes('/mode')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        return Promise.resolve({ ok: false, status: 500, json: async () => ({ detail: 'internal error' }), text: async () => '{"detail":"internal error"}' } as Response)
      }
      return Promise.reject(new TypeError('unexpected fetch'))
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    expect(result.success).toBe(false)
    expect(result.message).toContain('reset failed')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')

    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })

  test('R3. Reset returns 200 but malformed body → frontend stays DEMO', async () => {
    process.env.IOT_HONEYPOT_IDS_ROOT = '/nonexistent/path/for/test'
    delete require.cache[require.resolve('../src/lib/ids-data')]

    const g = globalThis as any
    if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'

    const origFetch = globalThis.fetch
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'GET' && urlStr.includes('/mode')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        // 200 but body doesn't contain mode: EMPTY
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ unexpected: 'data' }), text: async () => '{"unexpected":"data"}' } as Response)
      }
      return Promise.reject(new TypeError('unexpected fetch'))
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    expect(result.success).toBe(false)
    expect(result.message).toContain('malformed')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')

    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })

  test('R4. Reset returns 200 with mode=EMPTY → rollback succeeds, frontend EMPTY', async () => {
    process.env.IOT_HONEYPOT_IDS_ROOT = '/nonexistent/path/for/test'
    delete require.cache[require.resolve('../src/lib/ids-data')]

    const g = globalThis as any
    if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'

    const origFetch = globalThis.fetch
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'GET' && urlStr.includes('/mode')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'EMPTY' }), text: async () => '{"mode":"EMPTY"}' } as Response)
      }
      return Promise.reject(new TypeError('unexpected fetch'))
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    // Rollback succeeded — loadDemoData still fails (no data) but rollback was clean
    expect(result.success).toBe(false)
    expect(result.message).toContain('rolled back to EMPTY')
    const health = mod.getHealth()
    expect(health.mode).toBe('EMPTY')

    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })

  // ---- C1-C8: clearDemoData() reset confirmation tests ----
  // Each test forces the exact HTTP response and asserts whether the frontend
  // mode changes to EMPTY or stays DEMO. No permissive if/else branches.

  // Helper: set up clearDemoData test with frontend mode=DEMO
  function setupClearTest() {
    const g = globalThis as any
    if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'
    delete require.cache[require.resolve('../src/lib/ids-data')]
  }

  function makeResetMock(status: number, body: any) {
    return ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        return Promise.resolve({
          ok: status >= 200 && status < 300,
          status,
          json: async () => body,
          text: async () => JSON.stringify(body),
        } as Response)
      }
      return Promise.reject(new TypeError('unexpected fetch'))
    }) as any
  }

  test('C1. clearDemoData + reset 401 → failure, mode stays DEMO', async () => {
    setupClearTest()
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(401, { detail: 'unauthorized' })
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(result.message).toContain('auth failed')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')
  })

  test('C2. clearDemoData + reset 403 → failure, mode stays DEMO', async () => {
    setupClearTest()
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(403, { detail: 'forbidden' })
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(result.message).toContain('auth failed')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')
  })

  test('C3. clearDemoData + reset 409 → failure, mode stays DEMO', async () => {
    setupClearTest()
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(409, { detail: 'Cannot reset from current state' })
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(result.message).toContain('Cannot reset')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')
  })

  test('C4. clearDemoData + reset 500 → failure, mode stays DEMO', async () => {
    setupClearTest()
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(500, { detail: 'internal error' })
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(result.message).toContain('500')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')
  })

  test('C5. clearDemoData + reset 200 + malformed JSON → failure, mode stays DEMO', async () => {
    setupClearTest()
    const origFetch = globalThis.fetch
    // 200 but json() throws
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        return Promise.resolve({
          ok: true, status: 200,
          json: async () => { throw new SyntaxError('malformed JSON') },
          text: async () => 'not json',
        } as Response)
      }
      return Promise.reject(new TypeError('unexpected fetch'))
    }) as any
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(result.message).toContain('malformed')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')
  })

  test('C6. clearDemoData + reset 200 + {} → failure, mode stays DEMO', async () => {
    setupClearTest()
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(200, {})
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(result.message).toContain('malformed')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')
  })

  test('C7. clearDemoData + reset 200 + {"mode":"DEMO"} → failure, mode stays DEMO', async () => {
    setupClearTest()
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(200, { mode: 'DEMO' })
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(result.message).toContain('malformed')
    const health = mod.getHealth()
    expect(health.mode).toBe('DEMO')
  })

  test('C8. clearDemoData + reset 200 + {"mode":"EMPTY"} → success, mode becomes EMPTY', async () => {
    setupClearTest()
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(200, { mode: 'EMPTY' })
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(true)
    const health = mod.getHealth()
    expect(health.mode).toBe('EMPTY')
  })

  // ---- D1-D8: Final mode coherence regression tests ----
  // These verify the complete rollback contract for both clearDemoData() and
  // loadDemoData() — specifically that setMode('EMPTY') only executes after
  // backend explicitly confirms { mode: "EMPTY" }.

  // Helper for loadDemoData rollback tests with missing dataset
  function setupLoadDemoMissingDataset() {
    process.env.IOT_HONEYPOT_IDS_ROOT = '/nonexistent/path/for/test'
    delete require.cache[require.resolve('../src/lib/ids-data')]
  }

  // D1: clearDemoData() success — reset 200 + {mode:EMPTY}
  test('D1. clearDemoData success — reset 200 + {mode:EMPTY}', async () => {
    const g = globalThis as any; if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'
    delete require.cache[require.resolve('../src/lib/ids-data')]
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(200, { mode: 'EMPTY' })
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(true)
    expect(mod.getHealth().mode).toBe('EMPTY')
  })

  // D2: clearDemoData() HTTP failure — reset 500
  test('D2. clearDemoData failure — reset 500, mode stays DEMO', async () => {
    const g = globalThis as any; if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'
    delete require.cache[require.resolve('../src/lib/ids-data')]
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(500, { detail: 'error' })
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(mod.getHealth().mode).toBe('DEMO')
  })

  // D3: clearDemoData() malformed JSON
  test('D3. clearDemoData failure — reset 200 + malformed JSON, mode stays DEMO', async () => {
    const g = globalThis as any; if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'
    delete require.cache[require.resolve('../src/lib/ids-data')]
    const origFetch = globalThis.fetch
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const method = init?.method || 'GET'
      const urlStr = typeof url === 'string' ? url : url.toString()
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => { throw new SyntaxError('bad json') }, text: async () => 'not json' } as Response)
      }
      return Promise.reject(new TypeError('unexpected'))
    }) as any
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(mod.getHealth().mode).toBe('DEMO')
  })

  // D4: clearDemoData() missing mode
  test('D4. clearDemoData failure — reset 200 + {}, mode stays DEMO', async () => {
    const g = globalThis as any; if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'
    delete require.cache[require.resolve('../src/lib/ids-data')]
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(200, {})
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(mod.getHealth().mode).toBe('DEMO')
  })

  // D5: clearDemoData() wrong mode
  test('D5. clearDemoData failure — reset 200 + {mode:DEMO}, mode stays DEMO', async () => {
    const g = globalThis as any; if (g.__trapsig_state) g.__trapsig_state.mode = 'DEMO'
    delete require.cache[require.resolve('../src/lib/ids-data')]
    const origFetch = globalThis.fetch
    globalThis.fetch = makeResetMock(200, { mode: 'DEMO' })
    const mod = await import('../src/lib/ids-data')
    const result = await mod.clearDemoData()
    globalThis.fetch = origFetch
    expect(result.success).toBe(false)
    expect(mod.getHealth().mode).toBe('DEMO')
  })

  // D6: loadDemoData() successful rollback — the critical test
  // backend EMPTY → POST /mode/demo (200 DEMO) → dataset missing → POST /mode/reset (200 EMPTY)
  // Expected: loadDemoData fails (no dataset), but frontend mode IS EMPTY
  test('D6. loadDemoData rollback success — frontend mode becomes EMPTY', async () => {
    setupLoadDemoMissingDataset()
    const origFetch = globalThis.fetch
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'GET' && urlStr.includes('/mode')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'EMPTY' }), text: async () => '{"mode":"EMPTY"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/demo')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'EMPTY' }), text: async () => '{"mode":"EMPTY"}' } as Response)
      }
      return Promise.reject(new TypeError('unexpected'))
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    // loadDemoData fails (no dataset), but rollback succeeded
    expect(result.success).toBe(false)
    expect(result.message).toContain('rolled back to EMPTY')
    // CRITICAL: frontend mode must be EMPTY (matching backend)
    expect(mod.getHealth().mode).toBe('EMPTY')

    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })

  // D7: loadDemoData() failed rollback — reset returns 500
  // After rollback failure, loadDemoData re-syncs from backend.
  // Backend is still DEMO (reset failed), so frontend must be DEMO.
  test('D7. loadDemoData rollback failure — reset 500, frontend re-syncs to DEMO', async () => {
    setupLoadDemoMissingDataset()
    const origFetch = globalThis.fetch
    let resetAttempted = false
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'GET' && urlStr.includes('/mode')) {
        // First GET (sync): EMPTY. After reset fails, re-sync: backend is DEMO.
        if (resetAttempted) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
        }
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'EMPTY' }), text: async () => '{"mode":"EMPTY"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/demo')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        resetAttempted = true
        return Promise.resolve({ ok: false, status: 500, json: async () => ({ detail: 'error' }), text: async () => '{"detail":"error"}' } as Response)
      }
      return Promise.reject(new TypeError('unexpected'))
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    expect(result.success).toBe(false)
    expect(result.message).toContain('reset failed')
    // CRITICAL: After rollback failure, frontend re-synced from backend.
    // Backend is still DEMO (reset failed), so frontend must be DEMO.
    // The frontend must NOT falsely claim EMPTY.
    expect(mod.getHealth().mode).toBe('DEMO')

    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })

  // D8: loadDemoData() uncertain rollback — two sub-cases
  // After uncertain rollback, loadDemoData re-syncs from backend.
  test('D8a. loadDemoData rollback — reset 200 + {} → frontend re-syncs to DEMO', async () => {
    setupLoadDemoMissingDataset()
    const origFetch = globalThis.fetch
    let resetAttempted = false
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'GET' && urlStr.includes('/mode')) {
        if (resetAttempted) {
          // Re-sync: backend is still DEMO (rollback was uncertain)
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
        }
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'EMPTY' }), text: async () => '{"mode":"EMPTY"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/demo')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        resetAttempted = true
        return Promise.resolve({ ok: true, status: 200, json: async () => ({}), text: async () => '{}' } as Response)
      }
      return Promise.reject(new TypeError('unexpected'))
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    expect(result.success).toBe(false)
    expect(result.message).toContain('malformed')
    // Frontend re-synced: backend is DEMO (uncertain rollback), so frontend is DEMO
    expect(mod.getHealth().mode).toBe('DEMO')

    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })

  test('D8b. loadDemoData rollback — network failure → frontend re-syncs to DEMO', async () => {
    setupLoadDemoMissingDataset()
    const origFetch = globalThis.fetch
    let resetAttempted = false
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === 'string' ? url : url.toString()
      const method = init?.method || 'GET'
      if (method === 'GET' && urlStr.includes('/mode')) {
        if (resetAttempted) {
          // Re-sync: backend is still DEMO (network error during reset)
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
        }
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'EMPTY' }), text: async () => '{"mode":"EMPTY"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/demo')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ mode: 'DEMO' }), text: async () => '{"mode":"DEMO"}' } as Response)
      }
      if (method === 'POST' && urlStr.includes('/mode/reset')) {
        resetAttempted = true
        return Promise.reject(new TypeError('network failure'))
      }
      return Promise.reject(new TypeError('unexpected'))
    }) as any

    const mod = await import('../src/lib/ids-data')
    const result = await mod.loadDemoData()
    globalThis.fetch = origFetch

    expect(result.success).toBe(false)
    expect(result.message).toContain('network error')
    // Frontend re-synced: backend is DEMO, so frontend is DEMO
    expect(mod.getHealth().mode).toBe('DEMO')

    delete process.env.IOT_HONEYPOT_IDS_ROOT
  })
})
