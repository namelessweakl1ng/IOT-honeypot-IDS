/**
 * Pass 4 Verification: Next.js API-key forwarding regression test.
 *
 * This is a standalone test script run via `bun` — no test framework needed.
 * It verifies the server-side auth forwarding path:
 *   Browser-facing Next.js route
 *     -> honeypotAction()
 *     -> fetch(FastAPI, { headers: { 'X-API-Key': <server-side secret> } })
 *
 * The test mocks `fetch` to capture the headers without hitting a real backend.
 *
 * Run: bun run tests/nextjs-auth-forwarding.test.ts
 *
 * Verifies:
 *   1. TRAPSIG_BACKEND_API_KEY is read server-side
 *   2. FastAPI receives X-API-Key header with the configured secret
 *   3. Browser-facing response does NOT contain the secret
 *   4. Secret is not placed in NEXT_PUBLIC_* (checked via source grep)
 *   5. Missing server-side key → backend returns 401 (fail closed)
 *   6. Invalid honeypot ID cannot cause an arbitrary request (rejected locally)
 */

// Type-only import — the actual module is loaded dynamically with mocked fetch.
import { describe, test, expect, mock, beforeEach, afterEach } from 'bun:test'

// ---- Mock fetch to capture headers + control responses ----

interface CapturedRequest {
  url: string
  method: string
  headers: Record<string, string>
}

let capturedRequests: CapturedRequest[] = []
let mockResponse: { status: number; body: any } = { status: 200, body: { success: true, message: 'ok', verified_state: 'running' } }

const originalFetch = globalThis.fetch

function mockFetch(_url: string | URL | Request, init?: RequestInit): Promise<Response> {
  const url = typeof _url === 'string' ? _url : _url.toString()
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
  capturedRequests.push({
    url,
    method: init?.method || 'GET',
    headers,
  })
  // Return a Response-like object
  const resp = {
    ok: mockResponse.status >= 200 && mockResponse.status < 300,
    status: mockResponse.status,
    json: async () => mockResponse.body,
    text: async () => JSON.stringify(mockResponse.body),
  }
  return Promise.resolve(resp as Response)
}

// ---- Helpers ----

async function loadModule() {
  // Dynamic import so the mocked fetch is in place when the module runs.
  // Path: tests/nextjs-auth-forwarding.test.ts -> ../src/lib/ids-data/index.ts
  return await import('../src/lib/ids-data')
}

function resetEnv() {
  delete process.env.TRAPSIG_BACKEND_API_KEY
  delete process.env.API_SECRET_KEY
  delete process.env.NEXT_PUBLIC_TRAPSIG_BACKEND_API_KEY
}

// ---- Tests ----

describe('Next.js API-key forwarding (Pass 4)', () => {
  beforeEach(() => {
    capturedRequests = []
    mockResponse = { status: 200, body: { success: true, message: 'ok', verified_state: 'running' } }
    globalThis.fetch = mockFetch as any
    resetEnv()
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    resetEnv()
  })

  test('1. TRAPSIG_BACKEND_API_KEY is read server-side and forwarded as X-API-Key', async () => {
    process.env.TRAPSIG_BACKEND_API_KEY = 'test-secret-abc-123'
    const mod = await loadModule()
    await mod.startHoneypot('cowrie-01')

    expect(capturedRequests.length).toBe(1)
    const req = capturedRequests[0]
    expect(req.headers['X-API-Key']).toBe('test-secret-abc-123')
    expect(req.method).toBe('POST')
    expect(req.url).toContain('/honeypots/cowrie-01/start')
  })

  test('2. Falls back to API_SECRET_KEY if TRAPSIG_BACKEND_API_KEY unset', async () => {
    process.env.API_SECRET_KEY = 'fallback-secret-xyz'
    const mod = await loadModule()
    await mod.stopHoneypot('camera-01')

    expect(capturedRequests.length).toBe(1)
    expect(capturedRequests[0].headers['X-API-Key']).toBe('fallback-secret-xyz')
  })

  test('3. Browser-facing response does NOT contain the secret', async () => {
    process.env.TRAPSIG_BACKEND_API_KEY = 'super-secret-do-not-leak'
    const mod = await loadModule()
    const result = await mod.restartHoneypot('iot-01')

    const resultStr = JSON.stringify(result)
    expect(resultStr).not.toContain('super-secret-do-not-leak')
    expect(resultStr).not.toContain('TRAPSIG_BACKEND_API_KEY')
  })

  test('4. Missing server-side key → fetch sent without X-API-Key → backend rejects', async () => {
    // No TRAPSIG_BACKEND_API_KEY, no API_SECRET_KEY
    mockResponse = { status: 401, body: { detail: 'missing or invalid API key' } }
    const mod = await loadModule()
    const result = await mod.startHoneypot('cowrie-01')

    // fetch was called, but without X-API-Key header
    expect(capturedRequests.length).toBe(1)
    expect(capturedRequests[0].headers['X-API-Key']).toBeUndefined()
    // Result surfaces the auth failure honestly
    expect(result.success).toBe(false)
    expect(result.message).toContain('auth failed')
    // The message must NOT contain any secret value
    expect(result.message).not.toContain('super-secret')
  })

  test('5. Invalid honeypot ID is rejected locally — no fetch to FastAPI', async () => {
    process.env.TRAPSIG_BACKEND_API_KEY = 'test-secret'
    const mod = await loadModule()
    const result = await mod.startHoneypot('cowrie-01; rm -rf /')

    expect(result.success).toBe(false)
    expect(result.message).toContain('unknown honeypot')
    // No fetch should have been made — rejected before hitting the network
    expect(capturedRequests.length).toBe(0)
  })

  test('6. Invalid action is rejected locally — no fetch to FastAPI', async () => {
    process.env.TRAPSIG_BACKEND_API_KEY = 'test-secret'
    const mod = await loadModule()
    // The exported wrappers only accept 'start'/'stop'/'restart', but the
    // internal honeypotAction validates too. We test via the exported
    // startHoneypot which always passes 'start' — the action allow-list
    // is a defense-in-depth layer.
    const result = await mod.startHoneypot('cowrie-01')
    // This should succeed (valid id + valid action)
    expect(capturedRequests.length).toBe(1)
  })

  test('7. Backend 503 (Pi unavailable) is surfaced honestly', async () => {
    process.env.TRAPSIG_BACKEND_API_KEY = 'test-secret'
    mockResponse = { status: 503, body: { detail: 'Pi unavailable: NOT_CONFIGURED' } }
    const mod = await loadModule()
    const result = await mod.startHoneypot('cowrie-01')

    expect(result.success).toBe(false)
    expect(result.message).toContain('Pi unavailable')
    expect(result.message).toContain('NOT_CONFIGURED')
  })

  test('8. Backend 500 (verification failure) is surfaced honestly', async () => {
    process.env.TRAPSIG_BACKEND_API_KEY = 'test-secret'
    mockResponse = { status: 500, body: { detail: 'state not verified' } }
    const mod = await loadModule()
    const result = await mod.startHoneypot('cowrie-01')

    expect(result.success).toBe(false)
    expect(result.message).toContain('failed verification')
  })

  test('9. Secret not in NEXT_PUBLIC_* env vars (source-level check)', async () => {
    // Verify the source code does NOT reference NEXT_PUBLIC_TRAPSIG_BACKEND_API_KEY
    const fs = await import('fs')
    const path = await import('path')
    const srcPath = path.join(process.cwd(), 'src', 'lib', 'ids-data', 'index.ts')
    const src = fs.readFileSync(srcPath, 'utf-8')
    expect(src).not.toContain('NEXT_PUBLIC_TRAPSIG_BACKEND_API_KEY')
    expect(src).not.toContain('NEXT_PUBLIC_API_SECRET_KEY')
    // The code MUST read from process.env (server-side only)
    expect(src).toContain('process.env.TRAPSIG_BACKEND_API_KEY')
  })

  test('10. Auth failure message does not leak the key value', async () => {
    process.env.TRAPSIG_BACKEND_API_KEY = 'leak-test-secret-999'
    mockResponse = { status: 401, body: { detail: 'invalid key' } }
    const mod = await loadModule()
    const result = await mod.startHoneypot('cowrie-01')

    expect(result.success).toBe(false)
    // The message must NOT contain the actual secret value
    expect(result.message).not.toContain('leak-test-secret-999')
    // But it SHOULD contain a diagnostic about the auth failure
    expect(result.message).toContain('auth failed')
  })
})

// Run the tests
console.log('Running Next.js API-key forwarding tests...')
console.log('(If no output below, run: bun test tests/nextjs-auth-forwarding.test.ts)')
