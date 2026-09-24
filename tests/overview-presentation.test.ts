/**
 * Overview presentation authority tests.
 *
 * Verifies that OverviewPage uses the authoritative displayMode prop
 * (from page.tsx) instead of the stale stats?.mode cache.
 */
import { describe, test, expect } from 'bun:test'

describe('Overview presentation authority', () => {

  // ---- TEST 1-4: displayMode is used for the MODE label ----

  test('1. displayMode EMPTY → Overview must display MODE: EMPTY', async () => {
    const src = await Bun.file('src/components/ids/overview-page.tsx').text()
    expect(src).toContain('MODE: {mode}')
    expect(src).toContain('const mode = displayMode')
    expect(src).not.toContain("MODE: {stats?.mode")
  })

  test('2. displayMode DEMO → Overview accepts DEMO', async () => {
    const src = await Bun.file('src/components/ids/overview-page.tsx').text()
    expect(src).toContain("displayMode: DisplayMode")
    expect(src).toContain("import type { DisplayMode } from './display-mode'")
    // DisplayMode type is defined in the shared module
    const dmSrc = await Bun.file('src/components/ids/display-mode.ts').text()
    expect(dmSrc).toContain("type DisplayMode = 'EMPTY' | 'DEMO' | 'LIVE' | 'UNKNOWN'")
  })

  test('3. displayMode LIVE → Overview accepts LIVE', async () => {
    const src = await Bun.file('src/components/ids/overview-page.tsx').text()
    expect(src).toContain("'LIVE'")
  })

  test('4. displayMode UNKNOWN → Overview must NOT display MODE: EMPTY', async () => {
    const src = await Bun.file('src/components/ids/overview-page.tsx').text()
    expect(src).toContain("'UNKNOWN'")
    expect(src).toContain('isUnknown')
    expect(src).not.toContain("MODE: {stats?.mode")
  })

  // ---- TEST 5: UNKNOWN + BACKEND_UNREACHABLE → NOT "Pi is offline" ----

  test('5. BACKEND_UNREACHABLE → telemetry must NOT say "Pi is offline"', async () => {
    const src = await Bun.file('src/components/ids/overview-page.tsx').text()
    // Must have a case for BACKEND_UNREACHABLE
    expect(src).toContain("case 'BACKEND_UNREACHABLE'")
    // Extract the return value for BACKEND_UNREACHABLE case
    const idx = src.indexOf("case 'BACKEND_UNREACHABLE'")
    const section = src.substring(idx, idx + 200)
    expect(section).not.toContain('Pi is offline')
    expect(section.toLowerCase()).toContain('backend')
  })

  // ---- TEST 6: OFFLINE → may say "Pi is offline" ----

  test('6. OFFLINE → telemetry message may say "Pi is offline"', async () => {
    const src = await Bun.file('src/components/ids/overview-page.tsx').text()
    const idx = src.indexOf("case 'OFFLINE'")
    const section = src.substring(idx, idx + 200)
    expect(section).toContain('Pi is offline')
  })

  // ---- TEST 7: NOT_CONFIGURED → must identify configuration issue ----

  test('7. NOT_CONFIGURED → telemetry must identify configuration', async () => {
    const src = await Bun.file('src/components/ids/overview-page.tsx').text()
    const idx = src.indexOf("case 'NOT_CONFIGURED'")
    const section = src.substring(idx, idx + 200)
    expect(section).not.toContain('Pi is offline')
    expect(section.toLowerCase()).toContain('configured')
  })

  // ---- TEST 8: LOAD DEMO button disabled when UNKNOWN ----

  test('8. UNKNOWN displayMode → LOAD DEMO button must be disabled or hidden', async () => {
    const src = await Bun.file('src/components/ids/overview-page.tsx').text()
    expect(src).toContain('BACKEND UNREACHABLE — DEMO MODE REQUIRES BACKEND')
  })

  // ---- TEST 9: page.tsx passes displayMode + piStatus to OverviewPage ----

  test('9. page.tsx passes displayMode and piStatus props to OverviewPage', async () => {
    const src = await Bun.file('src/app/page.tsx').text()
    expect(src).toContain('displayMode={displayMode}')
    expect(src).toContain('piStatus={piStatus}')
  })

  // ---- TEST 10: All pi_status enum values have distinct messages ----

  test('10. All major pi_status values have distinct messages (no collapse)', async () => {
    const src = await Bun.file('src/components/ids/overview-page.tsx').text()
    const statuses = ['CONNECTED', 'OFFLINE', 'BACKEND_UNREACHABLE', 'NOT_CONFIGURED',
                      'AUTH_FAILED', 'HOST_KEY_UNKNOWN', 'HOST_KEY_CHANGED',
                      'TIMEOUT', 'SSH_NOT_INSTALLED', 'UNCHECKED', 'DEMO']
    for (const s of statuses) {
      expect(src).toContain(`case '${s}'`)
    }
  })

  // ---- TESTS 11-14: All child pages receive displayMode and use it ----

  test('11. LiveEventsPage receives displayMode prop and uses it', async () => {
    const src = await Bun.file('src/components/ids/live-events-page.tsx').text()
    expect(src).toContain("displayMode: DisplayMode")
    expect(src).toContain("const mode = displayMode")
    // Must NOT use stale stats?.mode as authoritative
    expect(src).not.toContain("stats?.mode || eventsData?.mode")
  })

  test('12. SessionsPage receives displayMode prop and uses it', async () => {
    const src = await Bun.file('src/components/ids/sessions-page.tsx').text()
    expect(src).toContain("displayMode: DisplayMode")
    expect(src).toContain("const mode = displayMode")
    // Must NOT use d.mode || 'EMPTY' as authoritative
    expect(src).not.toContain("d.mode || 'EMPTY'")
  })

  test('13. DetectionsPage receives displayMode prop and uses it', async () => {
    const src = await Bun.file('src/components/ids/detections-page.tsx').text()
    expect(src).toContain("displayMode: DisplayMode")
    expect(src).toContain("const mode = displayMode")
    // Must NOT use stats?.mode || 'EMPTY' as authoritative label
    expect(src).not.toContain("stats?.mode || 'EMPTY'")
  })

  test('14. ModelsPage receives displayMode prop and uses it', async () => {
    const src = await Bun.file('src/components/ids/models-page.tsx').text()
    expect(src).toContain("displayMode: DisplayMode")
    expect(src).toContain("const mode = displayMode")
    // Must NOT use stats?.mode || 'EMPTY' as authoritative label
    expect(src).not.toContain("stats?.mode || 'EMPTY'")
  })

  // ---- TEST 15: page.tsx passes displayMode to all four child pages ----

  test('15. page.tsx passes displayMode to all four child pages', async () => {
    const src = await Bun.file('src/app/page.tsx').text()
    expect(src).toContain('displayMode={displayMode}')
    // Verify all four pages receive the prop
    const matches = src.match(/displayMode=\{displayMode\}/g)
    expect(matches).not.toBeNull()
    expect(matches!.length).toBeGreaterThanOrEqual(4) // Overview + 4 pages
  })

  // ---- TEST 16: All pages have UNKNOWN handling ----

  test('16. All child pages have UNKNOWN handling (isUnknown)', async () => {
    const pages = ['live-events-page.tsx', 'sessions-page.tsx', 'detections-page.tsx', 'models-page.tsx', 'overview-page.tsx']
    for (const page of pages) {
      const src = await Bun.file(`src/components/ids/${page}`).text()
      expect(src).toContain('isUnknown')
      expect(src).toContain("'UNKNOWN'")
    }
  })

  // ---- TEST 17: No production IDS page uses stale mode as authoritative ----

  test('17. No IDS page uses stats?.mode or eventsData?.mode as authoritative mode label', async () => {
    const pages = ['live-events-page.tsx', 'sessions-page.tsx', 'detections-page.tsx', 'models-page.tsx']
    for (const page of pages) {
      const src = await Bun.file(`src/components/ids/${page}`).text()
      // The mode label must NOT derive from stale stats/eventsData
      expect(src).not.toContain("MODE: {stats?.mode")
      expect(src).not.toContain("stats?.mode || 'EMPTY'")
      expect(src).not.toContain("stats?.mode || eventsData?.mode")
      expect(src).not.toContain("d.mode || 'EMPTY'")
    }
  })

  // ---- TESTS 18-22: HoneypotsPage presentation authority ----

  test('18. page.tsx passes displayMode and piStatus to HoneypotsPage', async () => {
    const src = await Bun.file('src/app/page.tsx').text()
    expect(src).toContain('HoneypotsPage displayMode={displayMode} piStatus={piStatus}')
  })

  test('19. HoneypotsPage accepts displayMode and piStatus props', async () => {
    const src = await Bun.file('src/components/ids/honeypots-page.tsx').text()
    expect(src).toContain('displayMode: DisplayMode')
    expect(src).toContain('piStatus: string')
  })

  test('20. HoneypotsPage does NOT use honeypots?.pi_status as authoritative presentation', async () => {
    const src = await Bun.file('src/components/ids/honeypots-page.tsx').text()
    // Must NOT prefer honeypots?.pi_status over the shell value
    expect(src).not.toContain('honeypots?.pi_status || sysStatus')
    expect(src).not.toContain("honeypots?.pi_status || 'UNCHECKED'")
  })

  test('21. HoneypotsPage uses shell piStatus (not stale local)', async () => {
    const src = await Bun.file('src/components/ids/honeypots-page.tsx').text()
    // The authoritative piStatus comes from the prop, not from local API response
    expect(src).toContain('piStatus: shellPiStatus')
    expect(src).toContain('const piStatus = shellPiStatus')
  })

  test('22. HoneypotsPage does NOT use stale mode as authoritative presentation', async () => {
    const src = await Bun.file('src/components/ids/honeypots-page.tsx').text()
    // Must NOT derive mode from local API response or cache
    expect(src).not.toContain("ss?.mode ?? 'EMPTY'")
    expect(src).not.toContain("mode: ss?.mode")
  })

  // ---- TEST 23: page.tsx has no duplicate DisplayMode declaration ----

  test('23. page.tsx has no duplicate DisplayMode type declaration', async () => {
    const src = await Bun.file('src/app/page.tsx').text()
    // The local declaration was removed; only the shared import remains
    expect(src).not.toContain("type DisplayMode = 'EMPTY' | 'DEMO' | 'LIVE' | 'UNKNOWN'")
    expect(src).toContain("import type { DisplayMode } from '@/components/ids/display-mode'")
  })

  // ---- TEST 24: HoneypotsPage has BACKEND_UNREACHABLE handling ----

  test('24. HoneypotsPage has BACKEND_UNREACHABLE in piStatusColor + piStatusExplanation', async () => {
    const src = await Bun.file('src/components/ids/honeypots-page.tsx').text()
    expect(src).toContain("case 'BACKEND_UNREACHABLE'")
    // Color must be rose (error), not slate (unknown)
    const colorIdx = src.indexOf("case 'BACKEND_UNREACHABLE'")
    const colorSection = src.substring(colorIdx, colorIdx + 100)
    expect(colorSection).toContain('text-rose-400')
    // Explanation must mention backend
    const explIdx = src.indexOf("case 'BACKEND_UNREACHABLE'", src.indexOf("case 'BACKEND_UNREACHABLE'") + 1)
    if (explIdx > 0) {
      const explSection = src.substring(explIdx, explIdx + 200)
      expect(explSection.toLowerCase()).toContain('backend')
    }
  })

  // ---- TESTS 25-29: Final honeypots presentation regression (Pass 5 final correction) ----
  // These tests guard against the two implementation defects called out in
  // the final review: dead displayMode prop, and duplicate switch cases.

  /**
   * TEST A — displayMode is actually USED for presentation, not just accepted.
   *
   * Strategy: isolate the HoneypotsPage component body (between the function
   * signature and the closing brace) and verify it contains a render-path
   * reference to displayMode AND a MODE label that interpolates the variable.
   * Just declaring `displayMode: DisplayMode` in the props type is NOT enough.
   */
  test('25 (A). HoneypotsPage uses displayMode in rendered presentation logic', async () => {
    const src = await Bun.file('src/components/ids/honeypots-page.tsx').text()
    // Component body must derive a runtime variable from displayMode
    expect(src).toContain('const mode = displayMode')
    // The mode variable must drive a rendered MODE label
    expect(src).toContain('MODE: {mode}')
    // modeColor must branch on at least the four canonical DisplayMode values
    expect(src).toMatch(/mode === 'LIVE'/)
    expect(src).toMatch(/mode === 'DEMO'/)
    expect(src).toMatch(/mode === 'UNKNOWN'|isUnknown/)
    // EMPTY must NOT be presented when mode is UNKNOWN — verify isUnknown is
    // both declared and used in a render-path conditional
    expect(src).toMatch(/isUnknown/)
    const isUnknownAssignments = src.match(/const isUnknown = mode === 'UNKNOWN'/g)
    expect(isUnknownAssignments).not.toBeNull()
    expect(isUnknownAssignments!.length).toBe(1)
    // isUnknown must be referenced at least once AFTER its declaration in a
    // render branch (not just declared and abandoned)
    const declIdx = src.indexOf('const isUnknown = mode === \'UNKNOWN\'')
    const afterDecl = src.substring(declIdx)
    // Must appear in either modeColor ternary or a JSX conditional
    expect(afterDecl).toMatch(/isUnknown \?|isUnknown &&|isEmpty \|\| isUnknown/)
  })

  /**
   * TEST B — piStatusColor() has exactly ONE case per BACKEND_* status.
   */
  test('26 (B). piStatusColor has no duplicate BACKEND_UNREACHABLE/ERROR/TIMEOUT cases', async () => {
    const src = await Bun.file('src/components/ids/honeypots-page.tsx').text()
    // Isolate piStatusColor body — from its name to the next function decl
    const startIdx = src.indexOf('function piStatusColor(')
    expect(startIdx).toBeGreaterThan(-1)
    const endIdx = src.indexOf('function piStatusExplanation(')
    expect(endIdx).toBeGreaterThan(startIdx)
    const colorBody = src.substring(startIdx, endIdx)

    for (const s of ['BACKEND_UNREACHABLE', 'BACKEND_ERROR', 'BACKEND_TIMEOUT']) {
      const re = new RegExp(`case '${s}'`, 'g')
      const matches = colorBody.match(re)
      expect(matches).not.toBeNull()
      expect(matches!.length).toBe(1) // exactly one occurrence per status
    }
  })

  /**
   * TEST C — piStatusExplanation() has exactly ONE case per BACKEND_* status.
   */
  test('27 (C). piStatusExplanation has no duplicate BACKEND_UNREACHABLE/ERROR/TIMEOUT cases', async () => {
    const src = await Bun.file('src/components/ids/honeypots-page.tsx').text()
    const startIdx = src.indexOf('function piStatusExplanation(')
    expect(startIdx).toBeGreaterThan(-1)
    // The next function after piStatusExplanation is honeypotStateColor
    const endIdx = src.indexOf('function honeypotStateColor(')
    expect(endIdx).toBeGreaterThan(startIdx)
    const explBody = src.substring(startIdx, endIdx)

    for (const s of ['BACKEND_UNREACHABLE', 'BACKEND_ERROR', 'BACKEND_TIMEOUT']) {
      const re = new RegExp(`case '${s}'`, 'g')
      const matches = explBody.match(re)
      expect(matches).not.toBeNull()
      expect(matches!.length).toBe(1)
    }
  })

  /**
   * TEST D — UNKNOWN must NOT silently fall back to EMPTY presentation.
   *
   * Strategy: verify the component body (a) declares isUnknown, (b) renders
   * an UNKNOWN-specific banner/message, and (c) does NOT collapse UNKNOWN
   * into the EMPTY code path.
   */
  test('28 (D). UNKNOWN mode must not fall back to EMPTY presentation', async () => {
    const src = await Bun.file('src/components/ids/honeypots-page.tsx').text()
    // isUnknown must be declared and reference mode === 'UNKNOWN'
    expect(src).toContain("const isUnknown = mode === 'UNKNOWN'")
    // There must be an UNKNOWN-specific render branch (banner or conditional)
    expect(src).toMatch(/isUnknown && \(/)
    // The MODE label interpolates `mode`, so UNKNOWN will display as
    // "MODE: UNKNOWN" — not "MODE: EMPTY". Verify the label uses the
    // resolved mode variable, not a hardcoded 'EMPTY' literal.
    const modeLabelMatch = src.match(/MODE:\s*\{mode\}/)
    expect(modeLabelMatch).not.toBeNull()
    // No code path may re-assign mode to 'EMPTY' as a fallback for UNKNOWN
    expect(src).not.toMatch(/mode\s*=\s*['"]EMPTY['"]/)
    expect(src).not.toMatch(/mode\s*\?\?\s*['"]EMPTY['"]/)
  })

  /**
   * TEST E — BACKEND_UNREACHABLE piStatus must NOT fall back to UNCHECKED.
   *
   * Strategy: verify the component uses the shell piStatus verbatim
   * (`const piStatus = shellPiStatus`) and that there is no fallback chain
   * that would convert BACKEND_UNREACHABLE → 'UNCHECKED'. Also verify the
   * explanation function returns a backend-specific message for
   * BACKEND_UNREACHABLE (not the UNCHECKED "no probe attempted" message).
   */
  test('29 (E). BACKEND_UNREACHABLE piStatus must not fall back to UNCHECKED', async () => {
    const src = await Bun.file('src/components/ids/honeypots-page.tsx').text()
    // The shell piStatus is authoritative — no fallback to 'UNCHECKED'
    expect(src).toContain('const piStatus = shellPiStatus')
    expect(src).not.toMatch(/piStatus\s*=\s*shellPiStatus\s*\?\?\s*['"]UNCHECKED['"]/)
    expect(src).not.toMatch(/piStatus\s*\|\|\s*['"]UNCHECKED['"]/)
    // Must NOT reintroduce honeypots?.pi_status or sysStatus?.pi_status as
    // the authoritative value for presentation
    expect(src).not.toContain('honeypots?.pi_status || sysStatus')
    expect(src).not.toContain("honeypots?.pi_status || 'UNCHECKED'")
    // piStatusExplanation for BACKEND_UNREACHABLE must mention the backend
    // — must NOT contain the UNCHECKED message "No Pi probe has been attempted"
    const startIdx = src.indexOf('function piStatusExplanation(')
    const endIdx = src.indexOf('function honeypotStateColor(')
    const explBody = src.substring(startIdx, endIdx)
    const buIdx = explBody.indexOf("case 'BACKEND_UNREACHABLE'")
    expect(buIdx).toBeGreaterThan(-1)
    const buSection = explBody.substring(buIdx, buIdx + 200)
    expect(buSection.toLowerCase()).toContain('backend')
    expect(buSection).not.toContain('No Pi probe has been attempted')
    // And UNCHECKED case must remain its own distinct case (no merging)
    const unIdx = explBody.indexOf("case 'UNCHECKED'")
    expect(unIdx).toBeGreaterThan(-1)
    const unSection = explBody.substring(unIdx, unIdx + 200)
    expect(unSection).toContain('No Pi probe has been attempted')
  })
})
