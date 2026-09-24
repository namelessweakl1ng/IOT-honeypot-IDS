import { NextResponse } from 'next/server'
import { syncModeFromBackend } from '@/lib/ids-data'
export const dynamic = 'force-dynamic'
export async function GET() {
  const result = await syncModeFromBackend()
  if (!result.ok) {
    // Backend unreachable — return explicit error, not a fabricated mode.
    // The frontend should display UNKNOWN/SYNCING, not a stale mode.
    return NextResponse.json(
      { ok: false, mode: result.mode, error: result.error },
      { status: 503 },
    )
  }
  return NextResponse.json({ ok: true, mode: result.mode })
}
