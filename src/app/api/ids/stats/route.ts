import { NextResponse } from 'next/server'
import { getStatsLive, getStatsSync } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET() {
  // In LIVE mode, proxy to FastAPI. In DEMO/EMPTY, use local data.
  const result = await getStatsLive()
  return NextResponse.json(result)
}
