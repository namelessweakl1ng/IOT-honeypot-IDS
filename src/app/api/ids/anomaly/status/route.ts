import { NextResponse } from 'next/server'
import { getAnomalyStatusLive } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET() {
  const result = await getAnomalyStatusLive()
  return NextResponse.json(result)
}
