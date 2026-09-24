import { NextResponse } from 'next/server'
import { getSessionFeaturesLive } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  const { sessionId } = await params
  const result = await getSessionFeaturesLive(sessionId)
  return NextResponse.json(result)
}
