import { NextResponse } from 'next/server'
import { getDetectionsLive } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET(request: Request) {
  const url = new URL(request.url)
  const size = Number(url.searchParams.get('size') || '50')
  const session_id = url.searchParams.get('session_id') || undefined
  const result = await getDetectionsLive({ size, session_id })
  return NextResponse.json(result)
}
