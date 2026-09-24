import { NextResponse } from 'next/server'
import { getSessionsLive } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET(request: Request) {
  const url = new URL(request.url)
  const size = Number(url.searchParams.get('size') || '50')
  const label = url.searchParams.get('label') || undefined
  const result = await getSessionsLive({ size, label })
  return NextResponse.json(result)
}
