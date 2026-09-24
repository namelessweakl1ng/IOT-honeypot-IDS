import { NextResponse } from 'next/server'
import { getCampaignsLive } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET(request: Request) {
  const url = new URL(request.url)
  const size = Number(url.searchParams.get('size') || '50')
  const source_ip = url.searchParams.get('source_ip') || undefined
  const result = await getCampaignsLive({ size, source_ip })
  return NextResponse.json(result)
}
