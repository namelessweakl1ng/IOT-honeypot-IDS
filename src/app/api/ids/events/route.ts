import { NextResponse } from 'next/server'
import { getEventsLive } from '@/lib/ids-data'
export const dynamic = 'force-dynamic'
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url)
  const size = searchParams.get('size') ? parseInt(searchParams.get('size')!) : 100
  const source_ip = searchParams.get('source_ip') || undefined
  const device = searchParams.get('device') || undefined
  return NextResponse.json(await getEventsLive({ size, source_ip, device }))
}
