import { NextResponse } from 'next/server'
import { getActiveModelLive } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET(request: Request) {
  const url = new URL(request.url)
  const role = url.searchParams.get('role') || 'default'
  const result = await getActiveModelLive(role)
  return NextResponse.json(result)
}
