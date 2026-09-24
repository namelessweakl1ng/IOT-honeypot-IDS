import { NextResponse } from 'next/server'
import { getSessionDetail } from '@/lib/ids-data'
export const dynamic = 'force-dynamic'
export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const detail = getSessionDetail(id)
  if (!detail) return NextResponse.json({ detail: 'session not found' }, { status: 404 })
  return NextResponse.json(detail)
}
