import { NextResponse } from 'next/server'
import { getModel } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const m = getModel(id)
  if (!m) return NextResponse.json({ detail: 'model not found' }, { status: 404 })
  return NextResponse.json(m)
}
