import { NextResponse } from 'next/server'
import { getDetectionLineage } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  const result = await getDetectionLineage(id)
  return NextResponse.json(result)
}
