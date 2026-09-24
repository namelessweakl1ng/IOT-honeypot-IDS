import { NextResponse } from 'next/server'
import { getModels, getModel } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET() {
  return NextResponse.json(getModels())
}
