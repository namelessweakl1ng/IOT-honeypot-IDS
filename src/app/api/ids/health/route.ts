import { NextResponse } from 'next/server'
import { getHealth } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'
export const revalidate = 0

export async function GET() {
  return NextResponse.json(getHealth())
}
