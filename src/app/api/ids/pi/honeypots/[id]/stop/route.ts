import { NextResponse } from 'next/server'
import { stopHoneypot } from '@/lib/ids-data'
export const dynamic = 'force-dynamic'
export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  return NextResponse.json(await stopHoneypot(id))
}
