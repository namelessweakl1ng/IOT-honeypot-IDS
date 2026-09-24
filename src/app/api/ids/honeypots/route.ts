import { NextResponse } from 'next/server'
import { getHoneypots } from '@/lib/ids-data'
export const dynamic = 'force-dynamic'
export async function GET() { return NextResponse.json(await getHoneypots()) }
