import { NextResponse } from 'next/server'
import { clearDemoData } from '@/lib/ids-data'
export const dynamic = 'force-dynamic'
export async function POST() { return NextResponse.json(await clearDemoData()) }
