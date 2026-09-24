import { NextResponse } from 'next/server'
import { loadDemoData } from '@/lib/ids-data'
export const dynamic = 'force-dynamic'
export async function POST() { return NextResponse.json(await loadDemoData()) }
