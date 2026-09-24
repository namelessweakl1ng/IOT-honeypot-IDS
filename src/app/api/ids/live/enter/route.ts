import { NextResponse } from 'next/server'
import { enterLiveMode } from '@/lib/ids-data'
export const dynamic = 'force-dynamic'
export async function POST() { return NextResponse.json(await enterLiveMode()) }
