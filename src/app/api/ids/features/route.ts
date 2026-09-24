import { NextResponse } from 'next/server'
import { getFeatures } from '@/lib/ids-data'
export const dynamic = 'force-dynamic'
export async function GET() { return NextResponse.json(getFeatures()) }
