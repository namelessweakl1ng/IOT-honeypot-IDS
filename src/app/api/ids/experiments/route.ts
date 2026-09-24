import { NextResponse } from 'next/server'
import { getExperiments, getFeatures, getAttackTypes, getHoneypots, getDatasets, getScenarios } from '@/lib/ids-data'

export const dynamic = 'force-dynamic'

export async function GET() { return NextResponse.json(getExperiments()) }
