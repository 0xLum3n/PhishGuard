import { NextResponse } from 'next/server'

const BACKEND_URL = (process.env.PHISHGUARD_API_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '')

export async function POST(request: Request) {
  let payload: unknown

  try {
    payload = await request.json()
  } catch {
    return NextResponse.json({ detail: 'Request body must be valid JSON.' }, { status: 400 })
  }

  try {
    const response = await fetch(`${BACKEND_URL}/api/analysis`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(payload),
      cache: 'no-store',
    })

    const body = await response.text()
    return new NextResponse(body, {
      status: response.status,
      headers: { 'Content-Type': response.headers.get('content-type') || 'application/json' },
    })
  } catch (error) {
    console.error('[v0] Analysis backend unavailable:', error)
    return NextResponse.json(
      {
        detail: 'The analysis backend is unavailable. Start the FastAPI service on port 8000 or set PHISHGUARD_API_URL to its reachable URL.',
      },
      { status: 502 },
    )
  }
}

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'
