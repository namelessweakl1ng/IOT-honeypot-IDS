import { NextRequest, NextResponse } from "next/server";

const API_URL = process.env.API_URL ?? "http://backend:8000";

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const upstream = new URL(`${API_URL}/${path.join("/")}`);
  upstream.search = request.nextUrl.search;
  const response = await fetch(upstream, {
    method: request.method,
    headers: { "content-type": request.headers.get("content-type") ?? "application/json" },
    body: request.method === "GET" ? undefined : await request.text(),
    cache: "no-store",
  });
  return new NextResponse(response.body, { status: response.status, headers: { "content-type": response.headers.get("content-type") ?? "application/json" } });
}

export const GET = proxy;
export const POST = proxy;
