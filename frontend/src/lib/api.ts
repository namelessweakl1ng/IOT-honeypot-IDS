const API=typeof window === "undefined" ? (process.env.API_URL ?? "http://backend:8000") : "/api";
export type RecordValue=Record<string,unknown>;
export async function api<T>(path:string,init?:RequestInit):Promise<T>{
  const response=await fetch(`${API}${path}`,{...init,headers:{"Content-Type":"application/json",...init?.headers},cache:"no-store"});
  if(!response.ok) throw new Error(`${response.status}: ${await response.text()}`);
  return response.json() as Promise<T>;
}
