// functions/api/log.ts
export async function onRequest({ request }: { request: Request }) {
  if (request.method !== 'POST') return new Response(null, { status: 405 });

  try {
    const data = await request.json();
    // 把日志打印到控制台（虽然你看不到，但至少结构正确）
    console.log('[REMOTE LOG]', JSON.stringify(data, null, 2));

    // 👇 关键：返回给前端！
    return new Response(JSON.stringify({ received: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch {
    return new Response(null, { status: 400 });
  }
}