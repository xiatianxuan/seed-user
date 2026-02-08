// functions/api/rm-user.ts

interface Env {
  DB: D1Database;
}

// 类型守卫：检查值是否为正整数
function isPositiveInteger(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value > 0
  );
}

export async function onRequest({
  request,
  env
}: {
  request: Request;
  env: Env;
}): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: '方法不允许，仅支持 POST' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  let body;
  try {
    body = await request.json();
  } catch (err) {
    return new Response(JSON.stringify({ error: '请求体必须是有效的 JSON' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // ✅ 关键：类型检查
  if (
    typeof body !== 'object' ||
    body === null ||
    !('user_id' in body)
  ) {
    return new Response(JSON.stringify({ error: '缺少 user_id 字段' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const userId = (body as { user_id: unknown }).user_id;

  if (!isPositiveInteger(userId)) {
    return new Response(JSON.stringify({ error: '无效的 user_id，必须为正整数' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 检查用户是否存在
  const existingUser = await env.DB.prepare(
    'SELECT id FROM users WHERE id = ?'
  ).bind(userId).first();

  if (!existingUser) {
    return new Response(JSON.stringify({ error: '用户不存在' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 执行删除
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();

  return new Response(JSON.stringify({
    success: true,
    message: `用户 ID ${userId} 已成功删除`,
    deleted_user_id: userId
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
}