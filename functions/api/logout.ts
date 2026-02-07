/*
 * 用户登出 API
 */

interface Env {
  DB: D1Database;
}

export async function onRequest({
  request,
  env
}: {
  request: Request;
  env: Env;
}): Promise<Response> {
  // 只允许 POST 请求（防止 CSRF）
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: '方法不允许' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 从 Cookie 中获取 session ID
  const cookie = request.headers.get('Cookie');
  const match = cookie?.match(/session=([^;]+)/);
  const sessionId = match ? decodeURIComponent(match[1]) : null;

  try {
    if (sessionId) {
      // 删除数据库中的 session
      await env.DB.prepare(
        `DELETE FROM sessions WHERE session_id = ?`
      ).bind(sessionId).run();
    }

    // 清除浏览器 Cookie（关键！）
    const isLocal = request.url.includes('localhost') || request.url.includes('127.0.0.1');
    const cookieParts = [
      'session=',
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      'Max-Age=0' // 立即过期
    ];

    if (!isLocal) {
      cookieParts.push('Secure');
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': cookieParts.join('; ')
      }
    });

  } catch (error) {
    console.error('登出失败:', error);
    return new Response(JSON.stringify({ error: '登出失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}