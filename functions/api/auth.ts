/*
 * 用户认证中间件：验证请求是否携带有效会话
 */

interface User {
  id: number;
  name: string;
  email: string;
}

interface AuthResult {
  user: User;
}

interface Env {
  DB: D1Database;
}

/**
 * 验证当前请求是否来自已登录用户
 * @returns {AuthResult | null} 如果登录成功，返回用户信息；否则返回 null
 */
export async function authenticateRequest(
  request: Request,
  env: Env
): Promise<AuthResult | null> {
  // 1. 从 Cookie 中提取 session_id
  const cookie = request.headers.get('Cookie');
  if (!cookie) return null;

  const match = cookie.match(/session=([^;]+)/);
  const sessionId = match ? decodeURIComponent(match[1]) : null;
  if (!sessionId) return null;

  // 2. 查询数据库：检查 session 是否存在且未过期
  // ✅ 使用 ISO 8601 UTC 时间字符串，与 login.ts 存储格式一致
  const nowUTC = new Date().toISOString();

  const session = await env.DB.prepare(`
    SELECT s.user_id, u.name, u.email
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.session_id = ? AND s.expires_at > ?
  `)
    .bind(sessionId, nowUTC)
    .first<{ user_id: number; name: string; email: string }>();

  if (!session) return null;

  // 3. 返回用户信息
  return {
    user: {
      id: session.user_id,
      name: session.name,
      email: session.email
    }
  };
}