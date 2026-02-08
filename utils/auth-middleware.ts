// utils/auth-middleware.ts
import type { D1Database } from '@cloudflare/workers-types';
import { UserManager } from './user-manager';

export interface AuthContext {
  currentUser: {
    id: number;
    username: string;
    role: string;
  };
}

/**
 * 验证请求是否来自已登录的 root 用户
 * - 从 Cookie 中提取 session ID
 * - 查询 D1 sessions 表验证有效性
 * - 检查关联用户是否存在且角色为 'root'
 */
export async function requireRootUser(
  request: Request,
  env: { DB: D1Database }
): Promise<Response | AuthContext> {
  // 1. 从 Cookie 获取 session ID
  const cookieHeader = request.headers.get('Cookie');
  const sessionMatch = cookieHeader?.match(/session=([^;]+)/);
  const sessionId = sessionMatch?.[1];

  if (!sessionId) {
    return new Response(JSON.stringify({ error: '未登录或会话无效' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // 2. 查询 sessions 表
    const session = await env.DB.prepare(
      'SELECT user_id, expires_at FROM sessions WHERE session_id = ?'
    )
      .bind(sessionId)
      .first<{ user_id: number; expires_at: string }>();

    if (!session) {
      return new Response(JSON.stringify({ error: '会话不存在' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 3. 检查会话是否过期（expires_at 是 ISO 8601 字符串）
    const expiresAt = new Date(session.expires_at).getTime();
    if (expiresAt < Date.now()) {
      // 可选：清理过期会话
      await env.DB.prepare('DELETE FROM sessions WHERE id = ?')
        .bind(sessionId)
        .run();
      return new Response(JSON.stringify({ error: '会话已过期' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 4. 获取用户信息
    const userManager = new UserManager(env.DB);
    const user = await userManager.getUserById(session.user_id);

    if (!user || !user.id) {
      return new Response(JSON.stringify({ error: '关联用户不存在' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 5. 检查角色是否为 root
    if (user.role !== 'root') {
      return new Response(JSON.stringify({ error: '需要 root 权限' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 6. 返回认证上下文
    return {
      currentUser: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    };
  } catch (err) {
    console.error('Auth middleware error:', err);
    return new Response(JSON.stringify({ error: '认证过程出错' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}