// utils/auth-middleware.ts
import type { D1Database } from '@cloudflare/workers-types';
import { UserManager } from './user-manager';
import { ROLE_PRESET } from './permissions'; // ✅ 正确导入 ROLE_PRESET

export interface AuthContext {
  currentUser: {
    id: number;
    username: string;
    permissions: number; // ✅ 权限用数字位掩码表示
  };
}

/**
 * 验证请求是否来自具有 ROOT 权限的用户
 * - ROOT 定义为：permissions === ROLE_PRESET.ROOT（即 -1）
 * - 从 Cookie 中提取 session ID
 * - 查询 sessions 表验证有效性
 * - 检查关联用户是否存在且 permissions 为 -1
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
    // 2. 查询 sessions 表（主键是 session_id）
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

    // 3. 检查会话是否过期
    const expiresAt = new Date(session.expires_at).getTime();
    if (expiresAt < Date.now()) {
      await env.DB.prepare('DELETE FROM sessions WHERE session_id = ?')
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

    // 5. ✅ 修正：使用 ROLE_PRESET.ROOT 判断（值为 -1）
    if (user.permissions !== ROLE_PRESET.ROOT) {
      return new Response(JSON.stringify({ error: '需要 root 权限' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 6. 返回认证上下文
    return {
      currentUser: {
        id: user.id,
        username: user.name,
        permissions: user.permissions,
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