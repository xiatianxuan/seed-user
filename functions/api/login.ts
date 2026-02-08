// functions/api/login.ts

import { Env } from '../../types';
import { jsonSuccess, jsonError } from '../../utils/response';
import { parseJsonBody } from '../../utils/parse-json';
import { UserManager } from '../../utils/user-manager';

// 👇 内联定义（或从 types 导入）
interface LoginRequest {
  identifier: string; // 邮箱或用户名
  password: string;
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function setAuthCookie(response: Response, sessionId: string, secure: boolean = true): Response {
  response.headers.set(
    'Set-Cookie',
    `session=${sessionId}; Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`
  );
  return response;
}

export async function onRequest({
  request,
  env
}: {
  request: Request;
  env: Env;
  params: Record<string, string>;
}): Promise<Response> {
  if (request.method !== 'POST') {
    return jsonError('方法不允许', 405);
  }

  try {
    const { identifier, password } = await parseJsonBody<LoginRequest>(request, {
      identifier: 'string',
      password: 'string'
    });

    if (identifier.trim() === '' || password.trim() === '') {
      return jsonError('邮箱/用户名和密码不能为空', 400);
    }

    const userManager = new UserManager(env.DB);
    const isValid = await userManager.verifyUserPassword(identifier, password);

    if (!isValid) {
      // ✅ 统一错误提示，防用户枚举
      return jsonError('邮箱/用户名或密码错误', 401);
    }

    // 获取用户信息（用于创建会话）
    let user;
    if (isValidEmail(identifier)) {
      user = await userManager.getUserByEmail(identifier.toLowerCase());
    } else {
      user = await userManager.getUserByUsername(identifier);
    }

    if (!user) {
      return jsonError('账户异常，请联系管理员', 500);
    }

    // 创建会话
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7天

    await env.DB.prepare(
      'INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionId, user.id, expiresAt).run();

    const successResponse = jsonSuccess('登录成功', 200);
    return setAuthCookie(successResponse, sessionId, env.SITE_URL.startsWith('https://'));

  } catch (errorResponse: unknown) {
    if (errorResponse instanceof Response) {
      return errorResponse;
    }
    console.error('登录失败:', errorResponse);
    return jsonError('服务器内部错误', 500);
  }
}