// functions/api/login.ts
import { Env } from '../../types';
import { jsonSuccess, jsonError } from '../../utils/response';
import { parseJsonBody } from '../../utils/parse-json';
import { UserManager } from '../../utils/user-manager';
import type { LogicalUser } from '../../utils/user-manager';

interface LoginRequest {
  identifier: string; // 邮箱或用户名
  password: string;
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
}): Promise<Response> {
  if (request.method !== 'POST') {
    return jsonError('方法不允许', 405);
  }

  try {
    const { identifier, password } = await parseJsonBody<LoginRequest>(request, {
      identifier: 'string',
      password: 'string'
    });

    if (!identifier.trim() || !password.trim()) {
      return jsonError('邮箱/用户名和密码不能为空', 400);
    }

    const userManager = new UserManager(env.DB);

    // 验证密码（支持邮箱或用户名）
    const isValid = await userManager.verifyUserPassword(identifier, password);
    if (!isValid) {
      return jsonError('邮箱/用户名或密码错误', 401);
    }

    // 获取用户信息（verifyUserPassword 已确认存在，此处应不为空）
    let user: LogicalUser | null = null;
    if (identifier.includes('@')) {
      user = await userManager.getUserByEmail(identifier.toLowerCase());
    } else {
      user = await userManager.getUserByName(identifier);
    }

    if (!user || !user.id) {
      // 理论上不会发生，但防御性编程
      console.error('登录成功但无法获取用户信息:', { identifier });
      return jsonError('账户异常，请联系管理员', 500);
    }

    // 创建会话
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7天

    const sessionResult = await env.DB.prepare(
      'INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionId, user.id, expiresAt).run();

    if (!sessionResult.success) {
      console.error('会话创建失败:', sessionResult);
      return jsonError('登录失败，请重试', 500);
    }

    const successResponse = jsonSuccess('登录成功', 200);
    return setAuthCookie(successResponse, sessionId, env.SITE_URL?.startsWith('https://') ?? true);

  } catch (errorResponse: unknown) {
    if (errorResponse instanceof Response) {
      return errorResponse;
    }
    console.error('登录失败:', errorResponse);
    return jsonError('服务器内部错误', 500);
  }
}