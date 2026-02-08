// ./functions/api/set-admin.ts
import type { Env } from '../../types';
import { requireRootUser } from '../../utils/auth-middleware';
import { UserManager } from '../../utils/user-manager';



interface SetAdminRequestBody {
  id?: number;
  name?: string;
  email?: string;
  revoke?: boolean;
}

export async function onRequest({
  request,
  env,
  ctx,
}: {
  request: Request;
  env: Env;
  ctx: ExecutionContext;
}): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(
      JSON.stringify({ error: '仅支持 POST 方法' }),
      {
        status: 405,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  const authResult = await requireRootUser(request, env);
  if (authResult instanceof Response) {
    return authResult;
  }

  try {
    const body = (await request.json()) as SetAdminRequestBody;
    const { id, name, email, revoke = false } = body;

    if (!id && !name && !email) {
      return new Response(
        JSON.stringify({
          error: '必须提供 id、name 或 email 中的一个',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const userManager = new UserManager(env.DB);

    let targetUser = null;
    if (id !== undefined) {
      targetUser = await userManager.getUserById(id);
    } else if (name) {
      targetUser = await userManager.getUserByUsername(name);
    } else if (email) {
      targetUser = await userManager.getUserByEmail(email);
    }

    if (!targetUser || !targetUser.id) {
      return new Response(
        JSON.stringify({ error: '用户不存在' }),
        { status: 404, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (targetUser.id === authResult.currentUser.id) {
      return new Response(
        JSON.stringify({ error: '不能修改自己的角色' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (targetUser.role === 'root') {
      return new Response(
        JSON.stringify({ error: '不能修改 root 用户的角色' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const newRole = revoke ? 'user' : 'admin';

    const result = await env.DB.prepare(
      'UPDATE users SET role = ? WHERE id = ?'
    )
      .bind(newRole, targetUser.id)
      .run();

    if (!result.success) {
      throw new Error('数据库更新失败');
    }

    const actionText = revoke ? '撤销' : '授予';
    const roleText = revoke ? '普通用户' : '管理员';

    return new Response(
      JSON.stringify({
        success: true,
        message: `已${actionText}用户 "${targetUser.username}" 的${roleText}权限`,
        user: {
          id: targetUser.id,
          username: targetUser.username,
          email: targetUser.email,
          role: newRole,
        },
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (err) {
    console.error('Set admin error:', err);
    return new Response(
      JSON.stringify({ error: '操作失败，请重试' }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }
}