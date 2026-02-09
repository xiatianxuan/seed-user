// ./functions/api/set-admin.ts
import type { Env } from '../../types';
import { requireRootUser } from '../../utils/auth-middleware';
import { UserManager } from '../../utils/user-manager';
import { PERM, ROLE_PRESET } from '../../utils/permissions';

interface SetAdminRequestBody {
  id?: number;
  name?: string;      // 注意：这里用 name，不是 username
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
      targetUser = await userManager.getUserByName(name);
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
        JSON.stringify({ error: '不能修改自己的权限' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (targetUser.permissions === ROLE_PRESET.ROOT) {
      return new Response(
        JSON.stringify({ error: '不能修改 root 用户的权限' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const newPermissions = revoke 
      ? PERM.READ 
      : (PERM.READ | PERM.WRITE | PERM.DELETE | PERM.MANAGE_USERS);

    const success = await userManager.updatePermissions(targetUser.id, newPermissions);
    if (!success) {
      throw new Error('更新权限失败');
    }

    const actionText = revoke ? '撤销' : '授予';
    const roleText = revoke ? '普通用户' : '管理员';

    return new Response(
      JSON.stringify({
        success: true,
        message: `已${actionText}用户 "${targetUser.name}" 的${roleText}权限`, // ← 用 .name
        user: {
          id: targetUser.id,
          name: targetUser.name,     // ← 不是 username
          email: targetUser.email,
          permissions: newPermissions,
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