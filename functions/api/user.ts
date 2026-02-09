/*
 * Copyright (C) 2026 xiatianxuan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import { authenticateRequest } from './auth';

// 🔑 权限常量（内联定义，避免依赖外部文件）
const Permission = {
  READ: 1,
  WRITE: 2,
  DELETE: 4,
  MANAGE_USERS: 8,
  ROOT: -1,
} as const;

/**
 * 根据 permissions 值返回可读的角色标签
 */
function getRoleLabel(permissions: number): string {
  if (permissions === Permission.ROOT) {
    return 'root';
  }
  if ((permissions & Permission.MANAGE_USERS) !== 0) {
    return 'admin';
  }
  return 'user';
}

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
  const auth = await authenticateRequest(request, env);

  if (!auth) {
    return new Response(null, { status: 401 });
  }

  const { id, name, email, permissions, created_at } = auth.user;

  return new Response(
    JSON.stringify({
      user: {
        id,
        name,
        email,
        permissions,               // ✅ 返回原始权限值（供前端细粒度控制）
        role: getRoleLabel(permissions), // ✅ 返回可读角色：'root' / 'admin' / 'user'
        created_at,
      }
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    }
  );
}