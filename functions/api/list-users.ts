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

const Permission = {
  READ: 1,
  WRITE: 2,
  DELETE: 4,
  MANAGE_USERS: 8,
  ROOT: -1,
} as const;

function getRoleLabel(permissions: number): 'user' | 'admin' | 'root' {
  if (permissions === Permission.ROOT) return 'root';
  if ((permissions & Permission.MANAGE_USERS) !== 0) return 'admin';
  return 'user';
}

function isRoot(permissions: number): boolean {
  return permissions === Permission.ROOT;
}

function isAdminOrRoot(permissions: number): boolean {
  return isRoot(permissions) || (permissions & Permission.MANAGE_USERS) !== 0;
}

// 🔑 新增：角色排序权重
const ROLE_PRIORITY: Record<'root' | 'admin' | 'user', number> = {
  root: 0,
  admin: 1,
  user: 2,
};

interface Env {
  DB: D1Database;
}

export async function onRequest({ request, env }: { request: Request; env: Env }) {
  const auth = await authenticateRequest(request, env);
  if (!auth) {
    return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
  }

  const currentUserPermissions = auth.user.permissions;

  if (!isAdminOrRoot(currentUserPermissions)) {
    return new Response(JSON.stringify({ error: '权限不足' }), { status: 403 });
  }

  // 查询所有用户（无 role 字段）
  const usersResult = await env.DB.prepare(`
    SELECT id, name, email, permissions, created_at
    FROM users
    ORDER BY created_at DESC  -- 先按时间排，后续会覆盖
  `).all<{ 
    id: number; 
    name: string; 
    email: string; 
    permissions: number; 
    created_at: string; 
  }>();

  const url = new URL(request.url);
  const rolesParam = url.searchParams.get('roles');
  let requestedRoles: Set<string> | null = null;

  if (rolesParam) {
    requestedRoles = new Set(
      rolesParam.split(',').map(r => r.trim().toLowerCase())
        .filter(r => ['user', 'admin', 'root'].includes(r))
    );
  }

  // 添加 role 标签 + 过滤
  const filteredUsers = usersResult.results
    .map(user => ({
      ...user,
      role: getRoleLabel(user.permissions),
    }))
    .filter(user => {
      if (isRoot(currentUserPermissions)) {
        return !requestedRoles || requestedRoles.has(user.role);
      }
      if (user.role === 'root') return false;
      return !requestedRoles || requestedRoles.has(user.role);
    });

  // ✅ 关键：按 root → admin → user 排序，同角色内按创建时间倒序
  filteredUsers.sort((a, b) => {
    const priorityA = ROLE_PRIORITY[a.role];
    const priorityB = ROLE_PRIORITY[b.role];

    if (priorityA !== priorityB) {
      return priorityA - priorityB; // root(0) < admin(1) < user(2)
    }

    // 同角色：新用户在前（created_at 降序）
    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  });

  return new Response(JSON.stringify(filteredUsers), {
    headers: { 'Content-Type': 'application/json' }
  });
}