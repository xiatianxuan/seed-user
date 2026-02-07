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

// ✅ 复用你已有的认证函数
import { authenticateRequest } from './auth';

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
  // 调用通用认证中间件
  const auth = await authenticateRequest(request, env);

  if (!auth) {
    // 未登录：返回 401 Unauthorized
    return new Response(null, { status: 401 });
  }

  // 已登录：返回用户基本信息（不包含敏感字段）
  return new Response(
    JSON.stringify({
      user: {
        id: auth.user.id,
        name: auth.user.name,
        email: auth.user.email
      }
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store' // 防止浏览器缓存敏感信息
      }
    }
  );
}