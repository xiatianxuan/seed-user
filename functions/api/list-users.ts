// functions/api/users.ts
import { authenticateRequest } from './auth';

interface Env {
  DB: D1Database;
}

export async function onRequest({ request, env }: { request: Request; env: Env }) {
  const auth = await authenticateRequest(request, env);
  if (!auth) {
    return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
  }

  // 解析查询参数：?roles=admin,root
  const url = new URL(request.url);
  const rolesParam = url.searchParams.get('roles');
  let roles: string[] = [];

  if (rolesParam) {
    roles = rolesParam.split(',').map(r => r.trim()).filter(r => ['user', 'admin', 'root'].includes(r));
  }

  // 如果没指定 roles，默认只返回 admin + root（安全）
  if (roles.length === 0) {
    roles = ['admin', 'root'];
  }

  // 构建 SQL IN 条件
  const placeholders = roles.map(() => '?').join(',');
  const query = `
    SELECT id, name, email, role, created_at
    FROM users
    WHERE role IN (${placeholders})
    ORDER BY 
      CASE role 
        WHEN 'root' THEN 1 
        WHEN 'admin' THEN 2 
        ELSE 3 
      END,
      id
  `;

  const stmt = env.DB.prepare(query);
  const result = await stmt.bind(...roles).all();

  return new Response(JSON.stringify(result.results), {
    headers: { 'Content-Type': 'application/json' }
  });
}