// functions/api/users.ts
import { authenticateRequest } from './auth'; // 注意路径是否正确

interface Env {
  DB: D1Database;
}

export async function onRequest({ request, env }: { request: Request; env: Env }) {
  const auth = await authenticateRequest(request, env);
  if (!auth) {
    return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
  }

  const currentUserRole = auth.user.role;

  // 根据当前用户角色决定可查询的角色范围
  let allowedRoles: string[];
  
  if (currentUserRole === 'root') {
    // root 可以查所有角色
    allowedRoles = ['user', 'admin', 'root'];
  } else if (currentUserRole === 'admin') {
    // admin 可以查 user 和自己（但不能查其他 admin 或 root）
    allowedRoles = ['user', 'admin'];
  } else {
    // 普通 user 无权访问此接口（或只能查自己，但通常不允许）
    return new Response(JSON.stringify({ error: '权限不足' }), { status: 403 });
  }

  // 解析查询参数：?roles=admin,user （可选过滤）
  const url = new URL(request.url);
  const rolesParam = url.searchParams.get('roles');
  let filteredRoles: string[] = [];

  if (rolesParam) {
    // 从参数中提取角色，并与 allowedRoles 取交集（防止越权）
    const requestedRoles = rolesParam.split(',').map(r => r.trim().toLowerCase());
    filteredRoles = requestedRoles.filter(r => 
      ['user', 'admin', 'root'].includes(r) && allowedRoles.includes(r)
    );
  }

  // 如果没指定 roles，使用全部允许的角色
  const finalRoles = filteredRoles.length > 0 ? filteredRoles : allowedRoles;

  // 构建安全的 SQL 查询
  const placeholders = finalRoles.map(() => '?').join(',');
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
      created_at DESC
  `;

  const stmt = env.DB.prepare(query);
  const result = await stmt.bind(...finalRoles).all();

  return new Response(JSON.stringify(result.results), {
    headers: { 'Content-Type': 'application/json' }
  });
}