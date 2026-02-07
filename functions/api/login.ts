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

interface UserRecord {
  id: number;
  name: string;
  email: string;
  password_salt: string;
  password_hash: string;
}

interface Env {
  DB: D1Database;
}

async function verifyPassword(
  inputPassword: string,
  storedSalt: string,
  storedHash: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const salt = Uint8Array.from(atob(storedSalt), c => c.charCodeAt(0));
  const data = encoder.encode(inputPassword);

  const key = await crypto.subtle.importKey("raw", data, { name: "PBKDF2" }, false, ["deriveBits"]);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-512" },
    key,
    256
  );
  const computedHash = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));
  return computedHash === storedHash;
}

export async function onRequest({
  request,
  env
}: {
  request: Request;
  env: Env;
}): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: '方法不允许' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const contentType = request.headers.get('content-type');
  if (!contentType?.includes('application/json')) {
    return new Response(JSON.stringify({ error: 'Content-Type 必须为 application/json' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: '无效的 JSON 格式' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const { identifier, password } = body as { identifier: string; password: string };

  if (!identifier || !password) {
    return new Response(JSON.stringify({ error: '请输入用户名/邮箱和密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    // ✅ 支持用户名或邮箱登录
    const user = await env.DB.prepare(`
      SELECT id, name, email, password_salt, password_hash
      FROM users
      WHERE email = ? OR name = ?
    `).bind(
      identifier.toLowerCase().includes('@') ? identifier.toLowerCase() : identifier,
      identifier
    ).first<UserRecord>();

    // ⚠️ 统一错误提示（防用户枚举）
    if (!user || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
      return new Response(JSON.stringify({ error: '用户名或密码错误' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // ✅ 生成唯一 session ID
    const sessionId = crypto.randomUUID();

    // ✅ 【关键修复】使用标准 UTC ISO 时间戳（与 auth.ts 兼容）
    const expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();

    // ✅ 存入 sessions 表
    await env.DB.prepare(`
      INSERT INTO sessions (session_id, user_id, expires_at)
      VALUES (?, ?, ?)
    `).bind(sessionId, user.id, expiresAt).run();

    // ✅ 判断是否为本地开发环境（HTTP）
    const isLocal = request.url.includes('localhost') || request.url.includes('127.0.0.1');

    const cookieParts = [
      `session=${sessionId}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${7 * 24 * 3600}`
    ];

    if (!isLocal) {
      cookieParts.push('Secure'); // 仅在线上 HTTPS 环境启用 Secure
    }

    return new Response(JSON.stringify({
      success: true,
      user: { id: user.id, name: user.name, email: user.email }
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': cookieParts.join('; ')
      }
    });

  } catch (error) {
    console.error('登录失败:', error);
    return new Response(JSON.stringify({ error: '服务器内部错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}