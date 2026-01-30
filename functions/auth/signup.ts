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

// 定义环境类型
interface Env {
    DB: D1Database;
}

// 工具函数： 验证邮箱格式
function isValidEmail(email: string): boolean {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// 工具函数： 标准化用户名
function validateUsername(name: string): string | null {
    const trimmed = name.trim().toLowerCase();

    if (trimmed.length === 0 || trimmed.length > 15) return null;
    if (!/^[a-z0-9_-]+$/.test(trimmed)) return null;
    if (/^\d+$/.test(trimmed)) return null;
    return trimmed;
}

// 工具函数：生成密码哈希和盐（分离存储）
async function hashPassword(password: string): Promise<{ salt: string; hash: string }> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);

  // 生成 16 字节随机盐
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // 导入原始密码作为密钥材料
  const key = await crypto.subtle.importKey(
    "raw",
    data,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  // 派生 256 位（32字节）哈希
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100_000,
      hash: "SHA-256"
    },
    key,
    256
  );

  // 分别 Base64 编码 salt 和 hash
  const saltB64 = btoa(String.fromCharCode(...salt));
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));

  return { salt: saltB64, hash: hashB64 };
}

export async function onRequest({
    request,
    env
}: {
    request: Request;
    env: Env;
    params: Record<string, string>;
    waitUntil: (promise: Promise<any>) => void;
}): Promise<Response> {
    // 只允许 POST 请求
    if (request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
    }

    // 只接受 JSON
    const contentType = request.headers.get("content-type");
    if (!contentType || !contentType.includes("application/json")) {
        return new Response(
            JSON.stringify({ error: "Content-Type must be application/json" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
        );
    }

    // 解析请求体
    let body;
    try {
        body = await request.json();
    } catch (e) {
        return new Response(
            JSON.stringify({ error: "Invalid JSON" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
        );
    }

    if (
        typeof body !== "object" ||
        body === null ||
        !("email" in body) ||
        !("password" in body) ||
        !("name" in body)
    ) {
        return new Response(JSON.stringify({ error: "Missing name, email or password" }),
            {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
    }
    const { name, email, password } = body as { name: unknown, email: unknown; password: unknown };

    if (typeof email !== "string" || typeof password !== "string" || typeof name !== "string") {
        return new Response(JSON.stringify({ error: "Name, email and password must be strings" }),
            {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
    }

    // 输入验证
    if (!email || !password || !name) {
        return new Response(
            JSON.stringify({ error: "Missing name, email or password" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
        );
    }
    const validName = validateUsername(name);
    if (!validName) {
        return new Response(JSON.stringify({
            error: "Username must be 1-15 lowercase letters, digits, underscores or hyphens (not all digits)."
        }), { status: 400 });
    }

    if (!isValidEmail(email)) {
        return new Response(
            JSON.stringify({ error: "Invalid email format" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
        );
    }



    if (password.length < 12) {
        return new Response(
            JSON.stringify({ error: "Password must be at least 12 characters" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
        );
    }

    try {
        // 检查邮箱是否已存在
        const existingEmail = await env.DB
            .prepare("SELECT id FROM users WHERE email = ?")
            .bind(email.toLowerCase())
            .first();

        if (existingEmail) {
            return new Response(
                JSON.stringify({ error: "Email already registered" }),
                { status: 409, headers: { "Content-Type": "application/json" } }
            );
        }

        const existingName = await env.DB
            .prepare("SELECT id FROM users WHERE name = ?")
            .bind(validName)
            .first();

        if (existingName) {
            return new Response(
                JSON.stringify({ error: "Name already registered" }),
                { status: 409, headers: { "Content-Type": "application/json" } }
            );
        }

        // 哈希密码
        const { salt, hash } = await hashPassword(password);

        // 插入新用户（邮箱转小写存储， 避免大小写问题）
        await env.DB
            .prepare(
                "INSERT INTO users (name, email, password_salt, password_hash, created_at, role) VALUES (?, ?, ?, ?, datetime('now'), 'user')"
            )
            .bind(validName, email.toLowerCase(), salt, hash)
            .run();

        // 返回成功
        return new Response(
            JSON.stringify({
                success: true,
                message: "User registered successfully",
                user: { email: email.toLowerCase() }
            }),
            {
                status: 201,
                headers: { "Content-Type": "application/json" }
            }
        );
    } catch (error) {
        console.error("Signup error:", error);

        // 防止泄露内部错误
        return new Response(JSON.stringify({ error: "Internal server error" }),
            { status: 500, headers: { "Content-Type": "application/json" } }
        );
    }
}