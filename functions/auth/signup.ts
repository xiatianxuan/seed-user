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

// 工具函数： 生成密码哈希（使用 PBKDF2 + SHA-256）
async function hashPassword(password: string): Promise<string> {
    // 将密码转为 Uint8Array
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    // 生成随机盐（16 字节）
    const salt = crypto.getRandomValues(new Uint8Array(16));

    // 使用 PBKDF2 算法派生密钥
    const key = await crypto.subtle.importKey(
        "raw",
        data,
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        key,
        256
    );

    // 合并 salt + hash, Base64 编码存储
    const hashArray = new Uint8Array(derivedBits);
    const combined = new Uint8Array(salt.length + hashArray.length);
    combined.set(salt);
    combined.set(hashArray, salt.length);

    return btoa(String.fromCharCode(...combined));
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
            JSON.stringify({ error: "Content-Type must be application/json"}),
            { status: 400, headers: { "Content-Type": "application/json" } }
        );
    }

    // 解析请求体
    let body;
    try {
        body = await request.json();
    } catch(e) {
        return new Response(
            JSON.stringify({ error: "Invalid JSON" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
        );
    }

    if (
        typeof body !== "object" ||
        body === null ||
        !("email" in body) ||
        !("password" in body)
    ) {
        return new Response(JSON.stringify({ error: "Missing email or password" }),
    {
        status: 400,
        headers: { "Content-Type": "application/json" }
    });
    }
    const { email, password } = body as { email: unknown; password: unknown };

    if (typeof email !== "string" || typeof password !== "string") {
        return new Response(JSON.stringify({ error: "Email and password must be strings" }),
    {
        status: 400,
        headers: { "Content-Type": "application/json" }
    });
    }

    // 输入验证
    if (!email || !password) {
        return new Response(
            JSON.stringify({ error: "Missing email or password" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
        );
    }

    if (!isValidEmail(email)) {
        return new Response(
            JSON.stringify({ error: "Invalid email format" }),
            { status:400, headers: { "Content-Type": "application/json" } }
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
        const existing = await env.DB
        .prepare("SELECT id FROM users WHERE email = ?")
        .bind(email.toLowerCase())
        .first();

        if (existing) {
            return new Response(
                JSON.stringify({ error: "Email already registered" }),
                { status:409, headers: { "Content-Type": "application/json" } }
            );
        }

        // 哈希密码
        const passwordHash = await hashPassword(password);

        // 插入新用户（邮箱转小写存储， 避免大小写问题）
        await env.DB
        .prepare(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, datetime('now'))"
        )
        .bind(email.toLowerCase(), passwordHash)
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
                headers: { "Content-Type": "application/json"}
            }
        );
    } catch (error) {
        console.error("Signup error:", error);

        // 防止泄露内部错误
        return new Response(
            JSON.stringify({ error: "Internal server error"}),
            { status: 500, headers: { "Content-Type": "application/json" } }
        );
    }
}