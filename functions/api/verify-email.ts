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

// ✅ 获取当前北京时间字符串 (格式: "2026-02-07 17:30:00")
function getBeijingTimeString(): string {
    return new Date(Date.now() + 8 * 3600 * 1000)
        .toISOString()
        .slice(0, 19)
        .replace('T', ' ');
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
    if (request.method !== "GET") {
        return new Response("方法不允许", { status: 405 });
    }

    const url = new URL(request.url);
    const token = url.searchParams.get("token");

    if (!token || typeof token !== "string") {
        return new Response("无效的验证链接", { status: 400 });
    }

    try {
        // ✅ 获取当前北京时间（用于与 SQLite 的 datetime 比较）
        const nowBeijing = getBeijingTimeString();

        // 查询未过期的待注册记录
        const pending = await env.DB.prepare(`
            SELECT name, email, password_salt, password_hash, created_at
            FROM pending_registrations
            WHERE token = ? AND datetime(expires_at) > datetime(?)
        `).bind(token, nowBeijing).first<{
            name: string;
            email: string;
            password_salt: string;
            password_hash: string;
            created_at: string;
        }>();

        if (!pending) {
            return new Response("验证链接已失效或不存在，请重新注册。", { status: 404 });
        }

        // 尝试将用户转正到 users 表（使用 permissions，不再使用 role）
        try {
            await env.DB.prepare(`
                INSERT INTO users (
                    name,
                    email,
                    password_salt,
                    password_hash,
                    permissions,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            `).bind(
                pending.name,
                pending.email,
                pending.password_salt,
                pending.password_hash,
                1, // ← 默认权限：普通用户（READ）。可根据需要改为 Permission.USER
                pending.created_at
            ).run();

            // 清理 pending 记录
            await env.DB.prepare("DELETE FROM pending_registrations WHERE token = ?")
                .bind(token)
                .run();

            // 返回成功页面
            return new Response(`
                <!DOCTYPE html>
                <html lang="zh-CN">
                <head>
                    <meta charset="utf-8">
                    <title>验证成功 - Seed</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                            text-align: center;
                            padding: 2rem;
                            background: #f9fafb;
                            color: #1f2937;
                        }
                        .success {
                            color: #10b981;
                            font-size: 1.5rem;
                            margin: 1rem 0;
                            font-weight: 600;
                        }
                        p {
                            margin: 0.5rem 0 1.5rem;
                            color: #4b5563;
                        }
                        a {
                            display: inline-block;
                            margin-top: 1rem;
                            padding: 0.5rem 1.5rem;
                            background: #3b82f6;
                            color: white;
                            text-decoration: none;
                            border-radius: 0.375rem;
                            font-weight: 500;
                            transition: background 0.2s;
                        }
                        a:hover {
                            background: #2563eb;
                        }
                    </style>
                </head>
                <body>
                    <div class="success">✅ 邮箱验证成功！</div>
                    <p>您的账号已激活，现在可以登录 Seed 了。</p>
                    <a href="/login">→ 前往登录</a>
                </body>
                </html>
            `, {
                headers: { "Content-Type": "text/html; charset=utf-8" }
            });

        } catch (e) {
            // 处理唯一性冲突（如用户名或邮箱重复）
            if (e instanceof Error && e.message.includes('UNIQUE constraint failed')) {
                // 清理无效 pending
                await env.DB.prepare("DELETE FROM pending_registrations WHERE token = ?")
                    .bind(token)
                    .run();
                return new Response("该用户名或邮箱已被注册，请重新尝试。", { status: 409 });
            }

            // 其他错误（如 SQL 语法、字段不存在等）向上抛出
            throw e;
        }

    } catch (error) {
        console.error("📧 邮箱验证失败:", error);
        return new Response("服务器内部错误，请稍后重试。", { status: 500 });
    }
}