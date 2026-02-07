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
        // 1. 查找有效的 pending 记录
        const pending = await env.DB.prepare(`
            SELECT name, email, password_salt, password_hash, created_at
            FROM pending_registrations
            WHERE token = ? AND expires_at > datetime('now')
        `).bind(token).first();

        if (!pending) {
            return new Response("验证链接已失效或不存在，请重新注册。", { status: 404 });
        }

        // 2. 尝试插入正式用户（可能因并发冲突失败）
        try {
            await env.DB.prepare(`
                INSERT INTO users (name, email, password_salt, password_hash, created_at, role)
                VALUES (?, ?, ?, ?, ?, 'user')
            `).bind(
                pending.name,
                pending.email,
                pending.password_salt,
                pending.password_hash,
                pending.created_at
            ).run();

            // 3. 删除 pending 记录
            await env.DB.prepare("DELETE FROM pending_registrations WHERE token = ?")
                .bind(token).run();

            // 4. 返回成功页面
            return new Response(`
                <!DOCTYPE html>
                <html lang="zh-CN">
                <head>
                    <meta charset="utf-8">
                    <title>验证成功 - Seed</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; text-align: center; padding: 2rem; }
                        .success { color: #10b981; font-size: 1.5rem; margin: 1rem 0; }
                        a { color: #3b82f6; text-decoration: none; margin-top: 1rem; display: inline-block; }
                    </style>
                </head>
                <body>
                    <div class="success">✅ 邮箱验证成功！</div>
                    <p>您现在可以登录 Seed 了。</p>
                    <a href="/login">→ 前往登录</a>
                </body>
                </html>
            `, {
                headers: { "Content-Type": "text/html; charset=utf-8" }
            });

        } catch (e) {
            // 处理极小概率的并发冲突（如两人同时验证相同用户名）
            if (e instanceof Error && e.message.includes('UNIQUE constraint failed')) {
                await env.DB.prepare("DELETE FROM pending_registrations WHERE token = ?")
                    .bind(token).run();
                return new Response("该账号已被他人注册，请重新尝试。", { status: 409 });
            }
            throw e;
        }

    } catch (error) {
        console.error("邮箱验证失败:", error);
        return new Response("服务器内部错误，请稍后重试。", { status: 500 });
    }
}