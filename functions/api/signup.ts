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

import { sendEmail, type SendEmailResult } from '../../utils/sendEmail';

// ✅ 生成北京时间字符串 (格式: "2026-02-07 17:30:00")
function getBeijingTimeString(offsetMinutes = 0): string {
    const now = Date.now() + 8 * 3600 * 1000 + offsetMinutes * 60 * 1000;
    return new Date(now)
        .toISOString()
        .slice(0, 19)
        .replace('T', ' ');
}

// ✅ 完整定义 Env 接口：包含 D1 + 所有环境变量
interface Env {
    DB: D1Database;
    RESEND_API_KEY: string;
    FROM_EMAIL: string;
    SITE_URL: string;
}

// --- 工具函数（保持不变）---
function isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hasChineseChar(str: string): boolean {
    return /[\u4e00-\u9fa5]/.test(str);
}

function validateUsername(name: string): string | null {
    const trimmed = name.trim();
    if (trimmed.length === 0 || trimmed.length > 15) return null;
    if (!/^[\u4e00-\u9fa5a-z0-9_-]+$/.test(trimmed)) return null;
    if (/^\d+$/.test(trimmed)) return null;
    return trimmed;
}

async function hashPassword(password: string): Promise<{ salt: string; hash: string }> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey("raw", data, { name: "PBKDF2" }, false, ["deriveBits"]);
    const derivedBits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-512" },
        key,
        256
    );
    const saltB64 = btoa(String.fromCharCode(...salt));
    const hashB64 = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));
    return { salt: saltB64, hash: hashB64 };
}

// --- 主处理函数 ---
export async function onRequest({
    request,
    env,
    waitUntil
}: {
    request: Request;
    env: Env;
    params: Record<string, string>;
    waitUntil: (promise: Promise<any>) => void;
}): Promise<Response> {
    if (request.method !== "POST") {
        return new Response(JSON.stringify({ error: "方法不允许" }), {
            status: 405,
            headers: { "Content-Type": "application/json" }
        });
    }

    const contentType = request.headers.get("content-type");
    if (!contentType?.includes("application/json")) {
        return new Response(JSON.stringify({ error: "请求头 Content-Type 必须为 application/json" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        });
    }

    let body;
    try {
        body = await request.json();
    } catch {
        return new Response(JSON.stringify({ error: "请求体不是有效的 JSON 格式" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        });
    }

    const { name, email, password } = body as { name: string; email: string; password: string };

    if (typeof name !== "string" || typeof email !== "string" || typeof password !== "string") {
        return new Response(JSON.stringify({ error: "用户名、邮箱和密码必须是字符串" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        });
    }

    if (!name || !email || !password) {
        return new Response(JSON.stringify({ error: "用户名、邮箱和密码不能为空" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        });
    }

    const validName = validateUsername(name);
    if (!validName) {
        return new Response(JSON.stringify({
            error: "用户名长度必须为 1-15 个字符，仅允许中文、小写字母、数字、下划线（_）或连字符（-），且不能全部为数字"
        }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        });
    }

    if (!isValidEmail(email)) {
        return new Response(JSON.stringify({ error: "邮箱格式不正确" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        });
    }

    if (password.length < 12) {
        return new Response(JSON.stringify({ error: "密码长度必须不少于 12 个字符" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        });
    }

    if (hasChineseChar(password)) {
        return new Response(JSON.stringify({ error: "密码不能包含中文字符" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        });
    }

    try {
        // ✅ 关键修改：同时检查 users 和 pending_registrations 表
        const existingRecord = await env.DB.prepare(`
            SELECT 1 FROM users WHERE email = ? OR name = ?
            UNION ALL
            SELECT 1 FROM pending_registrations WHERE email = ? OR name = ?
            LIMIT 1
        `).bind(
            email.toLowerCase(),
            validName,
            email.toLowerCase(),
            validName
        ).first();

        if (existingRecord) {
            return new Response(JSON.stringify({ error: "该邮箱或用户名已被使用" }), {
                status: 409,
                headers: { "Content-Type": "application/json" }
            });
        }

        // ✅ 哈希密码
        const { salt, hash } = await hashPassword(password);

        // ✅ 生成唯一 token
        const token = crypto.randomUUID();

        // ✅ 获取当前时间和5分钟后的时间（都是北京时间）
        const createdAtBeijing = getBeijingTimeString();     // 现在
        const expiresAtBeijing = getBeijingTimeString(5);   // +5分钟

        await env.DB.prepare(`
        INSERT INTO pending_registrations (
        name, email, password_salt, password_hash, token, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
            validName,
            email.toLowerCase(),
            salt,
            hash,
            token,
            createdAtBeijing,   // ← 新增
            expiresAtBeijing
        ).run();

        // ✅ 构造验证链接（指向 /api/verify-email）
        const verifyUrl = `${env.SITE_URL}/api/verify-email?token=${encodeURIComponent(token)}`;

        // ✅ 发送验证邮件
        const emailPromise = sendEmail(
            {
                to: email,
                subject: "请验证您的邮箱 - Seed",
                html: `
                    <p>您好！</p>
                    <p>您正在注册 Seed 账号，请点击下方链接完成邮箱验证：</p>
                    <p><a href="${verifyUrl}" style="display:inline-block;padding:10px 20px;background:#3b82f6;color:white;text-decoration:none;border-radius:6px;">验证邮箱</a></p>
                    <p>该链接将在 5 分钟后失效。</p>
                    <p>如果您未进行此操作，请忽略此邮件。</p>
                `
            },
            {
                RESEND_API_KEY: env.RESEND_API_KEY,
                FROM_EMAIL: env.FROM_EMAIL
            }
        ).then((result: SendEmailResult) => {
            if (!result.success) {
                console.error("邮件发送失败:", result.error);
            } else {
                console.log("验证邮件已发送至:", email);
            }
        });

        waitUntil(emailPromise);

        return new Response(JSON.stringify({
            success: true,
            message: "验证邮件已发送，有效期5分钟，请注意查收。"
        }), {
            status: 201,
            headers: { "Content-Type": "application/json" }
        });

    } catch (error) {
        console.error("注册失败:", error);
        return new Response(JSON.stringify({ error: "服务器内部错误，请稍后重试" }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }
}