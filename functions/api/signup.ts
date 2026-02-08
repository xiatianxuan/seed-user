// functions/api/signup.ts

import { Env } from '../../types';
import {
  generateSalt,
  computePasswordHash,
  uint8ArrayToHex,
} from '../../utils/password';
import { sendEmail } from '../../utils/sendEmail';
import { jsonSuccess, jsonError } from '../../utils/response';
import { parseJsonBody } from '../../utils/parse-json';
import { PendingRegistrationManager } from '../../utils/pending-manager';

// 👇 若未创建 types/index.ts，可在此内联定义
interface SignupRequest {
  name: string;
  email: string;
  password: string;
}

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

function getBeijingTimeString(offsetMinutes = 0): string {
  const now = Date.now() + 8 * 3600 * 1000 + offsetMinutes * 60 * 1000;
  return new Date(now).toISOString().slice(0, 19).replace('T', ' ');
}

export async function onRequest({
  request,
  env,
  waitUntil,
}: {
  request: Request;
  env: Env;
  params: Record<string, string>;
  waitUntil: (promise: Promise<any>) => void;
}): Promise<Response> {
  if (request.method !== 'POST') {
    return jsonError('方法不允许', 405);
  }

  try {
    const { name, email, password } = await parseJsonBody<SignupRequest>(request, {
      name: 'string',
      email: 'string',
      password: 'string',
    });

    const validName = validateUsername(name);
    if (!validName) {
      return jsonError(
        '用户名长度必须为 1-15 个字符，仅允许中文、小写字母、数字、下划线（_）或连字符（-），且不能全部为数字',
        400
      );
    }

    if (!isValidEmail(email)) {
      return jsonError('邮箱格式不正确', 400);
    }

    if (password.length < 12) {
      return jsonError('密码长度必须不少于 12 个字符', 400);
    }

    if (hasChineseChar(password)) {
      return jsonError('密码不能包含中文字符', 400);
    }

    const pendingManager = new PendingRegistrationManager(env.DB);

    // 检查是否已存在（用户或待注册）
    const existingUser = await env.DB
      .prepare(`SELECT 1 FROM users WHERE email = ? OR name = ?`)
      .bind(email.toLowerCase(), validName)
      .first();

    const pendingExists = await pendingManager.existsPending(email.toLowerCase(), validName);

    if (existingUser || pendingExists) {
      return jsonError('该邮箱或用户名已被使用', 409);
    }

    // ✅ 生成盐和哈希（分离存储）
    const salt = generateSalt();
    const hash = await computePasswordHash(password, salt);
    const passwordSaltHex = uint8ArrayToHex(salt);
    const passwordHashHex = uint8ArrayToHex(hash);

    const token = crypto.randomUUID();
    const nowBeijing = getBeijingTimeString();
    const expiresBeijing = getBeijingTimeString(5); // 5分钟后过期

    // ✅ 传入 passwordHash 和 passwordSalt（hex 字符串）
    await pendingManager.createPendingRegistration({
      username: validName,
      email: email.toLowerCase(),
      passwordHash: passwordHashHex,
      passwordSalt: passwordSaltHex,
      token,
      createdAt: nowBeijing,
      expiresAt: expiresBeijing,
    });

    const verifyUrl = `${env.SITE_URL}/api/verify-email?token=${encodeURIComponent(token)}`;
    const emailPromise = sendEmail(
      {
        to: email,
        subject: '请验证您的邮箱 - Seed',
        html: `
          <p>您好！</p>
          <p>您正在注册 Seed 账号，请点击下方链接完成邮箱验证：</p>
          <p><a href="${verifyUrl}" style="display:inline-block;padding:10px 20px;background:#3b82f6;color:white;text-decoration:none;border-radius:6px;">验证邮箱</a></p>
          <p>该链接将在 5 分钟后失效。</p>
          <p>如果您未进行此操作，请忽略此邮件。</p>
        `,
      },
      {
        RESEND_API_KEY: env.RESEND_API_KEY,
        FROM_EMAIL: env.FROM_EMAIL,
      }
    ).then((result) => {
      if (!result.success) {
        console.error('邮件发送失败:', result.error);
      } else {
        console.log('验证邮件已发送至:', email);
      }
    });

    waitUntil(emailPromise);
    return jsonSuccess('验证邮件已发送，有效期5分钟，请注意查收。', 201);
  } catch (errorResponse: unknown) {
    if (errorResponse instanceof Response) {
      return errorResponse;
    }
    console.error('注册失败:', errorResponse);
    return jsonError('服务器内部错误，请稍后重试', 500);
  }
}