// utils/sendEmail.ts

interface ResendSuccessResponse {
  id: string;
  from: string;
  to: string[];
  created_at: string;
}

interface ResendErrorResponse {
  name: string;
  message: string;
  statusCode: number;
}

interface ResendResponse {
  data?: ResendSuccessResponse;
  error?: ResendErrorResponse;
}

// 👇 所有需要在外部使用的类型都必须加 export
export interface SendEmailParams {
  to: string | string[];
  subject: string;
  html: string;
}

export interface EmailEnv {
  RESEND_API_KEY: string;
  FROM_EMAIL: string;
}

export interface SendEmailResult {
  success: boolean;
  error?: string;
  data?: ResendResponse;
}

/**
 * 发送邮件的工具函数（适配 Cloudflare Pages Functions / Workers）
 */
export async function sendEmail(
  { to, subject, html }: SendEmailParams,
  env: EmailEnv
): Promise<SendEmailResult> {
  // 参数校验
  if (
    !to ||
    (Array.isArray(to) && to.length === 0) ||
    !subject ||
    html === undefined
  ) {
    return { success: false, error: "Missing fields: to, subject, html" };
  }

  const recipients = Array.isArray(to) ? to : [to];
  const from = env.FROM_EMAIL;

  if (!env.RESEND_API_KEY || !from) {
    return {
      success: false,
      error: "Email service misconfigured (missing env vars)",
    };
  }

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from,
        to: recipients,
        subject,
        html,
      }),
    });

    const data = (await response.json()) as ResendResponse;

    if (!response.ok) {
      const errorMsg = data.error?.message || "Failed to send email via Resend";
      return { success: false, error: errorMsg, data };
    }

    return { success: true, data };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : "Unknown error during email sending",
    };
  }
}