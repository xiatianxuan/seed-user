// types/index.ts

/**
 * Cloudflare Workers 环境变量类型定义
 * 必须与 wrangler.toml 中的 [vars] 和 [[d1_databases]] 保持一致
 */
export interface Env {
  DB: D1Database;           // D1 数据库绑定
  RESEND_API_KEY: string;   // Resend API 密钥
  FROM_EMAIL: string;       // 发件邮箱（如: noreply@yourdomain.com）
  SITE_URL: string;         // 网站 URL（如: https://yourdomain.com）
}