// utils/parse-json.ts

import { jsonError } from './response';

/**
 * 安全解析 JSON 请求体，并验证必需字段类型
 * 
 * @template T - 期望的请求体类型（由调用方显式指定）
 * @param request - 原始 Request 对象
 * @param requiredFields - 字段名到类型的映射（仅用于运行时校验）
 * @returns Promise<T>
 */
export async function parseJsonBody<T extends Record<string, any>>(
  request: Request,
  requiredFields: { [K in keyof T]: 'string' | 'number' | 'boolean' }
): Promise<T> {
  const contentType = request.headers.get('content-type')?.toLowerCase();
  if (!contentType || !contentType.includes('application/json')) {
    throw jsonError('请求头 Content-Type 必须为 application/json', 400);
  }

  let parsed: unknown;
  try {
    parsed = await request.json();
  } catch {
    throw jsonError('请求体不是有效的 JSON 格式', 400);
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw jsonError('请求体必须是一个 JSON 对象', 400);
  }

  const body = parsed as Record<string, unknown>;
  for (const field in requiredFields) {
    if (!(field in body)) {
      throw jsonError(`缺少必需字段: ${String(field)}`, 400);
    }
    const expectedType = requiredFields[field];
    const value = body[field];
    if (typeof value !== expectedType) {
      throw jsonError(
        `字段 "${String(field)}" 必须是 ${expectedType} 类型`,
        400
      );
    }
  }

  return body as T;
}