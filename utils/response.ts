/**
 * @file response.ts
 * @description 统一的 HTTP JSON 响应生成工具
 * 
 * 本模块提供标准化的成功与错误响应函数，确保所有 API 端点返回一致的 JSON 格式，
 * 包含明确的 success/error 标识、可读消息和结构化数据。
 * 
 * 设计原则：
 * - 所有响应均为 application/json; charset=utf-8
 * - 成功响应包含 { success: true, ...data }
 * - 错误响应包含 { success: false, error: string }
 * - 避免直接使用 new Response()，减少样板代码
 * 
 * @example
 * // 成功响应（200）
 * return jsonSuccess({ user: { id: 1, name: '张三' } });
 * 
 * // 成功响应（201 Created）
 * return jsonSuccess("用户创建成功", 201);
 * 
 * // 客户端错误（400 Bad Request）
 * return jsonError("邮箱格式不正确");
 * 
 * // 服务器错误（500 Internal Server Error）
 * return jsonError("数据库连接失败", 500);
 */

/**
 * 生成成功的 JSON 响应（HTTP 2xx）
 * 
 * 此函数用于返回操作成功的标准响应。你可以传入：
 * - 一个字符串消息（将被包装为 { message: "..." }）
 * - 或一个对象（将被合并到响应体中）
 * 
 * 响应体始终包含 `success: true` 字段。
 * 
 * @param data - 要返回的数据。可以是：
 *   - `string`：将作为 `{ message: data }` 返回
 *   - `Record<string, any>`：将直接合并到响应体中
 * @param status - HTTP 状态码，默认为 200（OK）
 * @returns Response 对象，Content-Type 为 application/json; charset=utf-8
 * 
 * @example
 * // 返回简单消息
 * jsonSuccess("注册成功", 201);
 * // => { "success": true, "message": "注册成功" }
 * 
 * @example
 * // 返回结构化数据
 * jsonSuccess({ token: "abc123", expires_in: 3600 });
 * // => { "success": true, "token": "abc123", "expires_in": 3600 }
 */
export function jsonSuccess(
  data: string | Record<string, any>,
  status: number = 200
): Response {
  const body = typeof data === 'string'
    ? { message: data }
    : { ...data };

  return new Response(
    JSON.stringify({
      success: true,
      ...body
    }),
    {
      status,
      headers: {
        'Content-Type': 'application/json; charset=utf-8'
      }
    }
  );
}

/**
 * 生成错误的 JSON 响应（HTTP 4xx / 5xx）
 * 
 * 此函数用于返回操作失败的标准响应。错误信息将被放在 `error` 字段中。
 * 
 * 响应体始终包含 `success: false` 字段。
 * 
 * @param message - 错误描述信息（用户可读）
 * @param status - HTTP 状态码，默认为 400（Bad Request）
 * @returns Response 对象，Content-Type 为 application/json; charset=utf-8
 * 
 * @example
 * // 客户端输入错误
 * jsonError("密码长度不足", 400);
 * // => { "success": false, "error": "密码长度不足" }
 * 
 * @example
 * // 服务器内部错误
 * jsonError("邮件服务不可用", 500);
 * // => { "success": false, "error": "邮件服务不可用" }
 */
export function jsonError(
  message: string,
  status: number = 400
): Response {
  return new Response(
    JSON.stringify({
      success: false,
      error: message
    }),
    {
      status,
      headers: {
        'Content-Type': 'application/json; charset=utf-8'
      }
    }
  );
}