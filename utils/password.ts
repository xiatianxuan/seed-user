// utils/password.ts

/**
 * PBKDF2 密码哈希配置（支持分离存储 salt 和 hash）
 */

// 🧂 盐长度（字节）— 32 字节 = 256 位
const SALT_LENGTH_BYTES = 32;

// 🔁 迭代次数 — OWASP 推荐 ≥ 600,000 (SHA-256)
const PBKDF2_ITERATIONS = 600_000;

// 🔑 输出密钥长度（字节）— 32 字节 = 256 位
const KEY_LENGTH_BYTES = 32;

// 🧮 摘要算法（Web Crypto 兼容）
const DIGEST_ALGORITHM: 'SHA-512' = 'SHA-512';

/**
 * 生成随机盐（用于存储到 password_salt 字段）
 */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
}

/**
 * 使用给定密码和盐计算 PBKDF2 哈希
 * @returns 哈希值（Uint8Array），用于存储到 password_hash 字段
 */
export async function computePasswordHash(
  password: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  if (salt.length !== SALT_LENGTH_BYTES) {
    throw new Error(`Salt must be exactly ${SALT_LENGTH_BYTES} bytes`);
  }

  const passwordBytes = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: DIGEST_ALGORITHM,
    },
    baseKey,
    KEY_LENGTH_BYTES * 8
  );

  return new Uint8Array(derivedBits);
}

/**
 * 验证密码是否匹配给定的 salt 和 hash
 */
export async function verifyPasswordWithSalt(
  password: string,
  salt: Uint8Array,
  expectedHash: Uint8Array
): Promise<boolean> {
  const actualHash = await computePasswordHash(password, salt);

  if (actualHash.length !== expectedHash.length) {
    return false;
  }

  // 恒定时间比较（防时序攻击）
  let mismatch = 0;
  for (let i = 0; i < actualHash.length; i++) {
    mismatch |= actualHash[i] ^ expectedHash[i];
  }
  return mismatch === 0;
}

/**
 * 辅助：将 Uint8Array 转为十六进制字符串（用于数据库存储）
 */
export function uint8ArrayToHex(arr: Uint8Array): string {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 辅助：将十六进制字符串转为 Uint8Array（从数据库读取后使用）
 */
export function hexToUint8Array(hex: string): Uint8Array {
  if (!/^[0-9a-f]*$/i.test(hex) || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  return new Uint8Array(hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
}