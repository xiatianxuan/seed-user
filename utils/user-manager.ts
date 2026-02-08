// utils/user-manager.ts

import type { D1Database } from '@cloudflare/workers-types';
import {
  verifyPasswordWithSalt,
  hexToUint8Array,
} from './password';
import { USER_TABLE_CONFIG } from './user-config';

/**
 * 逻辑用户模型（与数据库结构解耦）
 */
export interface LogicalUser {
  id?: number;
  username: string;
  email: string;
  password?: string; // ⚠️ 仅用于输入（注册时），其他场景 undefined
  role?: string;
  permissions?: number;
  createdAt?: string;
}

/**
 * 创建用户时的数据（不含 ID，含哈希和盐）
 */
export interface CreateUserInput {
  username: string;
  email: string;
  passwordHash: string; // hex
  passwordSalt: string;  // hex
  role?: string;
  permissions?: number;
}

/**
 * 通用用户管理器
 */
export class UserManager {
  private db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  // ─── 私有工具方法 ───────────────────────────────

  private getCol(key: keyof typeof USER_TABLE_CONFIG.columns): string {
    return USER_TABLE_CONFIG.columns[key];
  }

  private buildSelectFields(): string {
    return Object.values(USER_TABLE_CONFIG.columns).join(', ');
  }

  private isValidEmail(str: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str);
  }

  /**
   * 根据 identifier（邮箱或用户名）获取完整用户（含密码字段，用于验证）
   */
  private async getUserByIdentifier(identifier: string): Promise<
    (LogicalUser & { passwordHash: string; passwordSalt: string }) | null
  > {
    let row: Record<string, any> | null = null;

    if (this.isValidEmail(identifier)) {
      const query = `
        SELECT ${this.buildSelectFields()}
        FROM ${USER_TABLE_CONFIG.tableName}
        WHERE ${this.getCol('email')} = ?
      `;
      row = await this.db.prepare(query).bind(identifier.toLowerCase()).first();
    } else {
      const query = `
        SELECT ${this.buildSelectFields()}
        FROM ${USER_TABLE_CONFIG.tableName}
        WHERE ${this.getCol('username')} = ?
      `;
      row = await this.db.prepare(query).bind(identifier).first();
    }

    if (!row) return null;

    return {
      id: row[this.getCol('id')],
      username: row[this.getCol('username')],
      email: row[this.getCol('email')],
      role: row[this.getCol('role')],
      permissions: row[this.getCol('permissions')],
      createdAt: row[this.getCol('createdAt')],
      passwordHash: row[this.getCol('passwordHash')],
      passwordSalt: row[this.getCol('passwordSalt')],
    };
  }

  /**
   * 构建 INSERT 字段（适配 CreateUserInput）
   */
  private buildInsertFieldsForCreate(user: CreateUserInput): { 
    cols: string; 
    placeholders: string; 
    values: any[] 
  } {
    const cols = [
      this.getCol('username'),
      this.getCol('email'),
      this.getCol('passwordHash'),
      this.getCol('passwordSalt'),
      this.getCol('role'),
      this.getCol('permissions'),
      this.getCol('createdAt'),
    ];

    const values = [
      user.username,
      user.email,
      user.passwordHash,
      user.passwordSalt,
      user.role ?? USER_TABLE_CONFIG.defaults.role,
      user.permissions ?? USER_TABLE_CONFIG.defaults.permissions,
      new Date().toISOString(),
    ];

    const placeholders = cols.map(() => '?').join(', ');
    return { cols: cols.join(', '), placeholders, values };
  }

  // ─── 公共方法 ───────────────────────────────────

  /**
   * 创建新用户（需预先计算好 hash 和 salt）
   */
  async createUser(userData: CreateUserInput): Promise<number> {
    const { cols, placeholders, values } = this.buildInsertFieldsForCreate(userData);

    const query = `
      INSERT INTO ${USER_TABLE_CONFIG.tableName} (${cols})
      VALUES (${placeholders})
    `;

    const result = await this.db.prepare(query).bind(...values).run();
    return Number(result.meta.last_row_id);
  }

  /**
   * 验证用户密码（支持邮箱或用户名作为 identifier）
   */
  async verifyUserPassword(identifier: string, password: string): Promise<boolean> {
    if (!identifier || !password) return false;

    const user = await this.getUserByIdentifier(identifier);
    if (!user) return false;

    try {
      const salt = hexToUint8Array(user.passwordSalt);
      const expectedHash = hexToUint8Array(user.passwordHash);
      return await verifyPasswordWithSalt(password, salt, expectedHash);
    } catch (err) {
      console.error('Password verification error:', err);
      return false;
    }
  }

  /**
   * 通过 ID 获取用户（不包含密码字段）
   */
  async getUserById(id: number): Promise<LogicalUser | null> {
    const query = `
      SELECT ${this.buildSelectFields()}
      FROM ${USER_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('id')} = ?
    `;
    const row = await this.db.prepare(query).bind(id).first<Record<string, any>>();
    
    if (!row) return null;

    return {
      id: row[this.getCol('id')],
      username: row[this.getCol('username')],
      email: row[this.getCol('email')],
      role: row[this.getCol('role')],
      permissions: row[this.getCol('permissions')],
      createdAt: row[this.getCol('createdAt')],
    };
  }

  /**
   * 通过邮箱获取用户（不包含密码字段）
   */
  async getUserByEmail(email: string): Promise<LogicalUser | null> {
    const query = `
      SELECT ${this.buildSelectFields()}
      FROM ${USER_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('email')} = ?
    `;
    const row = await this.db.prepare(query).bind(email).first<Record<string, any>>();
    
    if (!row) return null;

    return {
      id: row[this.getCol('id')],
      username: row[this.getCol('username')],
      email: row[this.getCol('email')],
      role: row[this.getCol('role')],
      permissions: row[this.getCol('permissions')],
      createdAt: row[this.getCol('createdAt')],
    };
  }

  /**
   * 通过用户名获取用户（不包含密码字段）
   */
  async getUserByUsername(username: string): Promise<LogicalUser | null> {
    const query = `
      SELECT ${this.buildSelectFields()}
      FROM ${USER_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('username')} = ?
    `;
    const row = await this.db.prepare(query).bind(username).first<Record<string, any>>();
    
    if (!row) return null;

    return {
      id: row[this.getCol('id')],
      username: row[this.getCol('username')],
      email: row[this.getCol('email')],
      role: row[this.getCol('role')],
      permissions: row[this.getCol('permissions')],
      createdAt: row[this.getCol('createdAt')],
    };
  }

  async deleteUser(id: number): Promise<boolean> {
    const query = `DELETE FROM ${USER_TABLE_CONFIG.tableName} WHERE ${this.getCol('id')} = ?`;
    const result = await this.db.prepare(query).bind(id).run();
    return result.success && (result.meta.changes as number) > 0;
  }

  async listUsers(roles: string[] = ['admin', 'root']): Promise<LogicalUser[]> {
    if (roles.length === 0) return [];

    const placeholders = roles.map(() => '?').join(',');
    const query = `
      SELECT ${this.buildSelectFields()}
      FROM ${USER_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('role')} IN (${placeholders})
      ORDER BY 
        CASE ${this.getCol('role')}
          WHEN 'root' THEN 1
          WHEN 'admin' THEN 2
          ELSE 3
        END,
        ${this.getCol('id')}
    `;
    const stmt = this.db.prepare(query);
    const result = await stmt.bind(...roles).all<Record<string, any>>();
    
    return result.results.map(row => ({
      id: row[this.getCol('id')],
      username: row[this.getCol('username')],
      email: row[this.getCol('email')],
      role: row[this.getCol('role')],
      permissions: row[this.getCol('permissions')],
      createdAt: row[this.getCol('createdAt')],
    }));
  }
}