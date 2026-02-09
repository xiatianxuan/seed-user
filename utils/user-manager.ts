// utils/user-manager.ts
import { D1Database } from '@cloudflare/workers-types';
import { PERM } from './permissions';
import { verifyPasswordWithSalt, hexToUint8Array } from './password';

// ✅ 表结构配置：与你的 D1 数据库完全一致
const USER_TABLE_CONFIG = {
  tableName: 'users',
  columns: {
    id: 'id',
    name: 'name',
    email: 'email',
    passwordSalt: 'password_salt',
    passwordHash: 'password_hash',
    permissions: 'permissions',
    createdAt: 'created_at'
  }
} as const;

export interface LogicalUser {
  id: number;
  name: string;
  email: string;
  passwordSalt: string;
  passwordHash: string;
  permissions: number;
  createdAt: string;
}

export class UserManager {
  private db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  private getCol(col: keyof LogicalUser): string {
    return USER_TABLE_CONFIG.columns[col];
  }

  async createUser(
    name: string,
    email: string,
    passwordSalt: string,
    passwordHash: string,
    permissions: number = PERM.READ
  ): Promise<number | null> {
    const query = `
      INSERT INTO ${USER_TABLE_CONFIG.tableName} (
        ${this.getCol('name')},
        ${this.getCol('email')},
        ${this.getCol('passwordSalt')},
        ${this.getCol('passwordHash')},
        ${this.getCol('permissions')},
        ${this.getCol('createdAt')}
      ) VALUES (?, ?, ?, ?, ?, datetime('now', '+8 hours'))
      RETURNING ${this.getCol('id')};
    `;
    const result = await this.db.prepare(query)
      .bind(name, email, passwordSalt, passwordHash, permissions)
      .first<{ id: number }>();
    return result?.id ?? null;
  }

  async getUserByName(name: string): Promise<LogicalUser | null> {
    const query = `
      SELECT 
        ${this.getCol('id')} AS id,
        ${this.getCol('name')} AS name,
        ${this.getCol('email')} AS email,
        ${this.getCol('passwordSalt')} AS passwordSalt,
        ${this.getCol('passwordHash')} AS passwordHash,
        ${this.getCol('permissions')} AS permissions,
        ${this.getCol('createdAt')} AS createdAt
      FROM ${USER_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('name')} = ?
    `;
    const row = await this.db.prepare(query).bind(name).first<LogicalUser>();
    return row || null;
  }

  async getUserByEmail(email: string): Promise<LogicalUser | null> {
    const query = `
      SELECT 
        ${this.getCol('id')} AS id,
        ${this.getCol('name')} AS name,
        ${this.getCol('email')} AS email,
        ${this.getCol('passwordSalt')} AS passwordSalt,
        ${this.getCol('passwordHash')} AS passwordHash,
        ${this.getCol('permissions')} AS permissions,
        ${this.getCol('createdAt')} AS createdAt
      FROM ${USER_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('email')} = ?
    `;
    const row = await this.db.prepare(query).bind(email).first<LogicalUser>();
    return row || null;
  }

  async getUserById(id: number): Promise<LogicalUser | null> {
    const query = `
      SELECT 
        ${this.getCol('id')} AS id,
        ${this.getCol('name')} AS name,
        ${this.getCol('email')} AS email,
        ${this.getCol('passwordSalt')} AS passwordSalt,
        ${this.getCol('passwordHash')} AS passwordHash,
        ${this.getCol('permissions')} AS permissions,
        ${this.getCol('createdAt')} AS createdAt
      FROM ${USER_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('id')} = ?
    `;
    const row = await this.db.prepare(query).bind(id).first<LogicalUser>();
    return row || null;
  }

  async getAllUsers(): Promise<LogicalUser[]> {
    const query = `
      SELECT 
        ${this.getCol('id')} AS id,
        ${this.getCol('name')} AS name,
        ${this.getCol('email')} AS email,
        ${this.getCol('passwordSalt')} AS passwordSalt,
        ${this.getCol('passwordHash')} AS passwordHash,
        ${this.getCol('permissions')} AS permissions,
        ${this.getCol('createdAt')} AS createdAt
      FROM ${USER_TABLE_CONFIG.tableName}
      ORDER BY ${this.getCol('id')} ASC
    `;
    const rows = await this.db.prepare(query).all<LogicalUser>();
    return rows.results || [];
  }

  async getUsersByPermission(permission: number): Promise<LogicalUser[]> {
    const query = `
      SELECT 
        ${this.getCol('id')} AS id,
        ${this.getCol('name')} AS name,
        ${this.getCol('email')} AS email,
        ${this.getCol('passwordSalt')} AS passwordSalt,
        ${this.getCol('passwordHash')} AS passwordHash,
        ${this.getCol('permissions')} AS permissions,
        ${this.getCol('createdAt')} AS createdAt
      FROM ${USER_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('permissions')} & ? != 0
      ORDER BY ${this.getCol('id')} ASC
    `;
    const rows = await this.db.prepare(query).bind(permission).all<LogicalUser>();
    return rows.results || [];
  }

  async deleteUserById(id: number): Promise<boolean> {
    const query = `
      DELETE FROM ${USER_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('id')} = ?
    `;
    const result = await this.db.prepare(query).bind(id).run();
    return result.success && (result.meta.changes as number) > 0;
  }

  async updatePermissions(userId: number, newPermissions: number): Promise<boolean> {
    if (newPermissions === -1) {
      throw new Error("不允许通过此方法授予 ROOT 权限");
    }
    const query = `
      UPDATE ${USER_TABLE_CONFIG.tableName}
      SET ${this.getCol('permissions')} = ?
      WHERE ${this.getCol('id')} = ?
    `;
    const result = await this.db.prepare(query).bind(newPermissions, userId).run();
    return result.success && (result.meta.changes as number) > 0;
  }

  // 验证用户密码（支持用户名或邮箱登录）
  async verifyUserPassword(identifier: string, password: string): Promise<boolean> {
    let user: LogicalUser | null = null;
    if (identifier.includes('@')) {
      user = await this.getUserByEmail(identifier.toLowerCase());
    } else {
      user = await this.getUserByName(identifier);
    }
    if (!user) return false;

    try {
      const salt = hexToUint8Array(user.passwordSalt);
      const hash = hexToUint8Array(user.passwordHash);
      return await verifyPasswordWithSalt(password, salt, hash);
    } catch (err) {
      console.error('密码验证异常:', err);
      return false;
    }
  }
}