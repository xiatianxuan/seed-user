// utils/pending-manager.ts

import type { D1Database } from '@cloudflare/workers-types';
import { PENDING_TABLE_CONFIG } from './pending-config';

/**
 * 待验证注册记录的逻辑模型
 */
export interface PendingRegistration {
  /** 主键 ID（可选） */
  id?: number;

  /** 用户名（显示名） */
  username: string;

  /** 邮箱（唯一） */
  email: string;

  /** 密码哈希（十六进制字符串） */
  passwordHash: string;

  /** 密码盐值（十六进制字符串） */
  passwordSalt: string; // 👈 新增！

  /** 验证令牌（UUID） */
  token: string;

  /** 创建时间（北京时间，格式："YYYY-MM-DD HH:mm:ss"） */
  createdAt: string;

  /** 过期时间（北京时间，格式同上） */
  expiresAt: string;
}

/**
 * 待验证注册管理器
 */
export class PendingRegistrationManager {
  private db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  // ─── 私有工具方法 ───────────────────────────────

  private getCol(key: keyof typeof PENDING_TABLE_CONFIG.columns): string {
    return PENDING_TABLE_CONFIG.columns[key];
  }

  private buildInsertFields(record: PendingRegistration): { 
    cols: string; 
    placeholders: string; 
    values: any[] 
  } {
    // 排除 id（自增）
    const logicalKeys = Object.keys(PENDING_TABLE_CONFIG.columns).filter(k => k !== 'id') as (keyof PendingRegistration)[];
    
    const actualCols = logicalKeys.map(k => this.getCol(k as keyof typeof PENDING_TABLE_CONFIG.columns));
    const values = logicalKeys.map(k => record[k]);

    return {
      cols: actualCols.join(', '),
      placeholders: actualCols.map(() => '?').join(', '),
      values,
    };
  }

  // ─── 公共方法 ───────────────────────────────────

  async createPendingRegistration(record: Omit<PendingRegistration, 'id'>): Promise<number> {
    const { cols, placeholders, values } = this.buildInsertFields(record as PendingRegistration);
    const query = `
      INSERT INTO ${PENDING_TABLE_CONFIG.tableName} (${cols})
      VALUES (${placeholders})
    `;
    const result = await this.db.prepare(query).bind(...values).run();
    return Number(result.meta.last_row_id);
  }

  async getPendingByToken(token: string): Promise<PendingRegistration | null> {
    const query = `
      SELECT ${Object.values(PENDING_TABLE_CONFIG.columns).join(', ')}
      FROM ${PENDING_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('token')} = ?
        AND ${this.getCol('expiresAt')} > datetime('now', '+8 hours')
    `;
    const row = await this.db.prepare(query).bind(token).first<Record<string, any>>();
    if (!row) return null;

    return {
      id: row[this.getCol('id')],
      username: row[this.getCol('username')],
      email: row[this.getCol('email')],
      passwordHash: row[this.getCol('passwordHash')],
      passwordSalt: row[this.getCol('passwordSalt')], // 👈 新增
      token: row[this.getCol('token')],
      createdAt: row[this.getCol('createdAt')],
      expiresAt: row[this.getCol('expiresAt')],
    };
  }

  async existsPending(email: string, username: string): Promise<boolean> {
    const query = `
      SELECT 1 FROM ${PENDING_TABLE_CONFIG.tableName}
      WHERE (${this.getCol('email')} = ? OR ${this.getCol('username')} = ?)
        AND ${this.getCol('expiresAt')} > datetime('now', '+8 hours')
      LIMIT 1
    `;
    const result = await this.db.prepare(query).bind(email, username).first();
    return !!result;
  }

  async deletePending(id: number): Promise<boolean> {
    const query = `DELETE FROM ${PENDING_TABLE_CONFIG.tableName} WHERE ${this.getCol('id')} = ?`;
    const result = await this.db.prepare(query).bind(id).run();
    return result.success && (result.meta.changes as number) > 0;
  }

  async cleanupExpired(): Promise<number> {
    const query = `
      DELETE FROM ${PENDING_TABLE_CONFIG.tableName}
      WHERE ${this.getCol('expiresAt')} <= datetime('now', '+8 hours')
    `;
    const result = await this.db.prepare(query).run();
    return result.meta.changes as number;
  }
}