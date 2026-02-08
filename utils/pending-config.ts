// utils/pending-config.ts

export const PENDING_TABLE_CONFIG = {
  tableName: 'pending_registrations',
  columns: {
    id: 'id',
    username: 'name',         // 逻辑名 → DB 列名
    email: 'email',
    passwordHash: 'password_hash',
    passwordSalt: 'password_salt', // 👈 必须存在！
    token: 'token',
    createdAt: 'created_at',
    expiresAt: 'expires_at',
  },
};