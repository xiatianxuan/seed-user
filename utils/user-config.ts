// utils/user-config.ts

export const USER_TABLE_CONFIG = {
  tableName: 'users',
  columns: {
    id: 'id',
    username: 'name',         // 逻辑名 → DB 列名
    email: 'email',
    passwordHash: 'password_hash',
    passwordSalt: 'password_salt', // 👈 必须存在
    role: 'role',
    permissions: 'permissions',
    createdAt: 'created_at',
  },
  defaults: {
    role: 'user',
    permissions: 0,
  },
};