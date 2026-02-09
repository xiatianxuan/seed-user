// utils/user-config.ts

export const USER_TABLE_CONFIG = {
  tableName: 'users',
  columns: {
    id: 'id',
    username: 'name',         // 逻辑名 → DB 列名
    email: 'email',
    passwordHash: 'password_hash',
    passwordSalt: 'password_salt',
    permissions: 'permissions', // ✅ 保留
    createdAt: 'created_at',
    // ❌ 删除 role 行（数据库已无此列）
  },
  defaults: {
    // ❌ 删除 role 默认值
    permissions: 1, // 建议默认为 READ (1)，而不是 0（无权限）
  },
};