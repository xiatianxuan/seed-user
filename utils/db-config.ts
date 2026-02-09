// utils/db-config.ts
export const USER_TABLE_CONFIG = {
  tableName: 'users',
  columns: {
    id: 'id',
    username: 'username',
    email: 'email',
    passwordSalt: 'password_salt',
    passwordHash: 'password_hash',
    permissions: 'permissions',
    createdAt: 'created_at'
  }
} as const;