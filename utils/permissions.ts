// utils/permissions.ts

// ── 原子权限（bit flags）──────────────────────
export const PERM = {
  READ:        1 << 0,  // 1
  WRITE:       1 << 1,  // 2
  DELETE:      1 << 2,  // 4
  MANAGE_USERS:1 << 3,  // 8
  EXPORT_DATA: 1 << 4,  // 16
  AUDIT_LOGS:  1 << 5,  // 32
} as const;

export type PermKey = keyof typeof PERM;

// ── 预设角色（仅用于初始化或展示，非运行时逻辑依赖）──
export const ROLE_PRESET = {
  USER:   PERM.READ,
  ADMIN:  PERM.READ | PERM.WRITE | PERM.DELETE | PERM.MANAGE_USERS,
  ROOT:   -1, // 所有位为 1（在 32 位整数下表示全权限）
} as const;

export type RolePresetKey = keyof typeof ROLE_PRESET;

// ── 工具函数 ───────────────────────────────
/**
 * 检查用户是否拥有指定的全部权限
 * @param userPerm 用户当前权限值（number）
 * @param required 所需权限（可以是单个 PERM.X 或组合）
 */
export function hasPermission(userPerm: number, required: number): boolean {
  // 特殊处理 ROOT（-1）：拥有所有权限
  if (userPerm === -1) return true;
  return (userPerm & required) === required;
}

/**
 * 判断是否为超级管理员（ROOT）
 */
export function isRoot(userPerm: number): boolean {
  return userPerm === -1;
}

/**
 * 获取权限名称列表（用于前端展示）
 */
export function getPermissionLabels(permValue: number): PermKey[] {
  const labels: PermKey[] = [];
  for (const [key, value] of Object.entries(PERM) as [PermKey, number][]) {
    if (permValue === -1 || (permValue & value) !== 0) {
      labels.push(key);
    }
  }
  return labels;
}