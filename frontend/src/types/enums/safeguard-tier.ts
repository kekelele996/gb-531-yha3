export const safeguardTiers = ['valid', 'grace', 'rejected'] as const
export type SafeguardTier = (typeof safeguardTiers)[number]

// 保护层在冻结参考时点落在哪种计入口径：
// - valid：验证有效期内，按登记有效性全额计入
// - grace：已过期但仍在配置的宽限窗口内，按登记有效性的 50% 计入
// - rejected：超出宽限窗口或其它不合格原因，不参与覆盖计算
export const safeguardTierLabels: Record<SafeguardTier, string> = {
  valid: '有效期内 · 全额',
  grace: '宽限期内 · 半额',
  rejected: '排除不计',
}
