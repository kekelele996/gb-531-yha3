export const safeguardTiers = ['eligible', 'grace', 'duplicate', 'excluded'] as const
export type SafeguardTier = (typeof safeguardTiers)[number]

export const safeguardTierLabels: Record<SafeguardTier, string> = {
  eligible: '有效期内 · 足额',
  grace: '宽限期内 · 折半',
  duplicate: '重复独立键 · 不计',
  excluded: '不计入覆盖',
}

export const safeguardTierHints: Record<SafeguardTier, string> = {
  eligible: '验证在有效期内，按名义有效性足额计入。',
  grace: '验证已过期但仍在宽限窗口内，按名义有效性的 50% 计入。',
  duplicate: '与同独立性键的保留层重复，该层不重复计分。',
  excluded: '生命周期失效、证据缺失或已超过宽限窗口，不参与覆盖计算。',
}
