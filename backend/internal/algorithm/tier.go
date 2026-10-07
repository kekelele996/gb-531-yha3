package algorithm

// SafeguardTier is the single eligibility vocabulary used by the coverage
// algorithm, the scoring explanation and the API responses.
type SafeguardTier string

const (
	// TierEligible: lifecycle active, verification still within test interval;
	// the layer contributes its full nominal effectiveness.
	TierEligible SafeguardTier = "eligible"
	// TierGrace: verification expiry has passed but the frozen reference time is
	// still within the configured grace window; the layer participates in
	// coverage with a discounted effectiveness (see GraceEffectivenessFactor).
	TierGrace SafeguardTier = "grace"
	// TierDuplicate: eligible/grace layer that loses an independence_key tie and
	// is not counted; the retained layer for the key is documented separately.
	TierDuplicate SafeguardTier = "duplicate"
	// TierExcluded: lifecycle, evidence or expiry (beyond grace) makes the layer
	// ineligible for the coverage calculation.
	TierExcluded SafeguardTier = "excluded"
)

// GraceEffectivenessFactor is the judgment rule for layers inside the grace
// window: they remain counted but at half nominal effectiveness. The discount,
// rather than full credit, records that overdue verification evidence is less
// trustworthy than current evidence while maintenance records are catching up.
const GraceEffectivenessFactor = 0.5

// GracePolicyNote is emitted in every explanation so the caliber applied to a
// grace-window layer is readable in the stored evidence.
const GracePolicyNote = "Layers inside the verification grace window participate in coverage at " +
	"50% of their nominal effectiveness; layers past the grace window are excluded."

// AppliedEffectiveness converts nominal effectiveness into the value combined
// by the scoring rule for a resolved tier. Eligible layers keep full credit,
// grace layers take GraceEffectivenessFactor; duplicates and excluded layers
// contribute nothing.
func AppliedEffectiveness(nominal float64, tier SafeguardTier) float64 {
	switch tier {
	case TierEligible:
		return nominal
	case TierGrace:
		return round4(nominal * GraceEffectivenessFactor)
	default:
		return 0
	}
}

// SafeguardTierValues lists the shared eligibility vocabulary served through
// the meta/enums endpoint.
func SafeguardTierValues() []string {
	return []string{string(TierEligible), string(TierGrace), string(TierDuplicate), string(TierExcluded)}
}
