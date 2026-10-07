package algorithm

import (
	"fmt"
	"hazop-safeguard-coverage/backend/internal/dto"
	"sort"
	"strings"
	"time"
)

type IndependenceResult struct {
	Retained     []ResolvedSafeguard
	Deduplicated []dto.DeduplicatedSafeguardResponse
	Rejected     []RejectedSafeguard
	Ledger       []ResolvedSafeguard
}

type RejectedSafeguard struct {
	ID     uint          `json:"id"`
	Tier   SafeguardTier `json:"tier"`
	Reason string        `json:"reason"`
}

// ResolvedSafeguard binds a frozen safeguard to the eligibility tier it fell
// into at the frozen reference time, together with the effectiveness actually
// combined by the scoring rule.
type ResolvedSafeguard struct {
	Safeguard            SnapshotSafeguard
	Tier                 SafeguardTier
	ExpiresAt            time.Time
	GraceUntil           *time.Time
	AppliedEffectiveness float64
	Note                 string
}

func ResolveIndependence(safeguards []SnapshotSafeguard, referenceTime time.Time, graceDays int) IndependenceResult {
	if graceDays < 0 {
		graceDays = 0
	}
	groups := make(map[string][]ResolvedSafeguard)
	result := IndependenceResult{}
	ledger := make([]ResolvedSafeguard, 0, len(safeguards))
	for _, safeguard := range safeguards {
		resolved := resolveTier(safeguard, referenceTime, graceDays)
		ledger = append(ledger, resolved)
		if resolved.Tier == TierExcluded {
			result.Rejected = append(result.Rejected, RejectedSafeguard{ID: safeguard.ID, Tier: TierExcluded, Reason: resolved.Note})
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(safeguard.IndependenceKey))
		groups[key] = append(groups[key], resolved)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		items := groups[key]
		sort.Slice(items, func(i, j int) bool {
			if items[i].AppliedEffectiveness == items[j].AppliedEffectiveness {
				return items[i].Safeguard.ID < items[j].Safeguard.ID
			}
			return items[i].AppliedEffectiveness > items[j].AppliedEffectiveness
		})
		items[0].Note = tierNote(items[0], key)
		result.Retained = append(result.Retained, items[0])
		if len(items) > 1 {
			ignored := make([]uint, 0, len(items)-1)
			for _, item := range items[1:] {
				item.Tier = TierDuplicate
				item.AppliedEffectiveness = 0
				item.Note = fmt.Sprintf("same independence_key %q; %s layer #%d retained with applied effectiveness %.4f",
					key, items[0].Tier, items[0].Safeguard.ID, items[0].AppliedEffectiveness)
				ledger = replaceLedger(ledger, item)
				result.Rejected = append(result.Rejected, RejectedSafeguard{ID: item.Safeguard.ID, Tier: TierDuplicate, Reason: item.Note})
				ignored = append(ignored, item.Safeguard.ID)
			}
			result.Deduplicated = append(result.Deduplicated, dto.DeduplicatedSafeguardResponse{
				IndependenceKey: key, KeptID: items[0].Safeguard.ID, IgnoredIDs: ignored,
				KeptTier: string(items[0].Tier),
				Reason:   "same independence_key on one cause-to-consequence path; highest applied effectiveness retained, then lowest ID",
			})
		}
	}
	sort.Slice(ledger, func(i, j int) bool { return ledger[i].Safeguard.ID < ledger[j].Safeguard.ID })
	sort.Slice(result.Rejected, func(i, j int) bool { return result.Rejected[i].ID < result.Rejected[j].ID })
	result.Ledger = ledger
	return result
}

func replaceLedger(ledger []ResolvedSafeguard, updated ResolvedSafeguard) []ResolvedSafeguard {
	for i := range ledger {
		if ledger[i].Safeguard.ID == updated.Safeguard.ID {
			ledger[i] = updated
			return ledger
		}
	}
	return append(ledger, updated)
}

func resolveTier(safeguard SnapshotSafeguard, referenceTime time.Time, graceDays int) ResolvedSafeguard {
	resolved := ResolvedSafeguard{Safeguard: safeguard}
	key := strings.ToUpper(strings.TrimSpace(safeguard.IndependenceKey))
	if key == "" {
		resolved.Tier = TierExcluded
		resolved.Note = "missing independence key"
		return resolved
	}
	if safeguard.Effectiveness <= 0 || safeguard.Effectiveness > 1 {
		resolved.Tier = TierExcluded
		resolved.Note = "effectiveness is outside (0,1]"
		return resolved
	}
	// "invalid" records an explicitly failed layer; grace never rescues it.
	// "pending" means no verification evidence has ever been recorded.
	switch safeguard.LifecycleState {
	case "invalid":
		resolved.Tier = TierExcluded
		resolved.Note = "lifecycle state \"invalid\" (explicitly failed) is never counted, even inside grace"
		return resolved
	case "pending":
		resolved.Tier = TierExcluded
		resolved.Note = "lifecycle state \"pending\" has no verification evidence"
		return resolved
	case "active", "expired":
		// "expired" is the date-driven overdue flag assigned when verification
		// evidence is recorded late; the grace window below may still count it.
	default:
		resolved.Tier = TierExcluded
		resolved.Note = fmt.Sprintf("lifecycle state %q is not active", safeguard.LifecycleState)
		return resolved
	}
	if safeguard.LastVerifiedAt == nil {
		resolved.Tier = TierExcluded
		resolved.Note = "verification evidence is missing"
		return resolved
	}
	if safeguard.TestIntervalDays <= 0 {
		resolved.Tier = TierExcluded
		resolved.Note = "test interval is invalid"
		return resolved
	}
	expires := safeguard.LastVerifiedAt.AddDate(0, 0, safeguard.TestIntervalDays)
	resolved.ExpiresAt = expires
	if !referenceTime.After(expires) {
		resolved.Tier = TierEligible
		resolved.AppliedEffectiveness = AppliedEffectiveness(safeguard.Effectiveness, TierEligible)
		resolved.Note = tierNote(resolved, key)
		return resolved
	}
	if graceDays > 0 {
		graceUntil := expires.AddDate(0, 0, graceDays)
		resolved.GraceUntil = &graceUntil
		if !referenceTime.After(graceUntil) {
			resolved.Tier = TierGrace
			resolved.AppliedEffectiveness = AppliedEffectiveness(safeguard.Effectiveness, TierGrace)
			resolved.Note = tierNote(resolved, key)
			return resolved
		}
		resolved.Tier = TierExcluded
		resolved.Note = fmt.Sprintf("verification expired at %s; %d-day grace window ended at %s",
			expires.UTC().Format(time.RFC3339), graceDays, graceUntil.UTC().Format(time.RFC3339))
		return resolved
	}
	resolved.Tier = TierExcluded
	resolved.Note = fmt.Sprintf("verification expired at %s", expires.UTC().Format(time.RFC3339))
	return resolved
}

func tierNote(resolved ResolvedSafeguard, key string) string {
	switch resolved.Tier {
	case TierEligible:
		return fmt.Sprintf("verification valid until %s; full nominal effectiveness %.4f under key %q",
			resolved.ExpiresAt.UTC().Format(time.RFC3339), resolved.AppliedEffectiveness, key)
	case TierGrace:
		return fmt.Sprintf("verification expired at %s (lifecycle %q) but within grace window ending %s; nominal %.4f counted at %.4f (%.0f%%) under key %q",
			resolved.ExpiresAt.UTC().Format(time.RFC3339), resolved.Safeguard.LifecycleState,
			resolved.GraceUntil.UTC().Format(time.RFC3339),
			resolved.Safeguard.Effectiveness, resolved.AppliedEffectiveness, GraceEffectivenessFactor*100, key)
	default:
		return resolved.Note
	}
}
