package algorithm

import (
	"fmt"
	"hazop-safeguard-coverage/backend/internal/dto"
	"sort"
	"strings"
	"time"
)

// Eligibility tiers recorded for every safeguard in the frozen snapshot.
const (
	// TierValid: verification is current at the reference time; the layer is
	// counted at its registered effectiveness.
	TierValid = "valid"

	// TierGrace: verification expired but the reference time is still within
	// the configured grace window; the layer participates in the coverage
	// calculation at GraceEffectivenessFactor of its registered effectiveness.
	TierGrace = "grace"
)

// GraceEffectivenessFactor is the single judgement rule chosen for the grace
// window: a layer whose verification record is overdue but still in service is
// counted at half effectiveness. It can never score as high as a freshly
// verified layer, and it is dropped entirely once the window closes.
const GraceEffectivenessFactor = 0.5

// CountedSafeguard pairs an eligible snapshot safeguard with the tier it fell
// into at the frozen reference time and the effectiveness actually scored.
type CountedSafeguard struct {
	Safeguard            SnapshotSafeguard
	Tier                 string
	CountedEffectiveness float64
	ExpiresAt            time.Time
	GraceEndsAt          *time.Time
}

type IndependenceResult struct {
	Retained     []CountedSafeguard
	Deduplicated []dto.DeduplicatedSafeguardResponse
	Rejected     []RejectedSafeguard
	Layers       []dto.LayerEligibilityResponse
}

type RejectedSafeguard struct {
	ID     uint   `json:"id"`
	Reason string `json:"reason"`
}

func ResolveIndependence(safeguards []SnapshotSafeguard, referenceTime time.Time, graceDays int) IndependenceResult {
	groups := make(map[string][]CountedSafeguard)
	result := IndependenceResult{}
	for _, safeguard := range safeguards {
		layer := classifySafeguard(safeguard, referenceTime, graceDays)
		// Missing independence key is reported before any other rejection,
		// matching the pre-grace eligibility filter order.
		if strings.TrimSpace(safeguard.IndependenceKey) == "" {
			layer.Eligible = false
			layer.Tier = "rejected"
			layer.RejectReason = "missing independence key"
		}
		if !layer.Eligible {
			result.Rejected = append(result.Rejected, RejectedSafeguard{ID: safeguard.ID, Reason: layer.RejectReason})
			result.Layers = append(result.Layers, layer.toResponse())
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(safeguard.IndependenceKey))
		result.Layers = append(result.Layers, layer.toResponse())
		counted := CountedSafeguard{
			Safeguard:            safeguard,
			Tier:                 layer.Tier,
			CountedEffectiveness: layer.CountedEffectiveness,
			ExpiresAt:            layer.ExpiresAt,
			GraceEndsAt:          layer.GraceEndsAt,
		}
		groups[key] = append(groups[key], counted)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		items := groups[key]
		sort.Slice(items, func(i, j int) bool {
			if items[i].CountedEffectiveness == items[j].CountedEffectiveness {
				return items[i].Safeguard.ID < items[j].Safeguard.ID
			}
			return items[i].CountedEffectiveness > items[j].CountedEffectiveness
		})
		result.Retained = append(result.Retained, items[0])
		if len(items) > 1 {
			ignored := make([]uint, 0, len(items)-1)
			for _, item := range items[1:] {
				ignored = append(ignored, item.Safeguard.ID)
			}
			result.Deduplicated = append(result.Deduplicated, dto.DeduplicatedSafeguardResponse{
				IndependenceKey: key, KeptID: items[0].Safeguard.ID, IgnoredIDs: ignored,
				Reason: "same independence_key on one cause-to-consequence path; highest counted effectiveness retained, then lowest ID",
			})
		}
	}
	sort.Slice(result.Rejected, func(i, j int) bool { return result.Rejected[i].ID < result.Rejected[j].ID })
	sort.Slice(result.Layers, func(i, j int) bool { return result.Layers[i].ID < result.Layers[j].ID })
	return result
}

// eligibility holds the tier decision for one safeguard at the reference time.
type eligibility struct {
	Safeguard            SnapshotSafeguard
	Eligible             bool
	Tier                 string
	CountedEffectiveness float64
	ExpiresAt            time.Time
	GraceEndsAt          *time.Time
	RejectReason         string
}

func classifySafeguard(safeguard SnapshotSafeguard, referenceTime time.Time, graceDays int) eligibility {
	layer := eligibility{Safeguard: safeguard}
	if reason := staticIneligibleReason(safeguard); reason != "" {
		layer.RejectReason = reason
		return layer
	}
	expires := safeguard.LastVerifiedAt.AddDate(0, 0, safeguard.TestIntervalDays)
	layer.ExpiresAt = expires
	if !referenceTime.After(expires) {
		// Within the verification interval: the ledger lifecycle must be active.
		if safeguard.LifecycleState == "active" {
			layer.Eligible = true
			layer.Tier = TierValid
			layer.CountedEffectiveness = safeguard.Effectiveness
			return layer
		}
		layer.RejectReason = fmt.Sprintf("lifecycle state %q is not active", safeguard.LifecycleState)
		return layer
	}
	// Verification date has passed. The ledger auto-flips the lifecycle to
	// "expired" as soon as the date passes, so a layer still in service while
	// its review record is being entered sits in exactly this state. The grace
	// window keeps such layers in the calculation at half effectiveness. A
	// deliberately retired layer ("invalid"/"pending") is never rescued.
	if graceDays > 0 && (safeguard.LifecycleState == "active" || safeguard.LifecycleState == "expired") {
		graceEnd := expires.AddDate(0, 0, graceDays)
		layer.GraceEndsAt = &graceEnd
		if !referenceTime.After(graceEnd) {
			layer.Eligible = true
			layer.Tier = TierGrace
			layer.CountedEffectiveness = round4(safeguard.Effectiveness * GraceEffectivenessFactor)
			return layer
		}
		layer.RejectReason = fmt.Sprintf(
			"verification expired at %s and %d-day grace period ended at %s",
			expires.UTC().Format(time.RFC3339), graceDays, graceEnd.UTC().Format(time.RFC3339),
		)
		return layer
	}
	if safeguard.LifecycleState != "active" {
		layer.RejectReason = fmt.Sprintf("lifecycle state %q is not active", safeguard.LifecycleState)
		return layer
	}
	layer.RejectReason = fmt.Sprintf("verification expired at %s", expires.UTC().Format(time.RFC3339))
	return layer
}

// staticIneligibleReason covers checks unaffected by the grace window:
// effectiveness bounds, evidence and test interval. Lifecycle is handled
// together with the date tiers because "expired" is a date-driven ledger
// state that the grace window is allowed to rescue. A missing independence
// key is filtered separately in ResolveIndependence.
func staticIneligibleReason(safeguard SnapshotSafeguard) string {
	if safeguard.Effectiveness <= 0 || safeguard.Effectiveness > 1 {
		return "effectiveness is outside (0,1]"
	}
	if safeguard.LastVerifiedAt == nil {
		return "verification evidence is missing"
	}
	if safeguard.TestIntervalDays <= 0 {
		return "test interval is invalid"
	}
	return ""
}

func (l eligibility) toResponse() dto.LayerEligibilityResponse {
	response := dto.LayerEligibilityResponse{
		ID: l.Safeguard.ID, Name: l.Safeguard.Name, IndependenceKey: l.Safeguard.IndependenceKey,
		RegisteredEffectiveness: l.Safeguard.Effectiveness, LifecycleState: l.Safeguard.LifecycleState,
		Eligible: l.Eligible,
	}
	if !l.ExpiresAt.IsZero() {
		response.VerificationExpiresAt = &l.ExpiresAt
	}
	if l.Eligible {
		response.Tier = l.Tier
		response.CountedEffectiveness = l.CountedEffectiveness
		response.GraceEndsAt = l.GraceEndsAt
	} else {
		response.Tier = "rejected"
		response.RejectReason = l.RejectReason
		response.GraceEndsAt = l.GraceEndsAt
	}
	return response
}
