package algorithm

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"hazop-safeguard-coverage/backend/internal/dto"
	"hazop-safeguard-coverage/backend/internal/model"
)

func TestEvaluatorIsDeterministicAndDeduplicatesIndependenceKeys(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	valid := reference.AddDate(0, 0, -10)
	expired := reference.AddDate(0, 0, -400)
	node := model.ProcessNode{ID: 7, NodeCode: "R-7", Name: "Reactor"}
	scenario := model.DeviationScenario{
		ID: 9, Guideword: "more", Parameter: "temperature",
		Cause: "cooling loss; runaway reaction", Consequence: "overpressure; release",
		Likelihood: 4, Severity: 5, ScenarioState: "analyzed", Version: 2,
	}
	safeguards := []model.Safeguard{
		{ID: 3, IndependenceKey: "SIS-A", Effectiveness: 0.4, TestIntervalDays: 365, LastVerifiedAt: &valid, LifecycleState: "active"},
		{ID: 2, IndependenceKey: "SIS-A", Effectiveness: 0.8, TestIntervalDays: 365, LastVerifiedAt: &valid, LifecycleState: "active"},
		{ID: 4, IndependenceKey: "PSV-B", Effectiveness: 0.9, TestIntervalDays: 365, LastVerifiedAt: &expired, LifecycleState: "expired"},
	}
	evaluator := NewEvaluator()
	first, err := evaluator.Evaluate(NewSnapshot(node, scenario, safeguards, reference, 0))
	if err != nil {
		t.Fatalf("first evaluation failed: %v", err)
	}
	second, err := evaluator.Evaluate(NewSnapshot(node, scenario, safeguards, reference, 0))
	if err != nil {
		t.Fatalf("second evaluation failed: %v", err)
	}
	if first.InputHash != second.InputHash || first.ExplanationJSON != second.ExplanationJSON {
		t.Fatal("same frozen input produced different output")
	}
	if first.CoverageScore != 80 {
		t.Fatalf("coverage score = %v, want 80", first.CoverageScore)
	}
	if len(first.Explanation.Deduplicated) != 1 || first.Explanation.Deduplicated[0].KeptID != 2 {
		t.Fatalf("unexpected deduplication: %#v", first.Explanation.Deduplicated)
	}
	passed, replayed, err := evaluator.Replay(first.SnapshotJSON, first.InputHash, first.CoverageScore)
	if err != nil || !passed || replayed.CoverageScore != first.CoverageScore {
		t.Fatalf("replay failed: passed=%t score=%v err=%v", passed, replayed.CoverageScore, err)
	}
}

func TestEvaluatorDetectsUnprotectedPaths(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	node := model.ProcessNode{ID: 1, NodeCode: "V-1", Name: "Vessel"}
	scenario := model.DeviationScenario{
		ID: 1, Guideword: "more", Parameter: "pressure",
		Cause: "blocked outlet", Consequence: "rupture", Likelihood: 3, Severity: 5,
		ScenarioState: "draft", Version: 1,
	}
	result, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, nil, reference, 0))
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if result.CoverageScore != 0 || len(result.Explanation.Paths) != 1 || result.Explanation.Paths[0].Covered {
		t.Fatalf("expected one unprotected path, got %#v", result.Explanation.Paths)
	}
}

// With zero grace days an expired layer must be excluded exactly as before.
func TestZeroGraceDaysMatchesLegacyBehavior(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	node := model.ProcessNode{ID: 1, NodeCode: "V-1", Name: "Vessel"}
	scenario := model.DeviationScenario{
		ID: 1, Guideword: "more", Parameter: "pressure",
		Cause: "blocked outlet", Consequence: "rupture", Likelihood: 3, Severity: 5,
		ScenarioState: "draft", Version: 1,
	}
	// Verification expired exactly one day before the reference time.
	verified := reference.AddDate(0, 0, -31)
	safeguards := []model.Safeguard{
		{ID: 1, Name: "PSV", SafeguardType: "relief", IndependenceKey: "PSV-1",
			Effectiveness: 0.9, TestIntervalDays: 30, LastVerifiedAt: &verified, LifecycleState: "active"},
	}
	legacy, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, safeguards, reference, 0))
	if err != nil {
		t.Fatalf("legacy evaluation failed: %v", err)
	}
	if legacy.CoverageScore != 0 {
		t.Fatalf("expired layer must be excluded with zero grace days, score=%v", legacy.CoverageScore)
	}
	if len(legacy.Explanation.Layers) != 0 {
		t.Fatalf("grace-era layer evidence must be omitted without grace, got %#v", legacy.Explanation.Layers)
	}
	// Legacy rejection reason survives in the scoring trace eligibility step.
	var sawLegacyReason bool
	for _, step := range legacy.Explanation.ScoreSteps {
		if step.Rule == "eligibility-filter" && strings.Contains(step.Explanation, "verification expired at") {
			sawLegacyReason = true
		}
	}
	if !sawLegacyReason {
		t.Fatalf("zero-grace run must keep the legacy eligibility-filter reason: %#v", legacy.Explanation.ScoreSteps)
	}
	if legacy.Explanation.GraceDays != 0 || legacy.Explanation.GracePolicy != "" {
		t.Fatal("zero-grace explanation must not carry grace metadata")
	}
	// Snapshot and explanation JSON must not carry grace-era keys at zero days.
	if contains(legacy.SnapshotJSON, "verification_grace_days") {
		t.Fatalf("zero-grace snapshot must be byte-compatible, snapshot=%s", legacy.SnapshotJSON)
	}
	if contains(legacy.ExplanationJSON, "grace_days") || contains(legacy.ExplanationJSON, "layers") {
		t.Fatalf("zero-grace explanation must be byte-compatible, explanation=%s", legacy.ExplanationJSON)
	}
}

// Inside the grace window the layer participates at half effectiveness.
func TestGraceWindowCountsHalfEffectiveness(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	node := model.ProcessNode{ID: 1, NodeCode: "V-1", Name: "Vessel"}
	scenario := model.DeviationScenario{
		ID: 1, Guideword: "more", Parameter: "pressure",
		Cause: "blocked outlet", Consequence: "rupture", Likelihood: 3, Severity: 5,
		ScenarioState: "draft", Version: 1,
	}
	// Expires one day before reference; grace window is 7 days. The ledger
	// has already auto-flipped the lifecycle to "expired" (review record not
	// entered yet), which the grace window must still rescue at half value.
	verified := reference.AddDate(0, 0, -31)
	safeguards := []model.Safeguard{
		{ID: 1, Name: "PSV", SafeguardType: "relief", IndependenceKey: "PSV-1",
			Effectiveness: 0.8, TestIntervalDays: 30, LastVerifiedAt: &verified, LifecycleState: "expired"},
	}
	result, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, safeguards, reference, 7))
	if err != nil {
		t.Fatalf("grace evaluation failed: %v", err)
	}
	// Counted effectiveness = 0.8 * 0.5 = 0.4 -> 40% coverage.
	if result.CoverageScore != 40 {
		t.Fatalf("grace layer score = %v, want 40", result.CoverageScore)
	}
	layer := findLayer(result.Explanation.Layers, 1)
	if layer == nil || layer.Tier != TierGrace || !layer.Eligible {
		t.Fatalf("ledger-expired layer should be rescued by the grace tier, got %#v", layer)
	}
	if layer.CountedEffectiveness != 0.4 || layer.RegisteredEffectiveness != 0.8 {
		t.Fatalf("unexpected effectiveness split: %#v", layer)
	}
	if layer.GraceEndsAt == nil {
		t.Fatal("grace layer must expose grace end time")
	}
	if result.Explanation.GraceDays != 7 {
		t.Fatalf("explanation grace days = %d, want 7", result.Explanation.GraceDays)
	}
	var sawGraceStep bool
	for _, step := range result.Explanation.ScoreSteps {
		if step.Rule == "grace-window-layer-combination" {
			sawGraceStep = true
		}
	}
	if !sawGraceStep {
		t.Fatalf("scoring trace must flag the grace-tier layer: %#v", result.Explanation.ScoreSteps)
	}
}

// Once the grace window closes the layer is excluded again, even with grace
// days configured.
func TestGraceWindowExpiryExcludesLayer(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	node := model.ProcessNode{ID: 1, NodeCode: "V-1", Name: "Vessel"}
	scenario := model.DeviationScenario{
		ID: 1, Guideword: "more", Parameter: "pressure",
		Cause: "blocked outlet", Consequence: "rupture", Likelihood: 3, Severity: 5,
		ScenarioState: "draft", Version: 1,
	}
	// Expires 31 days before reference; a 7-day grace window has already ended.
	verified := reference.AddDate(0, 0, -61)
	safeguards := []model.Safeguard{
		{ID: 1, Name: "PSV", SafeguardType: "relief", IndependenceKey: "PSV-1",
			Effectiveness: 0.8, TestIntervalDays: 30, LastVerifiedAt: &verified, LifecycleState: "active"},
	}
	result, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, safeguards, reference, 7))
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if result.CoverageScore != 0 {
		t.Fatalf("layer beyond grace window must be excluded, score=%v", result.CoverageScore)
	}
	layer := findLayer(result.Explanation.Layers, 1)
	if layer == nil || layer.Tier != "rejected" || layer.Eligible {
		t.Fatalf("layer should be rejected after grace window, got %#v", layer)
	}
}

// The frozen grace window must survive replay: an old evaluation frozen with
// grace=7 replays identically even if the evaluator caller now passes zero.
func TestGraceWindowIsFrozenAndReplaysDeterministically(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	node := model.ProcessNode{ID: 1, NodeCode: "V-1", Name: "Vessel"}
	scenario := model.DeviationScenario{
		ID: 1, Guideword: "more", Parameter: "pressure",
		Cause: "blocked outlet", Consequence: "rupture", Likelihood: 3, Severity: 5,
		ScenarioState: "draft", Version: 1,
	}
	verified := reference.AddDate(0, 0, -31)
	safeguards := []model.Safeguard{
		{ID: 1, Name: "PSV", SafeguardType: "relief", IndependenceKey: "PSV-1",
			Effectiveness: 0.8, TestIntervalDays: 30, LastVerifiedAt: &verified, LifecycleState: "active"},
	}
	evaluator := NewEvaluator()
	first, err := evaluator.Evaluate(NewSnapshot(node, scenario, safeguards, reference, 7))
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	passed, replayed, err := evaluator.Replay(first.SnapshotJSON, first.InputHash, first.CoverageScore)
	if err != nil || !passed {
		t.Fatalf("replay failed: passed=%t err=%v", passed, err)
	}
	if replayed.CoverageScore != 40 || replayed.Explanation.GraceDays != 7 {
		t.Fatalf("replay must use frozen grace window: score=%v days=%d", replayed.CoverageScore, replayed.Explanation.GraceDays)
	}
	layer := findLayer(replayed.Explanation.Layers, 1)
	if layer == nil || layer.Tier != TierGrace {
		t.Fatalf("replayed layer must retain grace tier, got %#v", layer)
	}
}

// A deliberately retired layer (invalid) is never rescued by the grace window.
func TestGraceWindowDoesNotRescueRetiredLayers(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	verified := reference.AddDate(0, 0, -31)
	cases := map[string]string{"invalid": "invalid", "pending": "pending"}
	for name, state := range cases {
		safeguards := []SnapshotSafeguard{{
			ID: 1, Name: "PSV", IndependenceKey: "PSV-1", Effectiveness: 0.8,
			TestIntervalDays: 30, LastVerifiedAt: &verified, LifecycleState: state,
		}}
		result := ResolveIndependence(safeguards, reference, 7)
		if len(result.Retained) != 0 || len(result.Rejected) != 1 {
			t.Fatalf("%s layer must stay outside calculation: %#v", name, result)
		}
		layer := result.Layers[0]
		if layer.Tier != "rejected" || layer.RejectReason != fmt.Sprintf("lifecycle state %q is not active", state) {
			t.Fatalf("%s layer rejection reason mismatch: %#v", name, layer)
		}
	}
}

// Boundary: at the exact grace-end instant the layer is still in the window;
// one second later it is excluded.
func TestGraceBoundaryAtWindowEnd(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	verified := reference.AddDate(0, 0, -30) // expires exactly at reference
	safeguards := []SnapshotSafeguard{{
		ID: 1, Name: "PSV", IndependenceKey: "PSV-1",
		Effectiveness: 0.8, TestIntervalDays: 30, LastVerifiedAt: &verified, LifecycleState: "active",
	}}
	atExpiry := ResolveIndependence(safeguards, reference, 7)
	if len(atExpiry.Retained) != 1 || atExpiry.Retained[0].Tier != TierValid {
		t.Fatalf("at expiry instant the layer stays in the valid tier: %#v", atExpiry)
	}
	atGraceEnd := ResolveIndependence(safeguards, reference.AddDate(0, 0, 7), 7)
	if len(atGraceEnd.Retained) != 1 || atGraceEnd.Retained[0].Tier != TierGrace {
		t.Fatalf("at grace-end instant the layer must still be grace tier: %#v", atGraceEnd)
	}
	afterGraceEnd := ResolveIndependence(safeguards, reference.AddDate(0, 0, 7).Add(time.Second), 7)
	if len(afterGraceEnd.Retained) != 0 || len(afterGraceEnd.Rejected) != 1 {
		t.Fatalf("one second past grace end the layer must be rejected: %#v", afterGraceEnd)
	}
}

func findLayer(layers []dto.LayerEligibilityResponse, id uint) *dto.LayerEligibilityResponse {
	for i := range layers {
		if layers[i].ID == id {
			return &layers[i]
		}
	}
	return nil
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
