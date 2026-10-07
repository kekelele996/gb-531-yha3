package algorithm

import (
	"encoding/json"
	"testing"
	"time"

	"hazop-safeguard-coverage/backend/internal/model"
)

func newGraceFixture(t *testing.T, reference time.Time, verified time.Time) (model.ProcessNode, model.DeviationScenario, []model.Safeguard) {
	t.Helper()
	node := model.ProcessNode{ID: 3, NodeCode: "T-3", Name: "Tank"}
	scenario := model.DeviationScenario{
		ID: 3, Guideword: "more", Parameter: "level",
		Cause: "inlet valve fails open", Consequence: "tank overfill spill",
		Likelihood: 3, Severity: 4, ScenarioState: "analyzed", Version: 1,
	}
	safeguards := []model.Safeguard{
		{ID: 10, Name: "High-high level trip", IndependenceKey: "SIS-L", Effectiveness: 0.8,
			TestIntervalDays: 30, LastVerifiedAt: &verified, LifecycleState: "active"},
	}
	return node, scenario, safeguards
}

func TestGraceWindowCountsLayerAtHalfEffectiveness(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	// Verification expired on 2026-08-30; reference is day 2 of a 7-day window.
	verified := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	node, scenario, safeguards := newGraceFixture(t, reference, verified)

	result, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, safeguards, reference, 7))
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if result.CoverageScore != 40 {
		t.Fatalf("coverage score = %v, want 40 (0.8 nominal at 50%% grace credit)", result.CoverageScore)
	}
	if len(result.Explanation.Layers) != 1 {
		t.Fatalf("layers = %d, want 1", len(result.Explanation.Layers))
	}
	layer := result.Explanation.Layers[0]
	if layer.Tier != "grace" || layer.AppliedEffectiveness != 0.4 || layer.NominalEffectiveness != 0.8 {
		t.Fatalf("unexpected layer tier/effectiveness: %#v", layer)
	}
	if layer.GraceUntil != "2026-09-06T00:00:00Z" {
		t.Fatalf("grace_until = %q, want 2026-09-06T00:00:00Z", layer.GraceUntil)
	}
	step := result.Explanation.ScoreSteps[0]
	if step.Tier != "grace" || step.Contribution != 0.4 {
		t.Fatalf("unexpected grace score step: %#v", step)
	}
	if result.Explanation.GraceDays != 7 || result.Explanation.GracePolicy == "" {
		t.Fatalf("grace policy missing from explanation: %#v", result.Explanation)
	}
	paths := result.Explanation.Paths
	if len(paths) != 1 || paths[0].Layers[0].Tier != "grace" || paths[0].Covered {
		t.Fatalf("path must expose the grace tier and stay below the 50%% threshold: %#v", paths)
	}
}

func TestGraceWindowEndBoundaryStillCounts(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	reference := expires.AddDate(0, 0, 7) // exactly grace_until
	verified := expires.AddDate(0, 0, -30)
	node, scenario, safeguards := newGraceFixture(t, reference, verified)

	result, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, safeguards, reference, 7))
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if result.Explanation.Layers[0].Tier != "grace" {
		t.Fatalf("tier = %q, want grace at the inclusive end of the window", result.Explanation.Layers[0].Tier)
	}
}

func TestLayerBeyondGraceWindowIsExcluded(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC) // one day past grace_until
	verified := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	node, scenario, safeguards := newGraceFixture(t, reference, verified)

	result, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, safeguards, reference, 7))
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if result.CoverageScore != 0 {
		t.Fatalf("coverage score = %v, want 0 when the layer is past grace", result.CoverageScore)
	}
	layer := result.Explanation.Layers[0]
	if layer.Tier != "excluded" || layer.AppliedEffectiveness != 0 {
		t.Fatalf("unexpected layer: %#v", layer)
	}
}

func TestGraceZeroBehavesExactlyAsBefore(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	verified := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	node, scenario, safeguards := newGraceFixture(t, reference, verified)

	result, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, safeguards, reference, 0))
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if result.CoverageScore != 0 || result.Explanation.Layers[0].Tier != "excluded" {
		t.Fatalf("expired layer must be excluded without grace: %#v", result.Explanation.Layers[0])
	}
	// omitempty keeps grace=0 out of the frozen snapshot, so legacy hashes stay identical.
	var raw map[string]any
	if err := json.Unmarshal([]byte(result.SnapshotJSON), &raw); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if _, present := raw["verification_grace_days"]; present {
		t.Fatal("verification_grace_days must be omitted from the zero-grace snapshot")
	}
}

func TestGraceWindowIsFrozenAndReplayable(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	verified := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	node, scenario, safeguards := newGraceFixture(t, reference, verified)

	evaluator := NewEvaluator()
	frozen := NewSnapshot(node, scenario, safeguards, reference, 7)
	result, err := evaluator.Evaluate(frozen)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	passed, replayed, err := evaluator.Replay(result.SnapshotJSON, result.InputHash, result.CoverageScore)
	if err != nil || !passed || replayed.CoverageScore != 40 {
		t.Fatalf("replay failed: passed=%t score=%v err=%v", passed, replayed.CoverageScore, err)
	}
	// The same inputs evaluated later with a different grace config hash differently.
	other, err := evaluator.Evaluate(NewSnapshot(node, scenario, safeguards, reference, 0))
	if err != nil {
		t.Fatalf("comparison evaluation failed: %v", err)
	}
	if other.InputHash == result.InputHash || other.CoverageScore == result.CoverageScore {
		t.Fatal("changing the grace window must change the frozen input hash and the score")
	}
}

func TestGraceWindowRecoversDateDrivenExpiredLifecycle(t *testing.T) {
	t.Parallel()
	// The register stamps lifecycle_state="expired" as soon as the verification
	// date passes the interval; that overdue flag must not block grace credit.
	reference := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	verified := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	node, scenario, safeguards := newGraceFixture(t, reference, verified)
	safeguards[0].LifecycleState = "expired"

	result, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, safeguards, reference, 7))
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	layer := result.Explanation.Layers[0]
	if layer.Tier != "grace" || layer.AppliedEffectiveness != 0.4 {
		t.Fatalf("date-driven expired layer should be recovered inside grace, got %#v", layer)
	}
}

func TestExplicitlyInvalidLayerIsNeverCredited(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	verified := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	node, scenario, safeguards := newGraceFixture(t, reference, verified)
	safeguards[0].LifecycleState = "invalid"

	result, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, safeguards, reference, 30))
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	layer := result.Explanation.Layers[0]
	if layer.Tier != "excluded" || result.CoverageScore != 0 {
		t.Fatalf("explicitly invalid layer must stay excluded even with a wide grace window, got %#v", layer)
	}
}

func TestDeduplicationTieBreakUsesAppliedGraceEffectiveness(t *testing.T) {
	t.Parallel()
	reference := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	expires := reference.AddDate(0, 0, -2)
	verifiedA := expires.AddDate(0, 0, -30)
	verifiedB := expires.AddDate(0, 0, -100)
	node := model.ProcessNode{ID: 5, NodeCode: "P-5", Name: "Pump"}
	scenario := model.DeviationScenario{
		ID: 5, Guideword: "no", Parameter: "flow", Cause: "pump trip",
		Consequence: "dry run", Likelihood: 2, Severity: 3, ScenarioState: "analyzed", Version: 1,
	}
	safeguards := []model.Safeguard{
		{ID: 1, Name: "Overdue trip", IndependenceKey: "KEY-1", Effectiveness: 0.9,
			TestIntervalDays: 30, LastVerifiedAt: &verifiedA, LifecycleState: "active"}, // grace: 0.45
		{ID: 2, Name: "Current trip", IndependenceKey: "KEY-1", Effectiveness: 0.4,
			TestIntervalDays: 100, LastVerifiedAt: &verifiedB, LifecycleState: "active"}, // eligible: 0.40
	}
	result, err := NewEvaluator().Evaluate(NewSnapshot(node, scenario, safeguards, reference, 7))
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if len(result.Explanation.Deduplicated) != 1 {
		t.Fatalf("expected one dedupe group, got %#v", result.Explanation.Deduplicated)
	}
	group := result.Explanation.Deduplicated[0]
	if group.KeptID != 1 || group.KeptTier != "grace" {
		t.Fatalf("grace layer with higher applied effectiveness should be retained: %#v", group)
	}
	// Discounted 0.45 wins over the eligible 0.40 layer.
	if result.CoverageScore != 45 {
		t.Fatalf("coverage score = %v, want 45", result.CoverageScore)
	}
}
