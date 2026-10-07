package algorithm
import (
	"encoding/json"
	"fmt"
	"hazop-safeguard-coverage/backend/internal/dto"
	"hazop-safeguard-coverage/backend/internal/util"
)
const SafetyBoundary = "Offline decision support only. Results cannot replace a licensed process-safety professional's judgment and cannot issue equipment control commands."

// GracePolicyNote documents the single effectiveness rule used inside the
// verification grace window so every stored explanation is self-describing.
const GracePolicyNote = "Safeguards whose verification expired but are still within the configured grace window participate in coverage at 50% of their registered effectiveness; layers outside the window are excluded."
type EvaluationResult struct {
	SnapshotJSON     string
	InputHash        string
	CoverageScore    float64
	UncoveredJSON    string
	DeduplicatedJSON string
	ExplanationJSON  string
	RiskBefore       string
	RiskAfter        string
	Explanation      dto.EvaluationExplanation
}
type Evaluator struct{}
func NewEvaluator() *Evaluator { return &Evaluator{} }
func (e *Evaluator) Evaluate(snapshot Snapshot) (EvaluationResult, error) {
	if snapshot.AlgorithmVersion != Version {
		return EvaluationResult{}, fmt.Errorf("algorithm version mismatch: got %q want %q", snapshot.AlgorithmVersion, Version)
	}
	if snapshot.Node.ID == 0 || snapshot.Scenario.ID == 0 {
		return EvaluationResult{}, fmt.Errorf("snapshot requires persisted node and scenario")
	}
	if snapshot.ReferenceTime.IsZero() {
		return EvaluationResult{}, fmt.Errorf("snapshot reference time is required")
	}
	snapshotJSON, err := util.CanonicalJSON(snapshot)
	if err != nil {
		return EvaluationResult{}, fmt.Errorf("serialize evaluation snapshot: %w", err)
	}
	graph := BuildGraph(snapshot)
	independence := ResolveIndependence(snapshot.Safeguards, snapshot.ReferenceTime, snapshot.VerificationGraceDays)
	score := CalculateScore(graph, snapshot.Scenario, independence.Retained, independence.Rejected)
	graceCount := 0
	for _, layer := range independence.Retained {
		if layer.Tier == TierGrace {
			graceCount++
		}
	}
	summary := fmt.Sprintf("%d cause-to-consequence paths evaluated; %d paths are below the protection threshold.", len(score.Paths), len(score.UncoveredPaths))
	explanation := dto.EvaluationExplanation{
		Summary: summary,
		Paths:   score.Paths, ScoreSteps: score.Steps, Deduplicated: independence.Deduplicated,
		BoundaryNote: SafetyBoundary, ReferenceTime: snapshot.ReferenceTime,
	}
	// Grace-era evidence is only attached when a grace window is configured,
	// so zero-grace explanations stay byte-identical to the legacy algorithm.
	if snapshot.VerificationGraceDays > 0 {
		explanation.Summary = fmt.Sprintf("%s %d safeguarded layer(s) are inside the %d-day verification grace window and are counted at half effectiveness.",
			summary, graceCount, snapshot.VerificationGraceDays)
		explanation.Layers = independence.Layers
		explanation.GraceDays = snapshot.VerificationGraceDays
		explanation.GracePolicy = GracePolicyNote
	}
	uncoveredJSON, err := util.CanonicalJSON(score.UncoveredPaths)
	if err != nil {
		return EvaluationResult{}, fmt.Errorf("serialize uncovered paths: %w", err)
	}
	deduplicatedJSON, err := util.CanonicalJSON(independence.Deduplicated)
	if err != nil {
		return EvaluationResult{}, fmt.Errorf("serialize deduplicated safeguards: %w", err)
	}
	explanationJSON, err := util.CanonicalJSON(explanation)
	if err != nil {
		return EvaluationResult{}, fmt.Errorf("serialize scoring explanation: %w", err)
	}
	return EvaluationResult{
		SnapshotJSON: snapshotJSON, InputHash: util.HashString(snapshotJSON), CoverageScore: score.CoverageScore,
		UncoveredJSON: uncoveredJSON, DeduplicatedJSON: deduplicatedJSON,
		ExplanationJSON: explanationJSON, RiskBefore: score.RiskBefore, RiskAfter: score.RiskAfter,
		Explanation: explanation,
	}, nil
}
func (e *Evaluator) Replay(snapshotJSON string, expectedHash string, expectedScore float64) (bool, EvaluationResult, error) {
	if util.HashString(snapshotJSON) != expectedHash {
		return false, EvaluationResult{}, fmt.Errorf("stored snapshot hash does not match stored input hash")
	}
	var snapshot Snapshot
	if err := json.Unmarshal([]byte(snapshotJSON), &snapshot); err != nil {
		return false, EvaluationResult{}, fmt.Errorf("decode frozen snapshot: %w", err)
	}
	result, err := e.Evaluate(snapshot)
	if err != nil {
		return false, EvaluationResult{}, fmt.Errorf("replay evaluation: %w", err)
	}
	passed := result.InputHash == expectedHash && result.CoverageScore == expectedScore
	return passed, result, nil
}
