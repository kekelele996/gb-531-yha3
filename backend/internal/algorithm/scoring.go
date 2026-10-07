package algorithm
import (
	"fmt"
	"hazop-safeguard-coverage/backend/internal/dto"
	"math"
	"sort"
)
const coveredThreshold = 0.5
type ScoreResult struct {
	CoverageScore  float64
	Paths          []dto.CoveragePathResponse
	UncoveredPaths []dto.CoveragePathResponse
	Steps          []dto.ScoreStepResponse
	RiskBefore     string
	RiskAfter      string
}
func CalculateScore(graph Graph, scenario SnapshotScenario, safeguards []CountedSafeguard, rejected []RejectedSafeguard) ScoreResult {
	ordered := append([]CountedSafeguard(nil), safeguards...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Safeguard.IndependenceKey == ordered[j].Safeguard.IndependenceKey {
			return ordered[i].Safeguard.ID < ordered[j].Safeguard.ID
		}
		return ordered[i].Safeguard.IndependenceKey < ordered[j].Safeguard.IndependenceKey
	})
	combined := 0.0
	remainingProbability := 1.0
	steps := make([]dto.ScoreStepResponse, 0, len(ordered)+len(rejected)+2)
	stepNumber := 1
	for _, layer := range ordered {
		safeguard := layer.Safeguard
		before := 1 - remainingProbability
		remainingProbability *= 1 - layer.CountedEffectiveness
		combined = 1 - remainingProbability
		// For valid layers the step text is kept identical to pre-grace runs;
		// grace layers carry an explicit half-effectiveness trace.
		var rule, input, explanation string
		if layer.Tier == TierGrace {
			rule = "grace-window-layer-combination"
			input = fmt.Sprintf(
				"safeguard=%d key=%s effectiveness=%.4f counted_effectiveness=%.4f tier=%s",
				safeguard.ID, safeguard.IndependenceKey, safeguard.Effectiveness, layer.CountedEffectiveness, TierGrace,
			)
			explanation = fmt.Sprintf(
				"Verification expired at %s but the layer is inside its %d-day grace window (until %s); effectiveness is counted at %.0f%%: %.4f.",
				layer.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"), graceWindowDays(layer),
				layer.GraceEndsAt.UTC().Format("2006-01-02T15:04:05Z"), GraceEffectivenessFactor*100, layer.CountedEffectiveness,
			)
		} else {
			rule = "independent-layer-combination"
			input = fmt.Sprintf("safeguard=%d key=%s effectiveness=%.4f", safeguard.ID, safeguard.IndependenceKey, safeguard.Effectiveness)
			explanation = "Independent effectiveness is combined as 1 - product(1 - effectiveness)."
		}
		steps = append(steps, dto.ScoreStepResponse{
			Step: stepNumber, Rule: rule, Input: input,
			Contribution: round4(combined - before), RunningScore: round4(combined * 100),
			Explanation: explanation,
		})
		stepNumber++
	}
	for _, item := range rejected {
		steps = append(steps, dto.ScoreStepResponse{
			Step: stepNumber, Rule: "eligibility-filter", Input: fmt.Sprintf("safeguard=%d", item.ID),
			Contribution: 0, RunningScore: round4(combined * 100), Explanation: item.Reason,
		})
		stepNumber++
	}
	paths := make([]dto.CoveragePathResponse, 0, len(graph.Paths))
	ids := make([]uint, 0, len(ordered))
	keys := make([]string, 0, len(ordered))
	for _, layer := range ordered {
		ids = append(ids, layer.Safeguard.ID)
		keys = append(keys, layer.Safeguard.IndependenceKey)
	}
	covered := combined >= coveredThreshold
	for _, path := range graph.Paths {
		reason := fmt.Sprintf("combined independent protection %.2f%% meets %.0f%% threshold", combined*100, coveredThreshold*100)
		if !covered {
			reason = fmt.Sprintf("combined independent protection %.2f%% is below %.0f%% threshold", combined*100, coveredThreshold*100)
		}
		pathResult := dto.CoveragePathResponse{
			PathID: path.ID, NodeCode: path.NodeCode, Cause: path.Cause, Consequence: path.Consequence,
			SafeguardIDs: append([]uint(nil), ids...), IndependenceKeys: append([]string(nil), keys...),
			CombinedProtection: round4(combined), Covered: covered, Reason: reason,
		}
		paths = append(paths, pathResult)
	}
	uncovered := make([]dto.CoveragePathResponse, 0)
	for _, path := range paths {
		if !path.Covered {
			uncovered = append(uncovered, path)
		}
	}
	coverageScore := round4(combined * 100)
	initialRisk := scenario.Likelihood * scenario.Severity
	residualRisk := int(math.Ceil(float64(initialRisk) * (1 - combined)))
	if residualRisk < 1 {
		residualRisk = 1
	}
	steps = append(steps, dto.ScoreStepResponse{
		Step: stepNumber, Rule: "residual-risk", Input: fmt.Sprintf("initial=%d protection=%.4f", initialRisk, combined),
		Contribution: 0, RunningScore: coverageScore,
		Explanation: fmt.Sprintf("Residual risk index is ceil(%d * (1 - %.4f)) = %d.", initialRisk, combined, residualRisk),
	})
	return ScoreResult{
		CoverageScore: coverageScore, Paths: paths, UncoveredPaths: uncovered, Steps: steps,
		RiskBefore: dto.RiskRank(initialRisk), RiskAfter: dto.RiskRank(residualRisk),
	}
}
func graceWindowDays(layer CountedSafeguard) int {
	if layer.GraceEndsAt == nil {
		return 0
	}
	return int(layer.GraceEndsAt.Sub(layer.ExpiresAt).Hours() / 24)
}
func round4(value float64) float64 { return math.Round(value*10000) / 10000 }
