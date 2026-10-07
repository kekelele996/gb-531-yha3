package algorithm

import (
	"fmt"
	"hazop-safeguard-coverage/backend/internal/dto"
	"math"
	"sort"
	"time"
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

func CalculateScore(graph Graph, scenario SnapshotScenario, retained []ResolvedSafeguard, rejected []RejectedSafeguard) ScoreResult {
	ordered := append([]ResolvedSafeguard(nil), retained...)
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
		before := 1 - remainingProbability
		remainingProbability *= 1 - layer.AppliedEffectiveness
		combined = 1 - remainingProbability
		steps = append(steps, dto.ScoreStepResponse{
			Step: stepNumber, Rule: "independent-layer-combination", Tier: string(layer.Tier),
			Input: fmt.Sprintf("safeguard=%d key=%s tier=%s nominal=%.4f applied=%.4f",
				layer.Safeguard.ID, layer.Safeguard.IndependenceKey, layer.Tier,
				layer.Safeguard.Effectiveness, layer.AppliedEffectiveness),
			Contribution: round4(combined - before), RunningScore: round4(combined * 100),
			Explanation: layer.Note,
		})
		stepNumber++
	}
	for _, item := range rejected {
		steps = append(steps, dto.ScoreStepResponse{
			Step: stepNumber, Rule: "eligibility-filter", Tier: string(item.Tier),
			Input:        fmt.Sprintf("safeguard=%d", item.ID),
			Contribution: 0, RunningScore: round4(combined * 100), Explanation: item.Reason,
		})
		stepNumber++
	}
	pathLayers := make([]dto.SafeguardLayerResponse, 0, len(ordered))
	ids := make([]uint, 0, len(ordered))
	keys := make([]string, 0, len(ordered))
	for _, layer := range ordered {
		ids = append(ids, layer.Safeguard.ID)
		keys = append(keys, layer.Safeguard.IndependenceKey)
		pathLayers = append(pathLayers, layerResponse(layer))
	}
	covered := combined >= coveredThreshold
	paths := make([]dto.CoveragePathResponse, 0, len(graph.Paths))
	for _, path := range graph.Paths {
		reason := fmt.Sprintf("combined independent protection %.2f%% meets %.0f%% threshold", combined*100, coveredThreshold*100)
		if !covered {
			reason = fmt.Sprintf("combined independent protection %.2f%% is below %.0f%% threshold", combined*100, coveredThreshold*100)
		}
		pathResult := dto.CoveragePathResponse{
			PathID: path.ID, NodeCode: path.NodeCode, Cause: path.Cause, Consequence: path.Consequence,
			SafeguardIDs: append([]uint(nil), ids...), IndependenceKeys: append([]string(nil), keys...),
			CombinedProtection: round4(combined), Covered: covered, Reason: reason,
			Layers: append([]dto.SafeguardLayerResponse(nil), pathLayers...),
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

func layerResponse(layer ResolvedSafeguard) dto.SafeguardLayerResponse {
	response := dto.SafeguardLayerResponse{
		SafeguardID: layer.Safeguard.ID, Name: layer.Safeguard.Name,
		IndependenceKey: layer.Safeguard.IndependenceKey, Tier: string(layer.Tier),
		NominalEffectiveness: round4(layer.Safeguard.Effectiveness),
		AppliedEffectiveness: round4(layer.AppliedEffectiveness),
		Note:                 layer.Note,
	}
	if !layer.ExpiresAt.IsZero() {
		response.ExpiresAt = layer.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if layer.GraceUntil != nil {
		response.GraceUntil = layer.GraceUntil.UTC().Format(time.RFC3339)
	}
	return response
}

func ledgerResponse(ledger []ResolvedSafeguard) []dto.SafeguardLayerResponse {
	responses := make([]dto.SafeguardLayerResponse, 0, len(ledger))
	for _, layer := range ledger {
		responses = append(responses, layerResponse(layer))
	}
	return responses
}

func round4(value float64) float64 { return math.Round(value*10000) / 10000 }
