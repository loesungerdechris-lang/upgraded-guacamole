package policy

import (
	"fmt"
	"math"
)

type Gate string

const (
	GateObserve         Gate = "G0_OBSERVE"
	GateFlag            Gate = "G1_FLAG"
	GateRequireEvidence Gate = "G2_REQUIRE_EVIDENCE"
	GateBlock           Gate = "G3_BLOCK"
	GateEscalateHuman   Gate = "G4_ESCALATE_HUMAN"
)

type Decision string

const (
	DecisionAllow    Decision = "ALLOW"
	DecisionObserve  Decision = "OBSERVE"
	DecisionFlag     Decision = "FLAG"
	DecisionRequire  Decision = "REQUIRE_EVIDENCE"
	DecisionBlock    Decision = "BLOCK"
	DecisionEscalate Decision = "ESCALATE_HUMAN"
)

func IsKnownDecision(decision Decision) bool {
	switch decision {
	case DecisionAllow, DecisionObserve, DecisionFlag, DecisionRequire, DecisionBlock, DecisionEscalate:
		return true
	default:
		return false
	}
}

type Policy struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Gate        Gate   `json:"gate"`
	Description string `json:"description"`
}

func (p Policy) Validate() error {
	if p.ID == "" || p.Version == "" {
		return fmt.Errorf("policy id and version are required")
	}
	switch p.Gate {
	case GateObserve, GateFlag, GateRequireEvidence, GateBlock, GateEscalateHuman:
		return nil
	default:
		return fmt.Errorf("unknown policy gate %q", p.Gate)
	}
}

func Decide(p Policy, riskScore float64) (Decision, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if math.IsNaN(riskScore) || riskScore < 0 || riskScore > 1 {
		return "", fmt.Errorf("risk score must be between 0 and 1")
	}
	if riskScore < 0.50 {
		return DecisionObserve, nil
	}
	switch p.Gate {
	case GateObserve:
		return DecisionObserve, nil
	case GateFlag:
		return DecisionFlag, nil
	case GateRequireEvidence:
		return DecisionRequire, nil
	case GateBlock:
		return DecisionBlock, nil
	case GateEscalateHuman:
		return DecisionEscalate, nil
	default:
		return "", fmt.Errorf("unsupported gate %q", p.Gate)
	}
}
