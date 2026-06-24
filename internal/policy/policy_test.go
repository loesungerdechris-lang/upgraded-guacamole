package policy

import "testing"

func TestDecideRequiresEvidence(t *testing.T) {
	p := Policy{ID: "policy://test", Version: "v0.1", Gate: GateRequireEvidence}
	decision, err := Decide(p, 0.75)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != DecisionRequire {
		t.Fatalf("expected %s, got %s", DecisionRequire, decision)
	}
}

func TestDecideRejectsUnknownGate(t *testing.T) {
	p := Policy{ID: "policy://test", Version: "v0.1", Gate: Gate("BAD")}
	_, err := Decide(p, 0.75)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecideRejectsInvalidRiskScore(t *testing.T) {
	p := Policy{ID: "policy://test", Version: "v0.1", Gate: GateFlag}
	_, err := Decide(p, 1.5)
	if err == nil {
		t.Fatal("expected error")
	}
}
