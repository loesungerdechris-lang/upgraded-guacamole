package receipt

import (
	"fmt"
	"time"

	corecrypto "github.com/loesungerdechris-lang/sentinel-core-go/internal/crypto"
)

type Signature struct {
	Format string `json:"format"`
	Alg    string `json:"alg"`
	KeyID  string `json:"key_id"`
	Value  string `json:"value"`
}

type Reason struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type Receipt struct {
	Version      string    `json:"version"`
	ReceiptID    string    `json:"receipt_id"`
	EvidenceHash string    `json:"evidence_hash"`
	PolicyID     string    `json:"policy_id"`
	Decision     string    `json:"decision"`
	Reason       Reason    `json:"reason"`
	IssuedAt     time.Time `json:"issued_at"`
	Signature    Signature `json:"signature"`
}

func knownDecision(value string) bool {
	switch value {
	case "ALLOW", "OBSERVE", "FLAG", "REQUIRE_EVIDENCE", "BLOCK", "ESCALATE_HUMAN":
		return true
	default:
		return false
	}
}

func (r Receipt) ValidateStructure() error {
	if r.Version == "" || r.ReceiptID == "" {
		return fmt.Errorf("version and receipt_id are required")
	}
	if err := corecrypto.ValidateSHA256Digest(r.EvidenceHash); err != nil {
		return fmt.Errorf("evidence_hash: %w", err)
	}
	if r.PolicyID == "" || r.Decision == "" {
		return fmt.Errorf("policy_id and decision are required")
	}
	if !knownDecision(r.Decision) {
		return fmt.Errorf("receipt decision is not recognized")
	}
	if r.Reason.Code == "" {
		return fmt.Errorf("reason.code is required")
	}
	if r.IssuedAt.IsZero() {
		return fmt.Errorf("issued_at is required")
	}
	if r.Signature.Format == "" || r.Signature.Alg == "" || r.Signature.KeyID == "" || r.Signature.Value == "" {
		return fmt.Errorf("signature fields are required")
	}
	return nil
}
