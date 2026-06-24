package evidence

import (
	"encoding/json"
	"fmt"
	"time"

	corecrypto "github.com/loesungerdechris-lang/sentinel-core-go/internal/crypto"
)

const GenesisPreviousHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type Record struct {
	Version      string            `json:"version"`
	Sequence     uint64            `json:"sequence"`
	Subject      string            `json:"subject"`
	Kind         string            `json:"kind"`
	PayloadHash  string            `json:"payload_hash"`
	PreviousHash string            `json:"previous_hash"`
	PolicyID     string            `json:"policy_id"`
	Actor        string            `json:"actor"`
	ActorRole    string            `json:"actor_role"`
	IssuedAt     time.Time         `json:"issued_at"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

func (r Record) Validate() error {
	if r.Version == "" {
		return fmt.Errorf("version is required")
	}
	if r.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	if r.Kind == "" {
		return fmt.Errorf("kind is required")
	}
	if err := corecrypto.ValidateSHA256Digest(r.PayloadHash); err != nil {
		return fmt.Errorf("payload_hash: %w", err)
	}
	if err := corecrypto.ValidateSHA256Digest(r.PreviousHash); err != nil {
		return fmt.Errorf("previous_hash: %w", err)
	}
	if r.PolicyID == "" {
		return fmt.Errorf("policy_id is required")
	}
	if r.Actor == "" || r.ActorRole == "" {
		return fmt.Errorf("actor and actor_role are required")
	}
	if r.IssuedAt.IsZero() {
		return fmt.Errorf("issued_at is required")
	}
	return nil
}

func (r Record) Hash() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return corecrypto.SHA256Hex(canonical), nil
}
