package registry

import "fmt"

type TrustKeyStatus string

const (
	TrustKeyActive  TrustKeyStatus = "active"
	TrustKeyRevoked TrustKeyStatus = "revoked"
)

type TrustKey struct {
	KeyID     string         `json:"key_id"`
	Role      string         `json:"role"`
	Alg       string         `json:"alg"`
	PublicKey string         `json:"public_key"`
	Status    TrustKeyStatus `json:"status"`
}

type TrustRegistry struct {
	Keys map[string]TrustKey `json:"keys"`
}

func (r TrustRegistry) ResolveActive(keyID string) (TrustKey, error) {
	key, ok := r.Keys[keyID]
	if !ok {
		return TrustKey{}, fmt.Errorf("trust key %q not found", keyID)
	}
	if key.Status != TrustKeyActive {
		return TrustKey{}, fmt.Errorf("trust key %q is not active", keyID)
	}
	return key, nil
}
