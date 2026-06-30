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

func (r TrustRegistry) ResolveActiveForAlg(keyID string, alg string) (TrustKey, error) {
	key, err := r.ResolveActive(keyID)
	if err != nil {
		return TrustKey{}, err
	}
	if alg == "" {
		return TrustKey{}, fmt.Errorf("signature algorithm is required")
	}
	if key.Alg != alg {
		return TrustKey{}, fmt.Errorf("trust key %q algorithm mismatch: registered %q, requested %q", keyID, key.Alg, alg)
	}
	return key, nil
}
