package receipt

import (
	"testing"
	"time"

	corecrypto "github.com/loesungerdechris-lang/sentinel-core-go/internal/crypto"
)

func validReceipt() Receipt {
	return Receipt{
		Version:      "sentinel.receipt.v0.1",
		ReceiptID:    "receipt-1",
		EvidenceHash: corecrypto.SHA256Hex([]byte("evidence")),
		PolicyID:     "policy://test/v0.1",
		Decision:     "OBSERVE",
		Reason:       Reason{Code: "TEST", Detail: "fixture"},
		IssuedAt:     time.Date(2026, 6, 24, 8, 0, 0, 0, time.UTC),
		Signature:    Signature{Format: "detached", Alg: "Ed25519", KeyID: "test-key", Value: "test-signature"},
	}
}

func TestReceiptValidateStructureAcceptsValidReceipt(t *testing.T) {
	if err := validReceipt().ValidateStructure(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReceiptValidateStructureRejectsBadDigest(t *testing.T) {
	r := validReceipt()
	r.EvidenceHash = "bad"
	if err := r.ValidateStructure(); err == nil {
		t.Fatal("expected error")
	}
}
