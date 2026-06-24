package evidence

import (
	"testing"
	"time"

	corecrypto "github.com/loesungerdechris-lang/sentinel-core-go/internal/crypto"
)

func TestVerifyChainAcceptsGenesisRecord(t *testing.T) {
	record := Record{
		Version:      "sentinel.evidence.v0.1",
		Sequence:     1,
		Subject:      "fixture",
		Kind:         "TEST",
		PayloadHash:  corecrypto.SHA256Hex([]byte("payload")),
		PreviousHash: GenesisPreviousHash,
		PolicyID:     "policy://test/v0.1",
		Actor:        "tester",
		ActorRole:    "auditor",
		IssuedAt:     time.Date(2026, 6, 24, 8, 0, 0, 0, time.UTC),
	}
	result := VerifyChain([]Record{record})
	if !result.OK {
		t.Fatalf("expected valid chain, got errors: %#v", result.Errors)
	}
}

func TestVerifyChainRejectsPreviousHashMismatch(t *testing.T) {
	record := Record{
		Version:      "sentinel.evidence.v0.1",
		Sequence:     1,
		Subject:      "fixture",
		Kind:         "TEST",
		PayloadHash:  corecrypto.SHA256Hex([]byte("payload")),
		PreviousHash: corecrypto.SHA256Hex([]byte("wrong")),
		PolicyID:     "policy://test/v0.1",
		Actor:        "tester",
		ActorRole:    "auditor",
		IssuedAt:     time.Date(2026, 6, 24, 8, 0, 0, 0, time.UTC),
	}
	result := VerifyChain([]Record{record})
	if result.OK {
		t.Fatal("expected invalid chain")
	}
}
