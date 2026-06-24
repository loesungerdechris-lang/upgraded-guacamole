package main

import (
	"encoding/json"
	"fmt"
	"time"

	corecrypto "github.com/loesungerdechris-lang/sentinel-core-go/internal/crypto"
	"github.com/loesungerdechris-lang/sentinel-core-go/internal/evidence"
)

func main() {
	record := evidence.Record{
		Version:      "sentinel.evidence.v0.1",
		Sequence:     1,
		Subject:      "sentinel-core-go-bootstrap",
		Kind:         "BOOTSTRAP",
		PayloadHash:  corecrypto.SHA256Hex([]byte("sentinel-go-bootstrap")),
		PreviousHash: evidence.GenesisPreviousHash,
		PolicyID:     "policy://sentinel/bootstrap/v0.1",
		Actor:        "local-cli",
		ActorRole:    "builder",
		IssuedAt:     time.Now().UTC(),
	}
	hash, err := record.Hash()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	out := map[string]string{"ok": "true", "record_hash": hash}
	_ = json.NewEncoder(newConsoleWriter()).Encode(out)
}

type consoleWriter struct{}

func newConsoleWriter() consoleWriter { return consoleWriter{} }

func (consoleWriter) Write(p []byte) (int, error) {
	return fmt.Print(string(p))
}
