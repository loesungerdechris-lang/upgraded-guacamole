package evidence

import "fmt"

type ChainValidationResult struct {
	OK     bool
	Errors []string
}

func VerifyChain(records []Record) ChainValidationResult {
	result := ChainValidationResult{OK: true}
	previousHash := GenesisPreviousHash

	for i, record := range records {
		if err := record.Validate(); err != nil {
			result.OK = false
			result.Errors = append(result.Errors, fmt.Sprintf("record %d validation failed: %v", i, err))
			continue
		}
		if record.Sequence != uint64(i+1) {
			result.OK = false
			result.Errors = append(result.Errors, fmt.Sprintf("record %d sequence mismatch: got %d want %d", i, record.Sequence, i+1))
		}
		if record.PreviousHash != previousHash {
			result.OK = false
			result.Errors = append(result.Errors, fmt.Sprintf("record %d previous hash mismatch", i))
		}
		hash, err := record.Hash()
		if err != nil {
			result.OK = false
			result.Errors = append(result.Errors, fmt.Sprintf("record %d hash failed: %v", i, err))
			continue
		}
		previousHash = hash
	}

	return result
}
