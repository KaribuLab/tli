package internal

import (
	"encoding/json"
	"testing"
)

func TestExplicitTechnicalErrorNeverSucceeds(t *testing.T) {
	for _, raw := range []string{
		`{"scan_id":"scan","result":{"status":"COMPLETED","coverage":{"complete":true},"error":"failed batch"}}`,
		`{"scan_id":"scan","status":"COMPLETED","coverage":{"complete":true},"error":{"message":"failed"}}`,
	} {
		var r StatusResult
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatal(err)
		}
		if err := ValidateResult(r); err == nil {
			t.Fatal("explicit error lost despite complete coverage")
		}
	}
}
