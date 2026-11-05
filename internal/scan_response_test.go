package internal

import (
	"encoding/json"
	"testing"
)

func TestScanStatusResponseFormats(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		count      int
	}{
		{"flat incomplete", `{"status":"FAILED","result":{"status":"FAILED","issues_count":12,"report_url":"https://example.test/report","coverage":{"complete":false,"errors":["batch failed"]},"incomplete":{"message":"Análisis incompleto","files_not_fully_analyzed":["main.tf"]}}}`, 12},
		{"legacy", `{"status":"FAILED","result":{"report_url":"https://example.test/report","result":{"status":"FAILED","number_of_issues":3,"annotations":[{"title":"finding"}]}}}`, 3},
		{"completed", `{"status":"COMPLETED","result":{"status":"COMPLETED","issues_count":0,"report_url":"https://example.test/report"}}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var response GetScanStatusOutput
			if err := json.Unmarshal([]byte(tc.body), &response); err != nil {
				t.Fatal(err)
			}
			if response.Result.Result.Status != response.Status || response.Result.Result.NumberOfIssues != tc.count || response.Result.ReportUrl != "https://example.test/report" {
				t.Fatalf("incorrect result: %+v", response)
			}
			if tc.name == "flat incomplete" {
				r := response.Result.Result
				if r.Coverage == nil || r.Coverage.Complete || len(r.Coverage.Errors) != 1 || r.Incomplete == nil || r.Incomplete.Message != "Análisis incompleto" || len(r.Incomplete.FilesNotFullyAnalyzed) != 1 {
					t.Fatalf("missing incomplete analysis details: %+v", r)
				}
			}
			if tc.name == "legacy" && len(response.Result.Result.Annotations) != 1 {
				t.Fatal("lost legacy annotations")
			}
		})
	}
}
