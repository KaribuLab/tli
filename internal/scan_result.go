package internal

import "encoding/json"

type Annotation struct {
	Title          string `json:"title"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	Path           string `json:"path"`
	Line           int    `json:"line"`
	Summary        string `json:"summary"`
	Code           string `json:"code"`
	Recommendation string `json:"recommendation"`
}
type ScanResult struct {
	Status         string          `json:"status"`
	NumberOfIssues int             `json:"number_of_issues"`
	Annotations    []Annotation    `json:"annotations"`
	Coverage       *ScanCoverage   `json:"coverage,omitempty"`
	Incomplete     *ScanIncomplete `json:"incomplete,omitempty"`
	Error          any             `json:"error,omitempty"`
}
type ScanCoverage struct {
	Complete bool     `json:"complete"`
	Errors   []string `json:"errors"`
}
type ScanIncomplete struct {
	Message               string   `json:"message"`
	FilesNotFullyAnalyzed []string `json:"files_not_fully_analyzed"`
}
type StatusResult struct {
	ScanID    string     `json:"scan_id"`
	ReportUrl string     `json:"report_url"`
	Result    ScanResult `json:"result"`
}

func (r *StatusResult) UnmarshalJSON(data []byte) error {
	type alias StatusResult
	var wire struct {
		ScanID      string          `json:"scan_id"`
		ReportURL   string          `json:"report_url"`
		Result      json.RawMessage `json:"result"`
		IssuesCount *int            `json:"issues_count"`
	}
	if e := json.Unmarshal(data, &wire); e != nil {
		return e
	}
	var decoded alias
	if len(wire.Result) > 0 && string(wire.Result) != "null" {
		if e := json.Unmarshal(data, &decoded); e != nil {
			return e
		}
	} else {
		decoded.ScanID = wire.ScanID
		decoded.ReportUrl = wire.ReportURL
		if e := json.Unmarshal(data, &decoded.Result); e != nil {
			return e
		}
		if wire.IssuesCount != nil {
			decoded.Result.NumberOfIssues = *wire.IssuesCount
		}
	}
	*r = StatusResult(decoded)
	return nil
}
