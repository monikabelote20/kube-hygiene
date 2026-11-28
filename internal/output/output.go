// Package output renders findings as plain text, JSON or SARIF 2.1.0.
package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/monikabelote20/kube-hygiene/internal/rules"
)

// Formats lists the supported --format values.
var Formats = []string{"text", "json", "sarif"}

// Report is everything a renderer needs.
type Report struct {
	Source    string // input file name, or "stdin"
	Workloads int
	Findings  []rules.Finding
	Rules     []rules.Rule
	Version   string
	// Suppressed counts findings skipped via the ignore annotation.
	Suppressed int
}

// Write renders the report in the given format.
func Write(w io.Writer, format string, r Report) error {
	switch format {
	case "text":
		return Text(w, r)
	case "json":
		return JSON(w, r)
	case "sarif":
		return SARIF(w, r)
	default:
		return fmt.Errorf("unknown format %q (want one of %v)", format, Formats)
	}
}

// Text prints one aligned line per finding and a summary.
func Text(w io.Writer, r Report) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range r.Findings {
		container := ""
		if f.Container != "" {
			container = "[" + f.Container + "]"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Severity, f.Rule, f.Workload, container, f.Message)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\n%d workloads checked, %s\n", r.Workloads, summaryLine(r))
	return err
}

// summaryLine reads like "7 findings (2 error, 5 warning), 1 suppressed".
func summaryLine(r Report) string {
	counts := map[rules.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range []rules.Severity{rules.Error, rules.Warning, rules.Info} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	line := fmt.Sprintf("%d findings", len(r.Findings))
	if len(parts) > 0 {
		line += " (" + strings.Join(parts, ", ") + ")"
	}
	if r.Suppressed > 0 {
		line += fmt.Sprintf(", %d suppressed", r.Suppressed)
	}
	return line
}

type jsonReport struct {
	Source    string          `json:"source"`
	Workloads int             `json:"workloads"`
	Summary   jsonSummary     `json:"summary"`
	Findings  []rules.Finding `json:"findings"`
}

type jsonSummary struct {
	Total      int            `json:"total"`
	Suppressed int            `json:"suppressed"`
	ByRule     map[string]int `json:"by_rule"`
	BySeverity map[string]int `json:"by_severity"`
}

// JSON writes a machine-readable report.
func JSON(w io.Writer, r Report) error {
	byRule, bySeverity := map[string]int{}, map[string]int{}
	for _, f := range r.Findings {
		byRule[f.Rule]++
		bySeverity[f.Severity.String()]++
	}
	findings := r.Findings
	if findings == nil {
		findings = []rules.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{
		Source:    r.Source,
		Workloads: r.Workloads,
		Summary: jsonSummary{
			Total:      len(r.Findings),
			Suppressed: r.Suppressed,
			ByRule:     byRule,
			BySeverity: bySeverity,
		},
		Findings: findings,
	})
}

// SARIF types: only the subset GitHub code scanning reads.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	DefaultConfig    sarifConfig  `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// SARIF writes a SARIF 2.1.0 log that GitHub code scanning can ingest.
func SARIF(w io.Writer, r Report) error {
	driver := sarifDriver{
		Name:           "kube-hygiene",
		Version:        r.Version,
		InformationURI: "https://github.com/monikabelote20/kube-hygiene",
	}
	for _, rule := range r.Rules {
		driver.Rules = append(driver.Rules, sarifRule{
			ID:               rule.ID(),
			ShortDescription: sarifMessage{Text: rule.Description()},
			DefaultConfig:    sarifConfig{Level: sarifLevel(rule.Severity())},
		})
	}
	sort.Slice(driver.Rules, func(i, j int) bool { return driver.Rules[i].ID < driver.Rules[j].ID })

	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		name := f.Workload
		if f.Container != "" {
			name += "/" + f.Container
		}
		results = append(results, sarifResult{
			RuleID:  f.Rule,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: name + ": " + f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: r.Source},
					Region:           sarifRegion{StartLine: 1},
				},
				LogicalLocations: []sarifLogical{{FullyQualifiedName: name, Kind: "object"}},
			}},
			PartialFingerprints: map[string]string{"kubeHygiene/v1": fingerprint(f)},
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	})
}

// sarifLevel maps severities onto SARIF result levels.
func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.Error:
		return "error"
	case rules.Info:
		return "note"
	default:
		return "warning"
	}
}

// fingerprint stays stable across runs so code scanning can track an alert.
func fingerprint(f rules.Finding) string {
	sum := sha256.Sum256([]byte(f.Rule + "\x00" + f.Workload + "\x00" + f.Container))
	return hex.EncodeToString(sum[:16])
}
