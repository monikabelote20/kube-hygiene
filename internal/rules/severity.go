package rules

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity orders findings so CI can fail on the ones that matter.
type Severity int

const (
	// Info is advice that rarely needs action.
	Info Severity = iota + 1
	// Warning is a reliability or hygiene gap worth fixing.
	Warning
	// Error is a security exposure that should block a rollout.
	Error
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Warning:
		return "warning"
	case Error:
		return "error"
	default:
		return fmt.Sprintf("severity(%d)", int(s))
	}
}

// MarshalJSON writes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON reads a severity name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	v, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSeverity accepts info, warning or error (case-insensitive).
func ParseSeverity(name string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "info":
		return Info, nil
	case "warning", "warn":
		return Warning, nil
	case "error":
		return Error, nil
	default:
		return 0, fmt.Errorf("unknown severity %q (want info, warning or error)", name)
	}
}
