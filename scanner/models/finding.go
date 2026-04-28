package models

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// ScanConfig is written to the scanner's stdin by the Python orchestrator.
type ScanConfig struct {
	URL     string   `json:"url"`
	BaseURL string   `json:"base_url"`
	Params  []string `json:"params"`
	JSURLs  []string `json:"js_urls"`
	Workers int      `json:"workers"`
	Timeout int      `json:"timeout"`
}

// Finding is the unit of output emitted as one JSON line on stdout.
type Finding struct {
	Type     string `json:"type"`               // "status" | "finding" | "error" | "done"
	Severity string `json:"severity,omitempty"` // CRITICAL HIGH MEDIUM LOW INFO
	Category string `json:"category,omitempty"`
	Title    string `json:"title,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
	Message  string `json:"message,omitempty"` // for status / error
}

var mu sync.Mutex

// Emit writes one JSON line to stdout, thread-safe.
func Emit(f Finding) {
	b, _ := json.Marshal(f)
	mu.Lock()
	fmt.Fprintf(os.Stdout, "%s\n", b)
	mu.Unlock()
}

func Status(msg string) { Emit(Finding{Type: "status", Message: msg}) }
func Error(msg string)  { Emit(Finding{Type: "error", Message: msg}) }
func Done()             { Emit(Finding{Type: "done"}) }
