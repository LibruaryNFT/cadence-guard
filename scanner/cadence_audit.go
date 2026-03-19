package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Rule defines a single lint/security check
type Rule struct {
	ID          string
	Severity    string // "critical", "high", "medium", "low", "info"
	Pattern     *regexp.Regexp
	Description string
	// Optional: nearby pattern that indicates the flagged code is actually safe
	MitigationPattern *regexp.Regexp
	MitigationWindow  int // lines before/after to check for mitigation
}

// Finding represents a detected issue
type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
	Context     string `json:"context"`
}

var rules = []Rule{
	// === Access Control ===
	{
		ID:          "ACC-001",
		Severity:    "high",
		Pattern:     regexp.MustCompile(`access\s*\(\s*all\s*\)\s+fun\s+(withdraw|deposit|burn|mint|transfer|destroy|admin|setAdmin|updateAdmin|remove|delete|move|execute)`),
		Description: "Sensitive function uses access(all) instead of entitlement-gated access",
	},
	{
		ID:          "ACC-002",
		Severity:    "medium",
		Pattern:     regexp.MustCompile(`\bpub\s+fun\b`),
		Description: "Deprecated 'pub' modifier (pre-Cadence 1.0) — use access(all) or entitlement",
	},
	{
		ID:          "ACC-003",
		Severity:    "medium",
		Pattern:     regexp.MustCompile(`\bpub\s+var\b`),
		Description: "Deprecated 'pub var' — use access(all) var or entitlement-gated setter",
	},
	{
		ID:          "ACC-004",
		Severity:    "high",
		Pattern:     regexp.MustCompile(`access\s*\(\s*all\s*\)\s+fun\s+\w*(admin|Admin|owner|Owner|set|Set|update|Update)\w*\s*\(`),
		Description: "Admin/owner/setter function with access(all) — should use entitlement or account/contract access",
	},

	// === Resource Safety ===
	{
		ID:                "RES-001",
		Severity:          "high",
		Pattern:           regexp.MustCompile(`destroy\s*\(`),
		Description:       "Destroy call without nearby balance zeroing — verify vault balance is handled",
		MitigationPattern: regexp.MustCompile(`balance\s*=\s*0\.0|balance\s*==\s*0|\.balance\s*<=\s*0`),
		MitigationWindow:  5,
	},
	{
		ID:          "RES-002",
		Severity:    "medium",
		Pattern:     regexp.MustCompile(`<-\s*!`),
		Description: "Force-unwrap move (<-!) — potential resource loss if optional is nil",
	},
	{
		ID:                "RES-003",
		Severity:          "info",
		Pattern:           regexp.MustCompile(`\bfun\s+\w+\s*\([^)]*\)\s*:\s*[^{]*\{`),
		Description:       "Function may be eligible for `view` annotation — verify it has no state mutations",
		MitigationPattern: regexp.MustCompile(`\bview\s+fun\b|self\.\w+\s*=|emit\s+|<-|\.save\(|\.load<`),
		MitigationWindow:  20,
	},

	// === Token / Vault Operations ===
	{
		ID:                "TOK-001",
		Severity:          "high",
		Pattern:           regexp.MustCompile(`fun\s+deposit\s*\(\s*from`),
		Description:       "Deposit function without type guard — verify vault type is checked",
		MitigationPattern: regexp.MustCompile(`getType\(\)|isInstance\(|Type<@`),
		MitigationWindow:  10,
	},
	{
		ID:                "TOK-002",
		Severity:          "medium",
		Pattern:           regexp.MustCompile(`fun\s+(mint|createMinter|mintTokens)\b`),
		Description:       "Mint function — verify totalSupply is incremented and access is controlled",
		MitigationPattern: regexp.MustCompile(`totalSupply`),
		MitigationWindow:  10,
	},
	{
		ID:                "TOK-003",
		Severity:          "high",
		Pattern:           regexp.MustCompile(`fun\s+burnTokens|fun\s+burn\b`),
		Description:       "Burn function — verify balance is zeroed and totalSupply is decremented",
		MitigationPattern: regexp.MustCompile(`totalSupply|balance\s*=\s*0`),
		MitigationWindow:  10,
	},
	{
		ID:                "TOK-004",
		Severity:          "medium",
		Pattern:           regexp.MustCompile(`/\s*\d+\.\d+\s*\*|/\s*\w+\s*\*`),
		Description:       "Division before multiplication — may lose precision; prefer multiplying first unless overflow risk",
		MitigationPattern: regexp.MustCompile(`//.*overflow|//.*intentional`),
		MitigationWindow:  1,
	},

	// === Storage Operations ===
	{
		ID:          "STO-001",
		Severity:    "medium",
		Pattern:     regexp.MustCompile(`/storage/.*\(`),
		Description: "String interpolation in storage path — may allow path collision",
	},
	{
		ID:                "STO-002",
		Severity:          "low",
		Pattern:           regexp.MustCompile(`\.borrow<`),
		Description:       "Storage borrow without nil check — verify result is handled",
		MitigationPattern: regexp.MustCompile(`\?\?|if let|!\s*$`),
		MitigationWindow:  2,
	},

	// === Input Validation ===
	{
		ID:                "INP-001",
		Severity:          "medium",
		Pattern:           regexp.MustCompile(`access\s*\(\s*all\s*\)\s+fun\s+\w+\s*\([^)]+\)`),
		Description:       "Public function with parameters — verify pre-conditions validate inputs",
		MitigationPattern: regexp.MustCompile(`pre\s*\{`),
		MitigationWindow:  5,
	},
	{
		ID:          "INP-002",
		Severity:    "medium",
		Pattern:     regexp.MustCompile(`!=\s*nil\s*\{[^}]*!\s`),
		Description: "Nil-check followed by force-unwrap — use if-let instead: if let value = opt { ... }",
	},
	{
		ID:          "INP-003",
		Severity:    "low",
		Pattern:     regexp.MustCompile(`\bfor\s+\w+\s+in\s+self\.\w+\.keys\b`),
		Description: "Loop over dictionary keys — verify collection is bounded to prevent DoS via unbounded iteration",
	},

	// === Capabilities ===
	{
		ID:          "CAP-001",
		Severity:    "info",
		Pattern:     regexp.MustCompile(`capabilities\s*\.\s*publish`),
		Description: "Capability publishing — review what type and entitlements are exposed",
	},
	{
		ID:          "CAP-002",
		Severity:    "medium",
		Pattern:     regexp.MustCompile(`capabilities\s*\.\s*(publish|issue)\s*\([^)]*&\{[^}]+\}`),
		Description: "Interface-restricted capability — interface restriction alone is NOT security in Cadence 1.0; use entitlements",
	},

	// === Randomness ===
	{
		ID:          "RND-001",
		Severity:    "high",
		Pattern:     regexp.MustCompile(`revertibleRandom`),
		Description: "revertibleRandom usage — verify commit-reveal pattern with block separation",
	},

	// === Cross-VM ===
	{
		ID:          "EVM-001",
		Severity:    "info",
		Pattern:     regexp.MustCompile(`\bEVM\s*\.`),
		Description: "Cross-VM (EVM) call — review for atomicity, precision, and reentrancy",
	},
}

func main() {
	minSeverity := "low"
	jsonOutput := false
	var targetDir string

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--severity":
			if i+1 < len(args) {
				minSeverity = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printUsage()
			os.Exit(0)
		default:
			if !strings.HasPrefix(args[i], "-") {
				targetDir = args[i]
			}
		}
	}

	if targetDir == "" {
		fmt.Fprintf(os.Stderr, "Error: no target directory specified\n\n")
		printUsage()
		os.Exit(1)
	}

	severityOrder := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}

	minLevel, ok := severityOrder[minSeverity]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: invalid severity '%s' (use critical/high/medium/low/info)\n", minSeverity)
		os.Exit(1)
	}

	// Find all .cdc files
	var cdcFiles []string
	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == "node_modules" || base == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".cdc" {
			cdcFiles = append(cdcFiles, path)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking directory: %v\n", err)
		os.Exit(1)
	}

	if len(cdcFiles) == 0 {
		fmt.Fprintf(os.Stderr, "No .cdc files found in %s\n", targetDir)
		os.Exit(1)
	}

	// Scan each file
	var findings []Finding
	for _, file := range cdcFiles {
		fileFindings := scanFile(file, minLevel, severityOrder)
		findings = append(findings, fileFindings...)
	}

	// Sort by severity (highest first), then file, then line
	sort.Slice(findings, func(i, j int) bool {
		si := severityOrder[findings[i].Severity]
		sj := severityOrder[findings[j].Severity]
		if si != sj {
			return si > sj
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	// Output
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
	} else {
		printTextReport(findings, cdcFiles, severityOrder)
	}

	// Exit code: 1 if any high+ findings
	for _, f := range findings {
		if severityOrder[f.Severity] >= severityOrder["high"] {
			os.Exit(1)
		}
	}
}

func scanFile(filePath string, minLevel int, severityOrder map[string]int) []Finding {
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot read %s: %v\n", filePath, err)
		return nil
	}

	lines := strings.Split(string(data), "\n")
	var findings []Finding

	for _, rule := range rules {
		ruleLevel := severityOrder[rule.Severity]
		if ruleLevel < minLevel {
			continue
		}

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			// Skip comments
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
				continue
			}

			if rule.Pattern.MatchString(line) {
				// Check mitigation pattern if defined
				if rule.MitigationPattern != nil {
					mitigated := false
					start := i - rule.MitigationWindow
					if start < 0 {
						start = 0
					}
					end := i + rule.MitigationWindow + 1
					if end > len(lines) {
						end = len(lines)
					}
					for j := start; j < end; j++ {
						if rule.MitigationPattern.MatchString(lines[j]) {
							mitigated = true
							break
						}
					}
					if mitigated {
						continue
					}
				}

				findings = append(findings, Finding{
					RuleID:      rule.ID,
					Severity:    rule.Severity,
					File:        filepath.ToSlash(filePath),
					Line:        i + 1,
					Description: rule.Description,
					Context:     strings.TrimSpace(line),
				})
			}
		}
	}

	return findings
}

func printTextReport(findings []Finding, files []string, severityOrder map[string]int) {
	sevColors := map[string]string{
		"critical": "\033[1;31m", // bold red
		"high":     "\033[31m",   // red
		"medium":   "\033[33m",   // yellow
		"low":      "\033[36m",   // cyan
		"info":     "\033[37m",   // white
	}
	reset := "\033[0m"

	fmt.Printf("=== Cadence Guard — Security Scanner ===\n")
	fmt.Printf("Scanned %d .cdc files\n\n", len(files))

	if len(findings) == 0 {
		fmt.Println("No findings at the specified severity level.")
		return
	}

	// Count by severity
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Printf("Summary: ")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[sev] > 0 {
			fmt.Printf("%s%s:%d%s  ", sevColors[sev], strings.ToUpper(sev), counts[sev], reset)
		}
	}
	fmt.Println("\n")

	// Print findings
	for _, f := range findings {
		color := sevColors[f.Severity]
		fmt.Printf("  %s[%s]%s %s:%d — %s\n", color, strings.ToUpper(f.Severity), reset, f.File, f.Line, f.RuleID)
		fmt.Printf("    %s\n", f.Description)
		fmt.Printf("    > %s\n\n", f.Context)
	}
}

func printUsage() {
	fmt.Println(`Usage: cadence-guard [OPTIONS] <directory>

Scan Cadence (.cdc) files for common security anti-patterns.

Options:
  --severity <level>  Minimum severity to report: critical, high, medium, low, info (default: low)
  --json              Output as JSON instead of text
  --help              Show this help

Examples:
  cadence-guard ./contracts/
  cadence-guard --severity high --json ./contracts/
  cadence-guard --severity medium /path/to/project/

Rules: 21 security patterns across 7 categories
  ACC  Access Control (4 rules)
  RES  Resource Safety (3 rules)
  TOK  Token/Vault Operations (4 rules)
  STO  Storage Operations (2 rules)
  INP  Input Validation (3 rules)
  CAP  Capabilities (2 rules)
  RND  Randomness (1 rule)
  EVM  Cross-VM (1 rule)

Exit code: 1 if any HIGH or CRITICAL findings, 0 otherwise.`)
}
