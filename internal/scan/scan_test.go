package scan_test

import (
	"os"
	"path/filepath"
	"testing"

	"secret-scanner/internal/rules"
	"secret-scanner/internal/scan"
)

func TestScanCoordinates(t *testing.T) {
	testRules, err := rules.CompileAll([]rules.RuleSpec{
		{
			ID:      "aws-access-key",
			Prefix:  "AKIA",
			Pattern: `\bAKIA[0-9A-Z]{16}\b`,
		},
	})
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}

	// Construct sample data where line and col are known
	// Line 1: 10 chars + \n
	// Line 2: col 5 is start of AKIA...
	input := []byte("0123456789\n    AKIAIOSFODNN7EXAMPLE")

	target := scan.Target{
		Path: "test.env",
		Data: input,
	}

	matches := scan.Scan(testRules, target)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.Line != 2 {
		t.Errorf("Line = %d, want 2", m.Line)
	}
	if m.Column != 5 {
		t.Errorf("Column = %d, want 5", m.Column)
	}
	if m.Secret != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Secret = %q, want AKIAIOSFODNN7EXAMPLE", m.Secret)
	}
}

func TestScanFile(t *testing.T) {
	filePath := filepath.Join("testdata", "testdata")

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("could not read test file: %v", err)
	}

	rules, err := rules.CompileAll([]rules.RuleSpec{
		{
			ID:      "aws-access-key",
			Prefix:  "AKIA",
			Pattern: `\bAKIA[0-9A-Z]{16}\b`,
		},
		{
			ID:      "github-pat",
			Prefix:  "ghp_",
			Pattern: `ghp_[0-9a-zA-Z]{36}`,
		},
	})
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}

	matches := scan.Scan(rules, scan.Target{Path: filePath, Data: data})

	expected := []struct {
		ruleID string
		line   int
	}{
		{ruleID: "aws-access-key", line: 41},
		{ruleID: "github-pat", line: 208},
		{ruleID: "aws-access-key", line: 336},
	}

	if len(matches) != len(expected) {
		t.Fatalf("expected %d matches, got %d", len(expected), len(matches))
	}

	for i, want := range expected {
		got := matches[i]
		if got.RuleID != want.ruleID {
			t.Errorf("[%d] RuleID = %q, want %q", i, got.RuleID, want.ruleID)
		}
		if got.Line != want.line {
			t.Errorf("[%d] Line = %d, want %d", i, got.Line, want.line)
		}
	}
}
