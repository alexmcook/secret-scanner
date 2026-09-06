package rules_test

import (
	"testing"

	"secret-scanner/internal/rules"
)

func TestCompile(t *testing.T) {
	tests := []struct {
		name    string
		spec    rules.RuleSpec
		wantErr bool
	}{
		{
			name: "valid spec",
			spec: rules.RuleSpec{
				ID:      "aws-key",
				Prefix:  "AKIA",
				Pattern: `\bAKIA[0-9A-Z]{16}\b`,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := rules.Compile(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Compile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && rule.ID != tt.spec.ID {
				t.Errorf("rule.ID = %q, want %q", rule.ID, tt.spec.ID)
			}
		})
	}
}

func TestCompileAll(t *testing.T) {
	validSpecs := []rules.RuleSpec{
		{ID: "rule-1", Pattern: `ghp_[0-9a-zA-Z]{36}`},
		{ID: "rule-2", Pattern: `\bAKIA[0-9A-Z]{16}\b`},
	}

	compiled, err := rules.CompileAll(validSpecs)
	if err != nil {
		t.Fatalf("CompileAll() failed unexpectedly: %v", err)
	}
	if len(compiled) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(compiled))
	}

	invalidSpecs := append(validSpecs, rules.RuleSpec{ID: "bad", Pattern: `(`})
	_, err = rules.CompileAll(invalidSpecs)
	if err == nil {
		t.Fatalf("expected error on invalid regex in CompileAll, got nil")
	}
}
