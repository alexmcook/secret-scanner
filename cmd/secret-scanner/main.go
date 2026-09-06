package main

import (
	"fmt"
	"os"

	"secret-scanner/internal/rules"
	"secret-scanner/internal/scan"
)

var ruleSpecs = []rules.RuleSpec{
	{
		ID:      "github-pat",
		Prefix:  "ghp_",
		Pattern: `ghp_[0-9a-zA-Z]{36}`,
	},
	{
		ID:      "aws-access-key",
		Prefix:  "AKIA",
		Pattern: `\bAKIA[0-9A-Z]{16}\b`,
	},
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: go run main.go <file>")
		os.Exit(1)
	}

	filePath := os.Args[1]
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read file: %v\n", err)
		os.Exit(1)
	}

	rules, err := rules.CompileAll(ruleSpecs)
	output, err := scan.Scan(rules, scan.Target{Data: data, Path: filePath})

	for _, line := range output {
		fmt.Println(line)
	}

	os.Exit(1)
}
