package main

import (
	"bytes"
	"os"
	"regexp"
	"fmt"
)

type Rule struct {
	ID string
	Prefix []byte
	Pattern *regexp.Regexp
}

type Match struct {
	RuleID string
	Path string
	Line int
	Column int
	Secret string
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

	rules := []Rule{
		{
			ID: "github-pat",
			Prefix: []byte("ghp_"),
			Pattern: regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		},
		{
			ID: "aws-access-key",
			Prefix: []byte("AKIA"),
			Pattern: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		},
	}

	var matches []Match

	for _, rule := range rules {
		if len(rule.Prefix) > 0 && !bytes.Contains(data, rule.Prefix) {
			continue
		}

		match := rule.Pattern.FindAllIndex(data, -1)
		for _, loc := range match {
			start, end := loc[0], loc[1]
			secretBytes := data[start:end]

			line := bytes.Count(data[:start], []byte{'\n'}) + 1
			lastNewLine := bytes.LastIndexByte(data[:start], '\n')
			col := start - lastNewLine

			matches = append(matches, Match{
				RuleID: rule.ID,
				Path: filePath,
				Line: line,
				Column: col,
				Secret: string(secretBytes),
			})
		}
	}

	if len(matches) == 0 {
		fmt.Println("clean: no secrets found")
		return
	}

	for _, f := range matches {
		fmt.Printf("%s:%d:%d: [%s] %s\n", f.Path, f.Line, f.Column, f.RuleID, f.Secret)
	}
	os.Exit(1)
}
