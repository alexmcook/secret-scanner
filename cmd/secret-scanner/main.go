package main

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"secret-scanner/internal/rules"
	"secret-scanner/internal/scan"
)

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintf(stderr, "usage: go run main.go <file>\n")
		return 2
	}

	filePath := os.Args[1]
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(stderr, "failed to read file: %v\n", err)
		return 2
	}

	rules, err := rules.CompileDefault()
	if err != nil {
		fmt.Fprintf(stderr, "failed to compile regex: %v\n", err)
		return 2
	}
	matches := scan.Scan(rules, scan.Target{Data: data, Path: filePath})

	if len(matches) == 0 {
		fmt.Fprintf(stdout, "clean: no secrets found\n")
		return 0
	}

	printAligned(stdout, matches)
	return 1
}

func redact(s string) string {
	if len(s) <= 8 {
		return "******"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

func printAligned(stdout io.Writer, matches []scan.Match) {
	w := tabwriter.NewWriter(stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "LOCATION\tRULE\tSECRET\n")
	for _, m := range matches {
		loc := fmt.Sprintf("%s:%d:%d", m.Path, m.Line, m.Column)
		rule := fmt.Sprintf("[%s]", m.RuleID)
		secret := redact(m.Secret)
		fmt.Fprintf(w, "%s\t%s\t%s\n", loc, rule, secret)
	}
	w.Flush()
}
