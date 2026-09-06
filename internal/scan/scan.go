package scan

import (
	"bytes"
	"fmt"

	"secret-scanner/internal/rules"
)

type Target struct {
	Path string
	Data []byte
}

type Match struct {
	RuleID string
	Path   string
	Line   int
	Column int
	Secret string
}

func Scan(rules []rules.Rule, target Target) ([]string, error) {
	var matches []Match
	data := target.Data

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
				Path:   target.Path,
				Line:   line,
				Column: col,
				Secret: string(secretBytes),
			})
		}
	}

	var output []string

	if len(matches) == 0 {
		output = append(output, "clean: no secrets found")
		return output, nil
	}

	for _, f := range matches {
		output = append(output, fmt.Sprintf("%s:%d:%d: [%s] %s", f.Path, f.Line, f.Column, f.RuleID, f.Secret))
	}
	return output, nil
}
