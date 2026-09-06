package scan

import (
	"bytes"
	"sort"

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

func Scan(rules []rules.Rule, target Target) []Match {
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

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Line == matches[j].Line {
			return matches[i].Column < matches[j].Column
		}
		return matches[i].Line < matches[j].Line
	})

	return matches
}
