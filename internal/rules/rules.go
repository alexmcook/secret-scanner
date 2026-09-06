package rules

import (
	"fmt"
	"regexp"
)

type RuleSpec struct {
	ID      string
	Prefix  string
	Pattern string
}

type Rule struct {
	ID      string
	Prefix  []byte
	Pattern *regexp.Regexp
}

func Compile(spec RuleSpec) (Rule, error) {
	if spec.ID == "" {
		return Rule{}, fmt.Errorf("rule ID is empty")
	}

	if spec.Pattern == "" {
		return Rule{}, fmt.Errorf("rule %q pattern is empty", spec.ID)
	}

	re, err := regexp.Compile(spec.Pattern)
	if err != nil {
		return Rule{}, fmt.Errorf("invalid regex for rule %q: %w", spec.ID, err)
	}

	return Rule{
		ID:      spec.ID,
		Prefix:  []byte(spec.Prefix),
		Pattern: re,
	}, nil
}

func CompileAll(specs []RuleSpec) ([]Rule, error) {
	rules := make([]Rule, 0, len(specs))

	for _, spec := range specs {
		rule, err := Compile(spec)
		if err != nil {
			return []Rule{}, fmt.Errorf("compile rule %q: %w", spec.ID, err)
		}

		rules = append(rules, rule)
	}

	return rules, nil
}
