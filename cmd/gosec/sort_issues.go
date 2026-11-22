package main

import (
	"cmp"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/securego/gosec/v2/issue"
)

// handle ranges
func extractLineNumber(s string) int {
	lineNumber, _ := strconv.Atoi(strings.Split(s, "-")[0])
	return lineNumber
}

// compareIssues defines the report ordering. Severity is ranked in descending
// order so the most severe findings come first; every remaining key breaks
// ties in ascending order (rule, description, file, line). It returns a
// negative, zero, or positive value like the cmp package comparators.
func compareIssues(i, j *issue.Issue) int {
	return cmp.Or(
		cmp.Compare(j.Severity, i.Severity),
		cmp.Compare(i.RuleID, j.RuleID),
		cmp.Compare(i.What, j.What),
		cmp.Compare(i.File, j.File),
		cmp.Compare(extractLineNumber(i.Line), extractLineNumber(j.Line)),
	)
}

// sortIssues sorts the issues by severity in descending order, keeping the
// remaining keys in ascending order. A stable sort preserves the input order
// of findings that compare equal, so the report does not depend on how many
// packages were analyzed concurrently.
func sortIssues(issues []*issue.Issue) {
	slices.SortStableFunc(issues, compareIssues)
}

// dedupIssues drops findings that are identical in every reported field.
// Data-flow analysis can reach the same sink through several paths and emit
// the same issue more than once; only the first occurrence is kept, which
// keeps the report free of duplicate lines. It must run before any gate
// counting so that the reported totals match the displayed findings.
func dedupIssues(issues []*issue.Issue) []*issue.Issue {
	seen := make(map[string]struct{}, len(issues))
	unique := make([]*issue.Issue, 0, len(issues))
	for _, iss := range issues {
		if iss == nil {
			continue
		}
		key, err := json.Marshal(iss)
		if err != nil {
			// Every Issue field is JSON-encodable; keeping an unencodable
			// finding rather than silently dropping it is the safe fallback.
			unique = append(unique, iss)
			continue
		}
		if _, ok := seen[string(key)]; ok {
			continue
		}
		seen[string(key)] = struct{}{}
		unique = append(unique, iss)
	}
	return unique
}
