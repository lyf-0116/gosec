package gosec

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/securego/gosec/v2/issue"
)

// PathExcludeRule defines rules to exclude for specific file paths
type PathExcludeRule struct {
	Path  string   `json:"path"`  // Regex pattern for matching file paths
	Rules []string `json:"rules"` // Rule IDs to exclude. Use "*" to exclude all rules
}

// compiledPathRule is a pre-compiled version of PathExcludeRule for efficient matching
type compiledPathRule struct {
	pathRegex     *regexp.Regexp
	boundaryRegex *regexp.Regexp  // Variant anchored at a path segment boundary
	anchored      bool            // True when the pattern explicitly starts with "^"
	ruleSet       map[string]bool // Set of rule IDs to exclude
	excludeAll    bool            // True if "*" was specified in rules
	original      PathExcludeRule // Keep original for error messages
}

// PathExclusionFilter handles filtering of issues based on path and rule combinations
type PathExclusionFilter struct {
	configRules []compiledPathRule
	cliRules    []compiledPathRule
	// scanRoots holds the absolute, slash-normalized roots of the scan,
	// ordered from longest to shortest. Regexes are matched against the
	// path relative to the most specific root that contains a given file.
	scanRoots []string
	excluded  atomic.Int64
}

// matchCandidate is the slash-normalized string a rule is matched against.
type matchCandidate struct {
	path   string
	rooted bool // True when the path was derived relative to a scan root
}

// NewPathExclusionFilter creates a new filter from the provided exclusion rules.
// The rules are treated as configuration-file rules. When scan roots are not
// set, patterns are matched against the input path unchanged; call
// SetScanRoots to anchor matching on paths relative to the scan roots.
// Returns an error if any path regex is invalid.
func NewPathExclusionFilter(rules []PathExcludeRule) (*PathExclusionFilter, error) {
	compiled, err := compilePathRules(rules)
	if err != nil {
		return nil, err
	}
	return &PathExclusionFilter{configRules: compiled}, nil
}

// NewPathExclusionFilterWithRules creates a filter keeping configuration-file
// and CLI rules in separate groups. CLI rules take precedence: when a CLI rule
// matches the path of a file, configuration rules are not evaluated for that
// file at all, so the CLI can narrow exclusions declared in the configuration.
func NewPathExclusionFilterWithRules(configRules, cliRules []PathExcludeRule) (*PathExclusionFilter, error) {
	compiledConfig, err := compilePathRules(configRules)
	if err != nil {
		return nil, err
	}
	compiledCLI, err := compilePathRules(cliRules)
	if err != nil {
		return nil, err
	}
	return &PathExclusionFilter{
		configRules: compiledConfig,
		cliRules:    compiledCLI,
	}, nil
}

// compilePathRules validates and compiles a group of exclusion rules.
func compilePathRules(rules []PathExcludeRule) ([]compiledPathRule, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	compiled := make([]compiledPathRule, 0, len(rules))

	for i, rule := range rules {
		if rule.Path == "" {
			return nil, fmt.Errorf("exclude-rules[%d]: path cannot be empty", i)
		}

		pattern := normalizePathPattern(rule.Path)
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("exclude-rules[%d]: invalid path regex %q: %w", i, rule.Path, err)
		}
		var boundary *regexp.Regexp
		if !strings.HasPrefix(pattern, "^") {
			boundary, err = regexp.Compile("(?:^|/)" + pattern)
			if err != nil {
				return nil, fmt.Errorf("exclude-rules[%d]: invalid path regex %q: %w", i, rule.Path, err)
			}
		}

		ruleSet := make(map[string]bool)
		excludeAll := false

		for _, ruleID := range rule.Rules {
			ruleID = strings.TrimSpace(ruleID)
			if ruleID == "*" {
				excludeAll = true
			} else if ruleID != "" {
				ruleSet[ruleID] = true
			}
		}

		compiled = append(compiled, compiledPathRule{
			pathRegex:     regex,
			boundaryRegex: boundary,
			anchored:      strings.HasPrefix(pattern, "^"),
			ruleSet:       ruleSet,
			excludeAll:    excludeAll,
			original:      rule,
		})
	}

	return compiled, nil
}

// normalizePathPattern adapts a user-supplied pattern to the root-relative
// matching baseline. A leading slash (or one immediately following "^")
// refers to the scan root, not the filesystem root, so it is removed rather
// than making the pattern unmatchable. Escaped leading slashes are preserved.
func normalizePathPattern(pattern string) string {
	switch {
	case strings.HasPrefix(pattern, "^/"):
		return "^" + pattern[2:]
	case strings.HasPrefix(pattern, "/"):
		return pattern[1:]
	default:
		return pattern
	}
}

// SetScanRoots configures the absolute roots of the scan. Exclusion patterns
// are matched against file paths relative to the most specific root that
// contains the file. Files outside every root are never excluded, which keeps
// the default behavior on the safe side for a security tool.
func (f *PathExclusionFilter) SetScanRoots(roots ...string) {
	if f == nil {
		return
	}

	normalized := make([]string, 0, len(roots))
	for _, root := range roots {
		if root == "" {
			continue
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			abs = root
		}
		abs = filepath.Clean(abs)
		// When a single file is scanned, anchor matching on its directory so
		// patterns written for repository-relative paths still apply.
		if info, statErr := os.Stat(abs); statErr == nil && !info.IsDir() {
			abs = filepath.Dir(abs)
		}
		normalized = append(normalized, filepath.ToSlash(abs))
	}

	slices.SortFunc(normalized, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	f.scanRoots = slices.Compact(normalized)
}

// relativeCandidate returns the slash-normalized path that patterns should be
// matched against. The boolean result reports whether the file belongs to a
// configured scan root. With no roots configured the normalized input path is
// used directly so the filter keeps working as a standalone regex matcher.
func (f *PathExclusionFilter) relativeCandidate(filePath string) (matchCandidate, bool) {
	// Normalize separators before Clean: on POSIX systems a backslash is a
	// valid filename character, so Clean alone leaves Windows-style paths
	// untouched and the regex would never match them.
	normalized := filepath.ToSlash(filepath.Clean(strings.ReplaceAll(filePath, "\\", "/")))

	if len(f.scanRoots) == 0 {
		return matchCandidate{path: normalized}, true
	}

	if !filepath.IsAbs(filePath) {
		if abs, err := filepath.Abs(filePath); err == nil {
			normalized = filepath.ToSlash(filepath.Clean(strings.ReplaceAll(abs, "\\", "/")))
		}
	}

	for _, root := range f.scanRoots {
		if normalized == root {
			return matchCandidate{path: ".", rooted: true}, true
		}
		if strings.HasPrefix(normalized, root+"/") {
			return matchCandidate{path: strings.TrimPrefix(normalized, root+"/"), rooted: true}, true
		}
	}
	return matchCandidate{path: normalized, rooted: true}, false
}

// evaluateGroup checks the candidate path against one rule group. It reports
// whether any rule matched the path and, if so, whether the given rule ID is
// covered by that match.
func evaluateGroup(rules []compiledPathRule, candidate matchCandidate, ruleID string) (pathMatched, excluded bool) {
	for _, rule := range rules {
		if rule.matches(candidate) {
			pathMatched = true
			if rule.excludeAll || rule.ruleSet[ruleID] {
				excluded = true
			}
		}
	}
	return pathMatched, excluded
}

// matches reports whether the rule applies to the candidate path. When scan
// roots are configured, patterns without an explicit "^" anchor are matched at
// a directory boundary, so a rule like "cmd/.*" matches "cmd/main.go" and
// "pkg/cmd/helper.go" but not "mycmd/x.go". An explicit "^" anchor pins the
// pattern to the scan root, so "^cmd/.*" only matches the first case.
// Patterns ending with "$" keep their declared semantics.
func (rule compiledPathRule) matches(candidate matchCandidate) bool {
	if !candidate.rooted || rule.anchored {
		return rule.pathRegex.MatchString(candidate.path)
	}
	return rule.boundaryRegex.MatchString(candidate.path)
}

// ShouldExclude returns true if the given issue should be excluded based on
// its file path and rule ID
func (f *PathExclusionFilter) ShouldExclude(filePath, ruleID string) bool {
	if f == nil || (len(f.configRules) == 0 && len(f.cliRules) == 0) {
		return false
	}

	candidate, inScope := f.relativeCandidate(filePath)
	if !inScope {
		return false
	}

	// CLI rules take precedence: once a CLI rule names this path, the
	// configuration rules are shadowed for the file, allowing the CLI to
	// narrow broad exclusions declared in the configuration.
	cliPathMatched, cliExcluded := evaluateGroup(f.cliRules, candidate, ruleID)
	if cliPathMatched {
		if cliExcluded {
			f.excluded.Add(1)
			return true
		}
		return false
	}

	if _, configExcluded := evaluateGroup(f.configRules, candidate, ruleID); configExcluded {
		f.excluded.Add(1)
		return true
	}
	return false
}

// ExcludedCount returns the number of issues excluded since the last reset.
func (f *PathExclusionFilter) ExcludedCount() int64 {
	if f == nil {
		return 0
	}
	return f.excluded.Load()
}

// ResetExcludedCount zeroes the excluded-issue counter.
func (f *PathExclusionFilter) ResetExcludedCount() {
	if f == nil {
		return
	}
	f.excluded.Store(0)
}

// FilterIssues applies path-based exclusions to a slice of issues.
// Returns the filtered issues and the count of excluded issues.
func (f *PathExclusionFilter) FilterIssues(issues []*issue.Issue) ([]*issue.Issue, int) {
	if f == nil || (len(f.configRules) == 0 && len(f.cliRules) == 0) || len(issues) == 0 {
		return issues, 0
	}

	filtered := make([]*issue.Issue, 0, len(issues))
	excluded := 0

	for _, iss := range issues {
		if f.ShouldExclude(iss.File, iss.RuleID) {
			excluded++
			continue
		}
		filtered = append(filtered, iss)
	}

	return filtered, excluded
}

// ParseCLIExcludeRules parses the CLI format for exclude-rules.
// Format: "path:rule1,rule2;path2:rule3,rule4"
// Example: "cmd/.*:G204,G304;test/.*:G101"
func ParseCLIExcludeRules(input string) ([]PathExcludeRule, error) {
	if input == "" {
		return nil, nil
	}

	var rules []PathExcludeRule

	// Split by semicolon for multiple rules
	parts := strings.Split(input, ";")

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split by colon to separate path and rules
		colonIdx := strings.LastIndex(part, ":")
		if colonIdx == -1 {
			return nil, fmt.Errorf("exclude-rules part %d: missing ':' separator in %q", i+1, part)
		}

		pathPattern := strings.TrimSpace(part[:colonIdx])
		rulesPart := strings.TrimSpace(part[colonIdx+1:])

		if pathPattern == "" {
			return nil, fmt.Errorf("exclude-rules part %d: path pattern cannot be empty", i+1)
		}

		if rulesPart == "" {
			return nil, fmt.Errorf("exclude-rules part %d: rules list cannot be empty", i+1)
		}

		// Split rules by comma
		ruleIDs := strings.Split(rulesPart, ",")
		cleanedRules := make([]string, 0, len(ruleIDs))
		for _, r := range ruleIDs {
			r = strings.TrimSpace(r)
			if r != "" {
				cleanedRules = append(cleanedRules, r)
			}
		}

		if len(cleanedRules) == 0 {
			return nil, fmt.Errorf("exclude-rules part %d: no valid rules specified", i+1)
		}

		rules = append(rules, PathExcludeRule{
			Path:  pathPattern,
			Rules: cleanedRules,
		})
	}

	return rules, nil
}

// String returns a human-readable representation of the filter
func (f *PathExclusionFilter) String() string {
	if f == nil || (len(f.configRules) == 0 && len(f.cliRules) == 0) {
		return "PathExclusionFilter{empty}"
	}

	var parts []string
	formatGroup := func(source string, rules []compiledPathRule) {
		for _, rule := range rules {
			if rule.excludeAll {
				parts = append(parts, fmt.Sprintf("%s:%s:*", source, rule.original.Path))
			} else {
				ruleIDs := make([]string, 0, len(rule.ruleSet))
				for id := range rule.ruleSet {
					ruleIDs = append(ruleIDs, id)
				}
				parts = append(parts, fmt.Sprintf("%s:%s:[%s]", source, rule.original.Path, strings.Join(ruleIDs, ",")))
			}
		}
	}
	formatGroup("cli", f.cliRules)
	formatGroup("config", f.configRules)

	return fmt.Sprintf("PathExclusionFilter{%s}", strings.Join(parts, "; "))
}
