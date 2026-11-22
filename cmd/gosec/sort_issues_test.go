package main

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2/issue"
)

var defaultIssue = issue.Issue{
	File:       "/home/src/project/test.go",
	Line:       "1",
	Col:        "1",
	RuleID:     "ruleID",
	What:       "test",
	Confidence: issue.High,
	Severity:   issue.High,
	Code:       "1: testcode",
	Cwe:        issue.GetCweByRule("G101"),
}

func createIssue() issue.Issue {
	return defaultIssue
}

func TestRules(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sort issues Suite")
}

func firstIsGreater(less, greater *issue.Issue) {
	slice := []*issue.Issue{less, greater}

	sortIssues(slice)

	ExpectWithOffset(0, slice[0]).To(Equal(greater))
}

// firstIsBefore checks that two equal-key issues keep their input order,
// which only a stable sort guarantees.
func firstIsBefore(first, second *issue.Issue) {
	slice := []*issue.Issue{first, second}

	sortIssues(slice)

	ExpectWithOffset(0, slice[0]).To(BeIdenticalTo(first))
	ExpectWithOffset(0, slice[1]).To(BeIdenticalTo(second))
}

var _ = Describe("Sorting by Severity", func() {
	It("sorts by severity", func() {
		less := createIssue()
		less.Severity = issue.Low
		greater := createIssue()
		greater.Severity = issue.High
		firstIsGreater(&less, &greater)
	})

	Context("Severity is same", func() {
		It("sorts by What", func() {
			less := createIssue()
			less.What = "test1"
			greater := createIssue()
			greater.What = "test2"
			// Tie breakers are ascending: the lexicographically smaller
			// description must come first even though severity is equal.
			firstIsBefore(&less, &greater)
		})
	})

	Context("Severity and What is same", func() {
		It("sorts by File", func() {
			less := createIssue()
			less.File = "test1"
			greater := createIssue()
			greater.File = "test2"

			firstIsBefore(&less, &greater)
		})
	})

	Context("Severity, What and File is same", func() {
		It("sorts by line number", func() {
			less := createIssue()
			less.Line = "1"
			greater := createIssue()
			greater.Line = "2"

			firstIsBefore(&less, &greater)
		})

		It("handles line ranges correctly", func() {
			less := createIssue()
			less.Line = "5-10"
			greater := createIssue()
			greater.Line = "15-20"

			firstIsBefore(&less, &greater)
		})

		It("keeps input order when start lines in ranges are equal", func() {
			less := createIssue()
			less.Line = "10-15"
			greater := createIssue()
			greater.Line = "10-20"

			firstIsBefore(&less, &greater)
		})

		It("handles single line vs range", func() {
			less := createIssue()
			less.Line = "5"
			greater := createIssue()
			greater.Line = "10-15"

			firstIsBefore(&less, &greater)
		})
	})

	Context("Severity is same and all tie breakers are equal", func() {
		It("sorts by rule ID in ascending order", func() {
			less := createIssue()
			less.RuleID = "G101"
			greater := createIssue()
			greater.RuleID = "G102"

			firstIsBefore(&less, &greater)
		})
	})
})

var _ = Describe("extractLineNumber function", func() {
	It("extracts single line number", func() {
		lineNum := extractLineNumber("42")
		Expect(lineNum).To(Equal(42))
	})

	It("extracts start line from range", func() {
		lineNum := extractLineNumber("10-20")
		Expect(lineNum).To(Equal(10))
	})

	It("handles invalid line numbers", func() {
		lineNum := extractLineNumber("invalid")
		Expect(lineNum).To(Equal(0))
	})

	It("handles empty string", func() {
		lineNum := extractLineNumber("")
		Expect(lineNum).To(Equal(0))
	})

	It("handles multiple dashes", func() {
		lineNum := extractLineNumber("5-10-15")
		Expect(lineNum).To(Equal(5))
	})
})

var _ = Describe("Sorting multiple issues", func() {
	It("sorts multiple issues correctly by all criteria", func() {
		issues := []*issue.Issue{
			{Severity: issue.Low, What: "warning1", File: "file1.go", Line: "10"},
			{Severity: issue.High, What: "error1", File: "file1.go", Line: "5"},
			{Severity: issue.High, What: "error2", File: "file1.go", Line: "1"},
			{Severity: issue.Medium, What: "warning2", File: "file2.go", Line: "20"},
			{Severity: issue.High, What: "error1", File: "file2.go", Line: "3"},
		}

		sortIssues(issues)

		// Severity is descending, all remaining keys are ascending.
		Expect(issues[0].Severity).To(Equal(issue.High))
		Expect(issues[1].Severity).To(Equal(issue.High))
		Expect(issues[2].Severity).To(Equal(issue.High))
		Expect(issues[3].Severity).To(Equal(issue.Medium))
		Expect(issues[4].Severity).To(Equal(issue.Low))

		// Within High severity: What then File then Line are ascending.
		Expect(issues[0].What).To(Equal("error1"))
		Expect(issues[0].File).To(Equal("file1.go"))
		Expect(issues[0].Line).To(Equal("5"))
		Expect(issues[1].What).To(Equal("error1"))
		Expect(issues[1].File).To(Equal("file2.go"))
		Expect(issues[1].Line).To(Equal("3"))
		Expect(issues[2].What).To(Equal("error2"))
		Expect(issues[2].File).To(Equal("file1.go"))
		Expect(issues[2].Line).To(Equal("1"))
	})

	It("handles empty slice", func() {
		issues := []*issue.Issue{}
		sortIssues(issues)
		Expect(issues).To(BeEmpty())
	})

	It("handles single issue", func() {
		issue1 := createIssue()
		issues := []*issue.Issue{&issue1}
		sortIssues(issues)
		Expect(issues).To(HaveLen(1))
		Expect(issues[0]).To(Equal(&issue1))
	})

	It("maintains stability for equal issues", func() {
		issue1 := createIssue()
		issue2 := createIssue()
		// Same severity, what, file, and line
		issues := []*issue.Issue{&issue1, &issue2}

		sortIssues(issues)

		Expect(issues).To(HaveLen(2))
		Expect(issues[0]).To(BeIdenticalTo(&issue1))
		Expect(issues[1]).To(BeIdenticalTo(&issue2))
	})

	It("maintains stability when equal keys are interleaved", func() {
		issue1 := createIssue()
		issue2 := createIssue()
		issue3 := createIssue()
		issue3.Severity = issue.Low
		issues := []*issue.Issue{&issue1, &issue3, &issue2}

		sortIssues(issues)

		Expect(issues[0]).To(BeIdenticalTo(&issue1))
		Expect(issues[1]).To(BeIdenticalTo(&issue2))
		Expect(issues[2]).To(BeIdenticalTo(&issue3))
	})

	It("sorts issues with different severity levels", func() {
		low := createIssue()
		low.Severity = issue.Low
		medium := createIssue()
		medium.Severity = issue.Medium
		high := createIssue()
		high.Severity = issue.High

		issues := []*issue.Issue{&low, &high, &medium}
		sortIssues(issues)

		Expect(issues[0].Severity).To(Equal(issue.High))
		Expect(issues[1].Severity).To(Equal(issue.Medium))
		Expect(issues[2].Severity).To(Equal(issue.Low))
	})
})

var _ = Describe("dedupIssues", func() {
	It("removes identical findings produced by multiple taint paths", func() {
		first := createIssue()
		duplicate := createIssue()
		issues := []*issue.Issue{&first, &duplicate}

		result := dedupIssues(issues)

		Expect(result).To(HaveLen(1))
		Expect(result[0]).To(BeIdenticalTo(&first))
	})

	It("keeps distinct findings on the same line and rule when reasons differ", func() {
		first := createIssue()
		first.What = "first reason"
		second := createIssue()
		second.What = "second reason"
		issues := []*issue.Issue{&first, &second}

		result := dedupIssues(issues)

		Expect(result).To(HaveLen(2))
		Expect(result[0]).To(BeIdenticalTo(&first))
		Expect(result[1]).To(BeIdenticalTo(&second))
	})

	It("keeps findings that differ in any reported field", func() {
		base := createIssue()

		otherLine := createIssue()
		otherLine.Line = "2"
		otherRule := createIssue()
		otherRule.RuleID = "G104"
		otherSeverity := createIssue()
		otherSeverity.Severity = issue.Low

		issues := []*issue.Issue{&base, &otherLine, &otherRule, &otherSeverity, &base}

		result := dedupIssues(issues)

		Expect(result).To(HaveLen(4))
		Expect(result[0]).To(BeIdenticalTo(&base))
	})

	It("preserves the first occurrence when duplicates are interleaved", func() {
		first := createIssue()
		other := createIssue()
		other.Line = "9"
		duplicate := createIssue()
		issues := []*issue.Issue{&first, &other, &duplicate}

		result := dedupIssues(issues)

		Expect(result).To(HaveLen(2))
		Expect(result[0]).To(BeIdenticalTo(&first))
		Expect(result[1]).To(BeIdenticalTo(&other))
	})

	It("handles empty and nil inputs", func() {
		Expect(dedupIssues(nil)).To(BeEmpty())
		Expect(dedupIssues([]*issue.Issue{})).To(BeEmpty())
	})
})
