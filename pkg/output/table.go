// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// TableFormatter formats scan results as a human-readable table.
type TableFormatter struct {
	Options FormatterOptions
}

// cryptoDetail holds info for detailed crypto breakdown.
type cryptoDetail struct {
	algorithm    string
	risk         types.QuantumRisk
	reachability types.Reachability
	dependency   string
}

// Format writes the scan result as a table.
func (f *TableFormatter) Format(result *types.ScanResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	// Header
	fmt.Fprintf(w, "\nScanning %s... found %d dependencies\n\n", result.Manifest, result.Summary.TotalDependencies)

	// Check if there are any crypto findings
	hasCrypto := false
	for _, dep := range result.Dependencies {
		if dep.Analysis != nil && len(dep.Analysis.Crypto) > 0 {
			hasCrypto = true
			break
		}
	}

	if !hasCrypto {
		fmt.Fprintln(w, "No cryptographic usage detected in dependencies.")
		fmt.Fprintln(w)
		return nil
	}

	hasReachability := result.Summary.ReachabilityAnalyzed

	// Collect all crypto details for breakdown
	var allCrypto []cryptoDetail
	remediations := make(map[string]string) // algorithm -> remediation

	for _, dep := range result.Dependencies {
		if dep.Analysis == nil || len(dep.Analysis.Crypto) == 0 {
			continue
		}

		depName := dep.Dependency.Name
		if dep.Dependency.Version != "" {
			depName = fmt.Sprintf("%s@%s", dep.Dependency.Name, dep.Dependency.Version)
		}

		for _, crypto := range dep.Analysis.Crypto {
			allCrypto = append(allCrypto, cryptoDetail{
				algorithm:    crypto.Algorithm,
				risk:         crypto.QuantumRisk,
				reachability: crypto.Reachability,
				dependency:   depName,
			})
			if crypto.Remediation != "" {
				remediations[crypto.Algorithm] = crypto.Remediation
			}
		}
	}

	// Print detailed crypto breakdown grouped by reachability
	if hasReachability {
		f.printReachabilityBreakdown(w, allCrypto)
	} else {
		f.printSimpleBreakdown(w, allCrypto)
	}

	// Summary
	fmt.Fprintln(w, strings.Repeat("─", 90))
	if hasReachability {
		fmt.Fprintf(w, "SUMMARY: %d deps | %d with crypto | %d vulnerable | %d partial\n",
			result.Summary.TotalDependencies,
			result.Summary.WithCrypto,
			result.Summary.QuantumVulnerable,
			result.Summary.QuantumPartial,
		)
		fmt.Fprintf(w, "REACHABILITY: %d confirmed | %d reachable | %d available-only\n\n",
			result.Summary.ConfirmedCrypto,
			result.Summary.ReachableCrypto,
			result.Summary.AvailableCrypto,
		)
	} else {
		fmt.Fprintf(w, "SUMMARY: %d deps | %d with crypto | %d vulnerable | %d partial\n\n",
			result.Summary.TotalDependencies,
			result.Summary.WithCrypto,
			result.Summary.QuantumVulnerable,
			result.Summary.QuantumPartial,
		)
	}

	// Display remediation guidance
	if f.Options.ShowRemediation && len(remediations) > 0 {
		f.printRemediation(w, allCrypto, remediations)
	}

	// Count deep-analyzed packages
	deepAnalyzed := 0
	notAnalyzed := 0
	for _, dep := range result.Dependencies {
		if dep.DeepAnalyzed {
			deepAnalyzed++
		} else if !dep.InDatabase && dep.Analysis == nil {
			notAnalyzed++
		}
	}

	// Info for deep-analyzed packages
	if deepAnalyzed > 0 {
		fmt.Fprintf(w, "✓ %d packages analyzed via AST (--deep)\n", deepAnalyzed)
	}

	// Warning for packages not analyzed
	if notAnalyzed > 0 {
		fmt.Fprintf(w, "⚠ %d packages not in database (use --deep to analyze)\n", notAnalyzed)
	}

	if deepAnalyzed > 0 || notAnalyzed > 0 {
		fmt.Fprintln(w)
	}

	return nil
}

// printReachabilityBreakdown prints crypto grouped by reachability status.
func (f *TableFormatter) printReachabilityBreakdown(w io.Writer, allCrypto []cryptoDetail) {
	// Group by reachability
	confirmed := filterByReachability(allCrypto, types.ReachabilityConfirmed)
	reachable := filterByReachability(allCrypto, types.ReachabilityReachable)
	available := filterByReachability(allCrypto, types.ReachabilityAvailable)

	// Sort each group by risk (vulnerable first)
	sortByRisk(confirmed)
	sortByRisk(reachable)
	sortByRisk(available)

	// Print CONFIRMED section (most important)
	if len(confirmed) > 0 {
		fmt.Fprintln(w, "⚠ CONFIRMED - Actually used by your code:")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		fmt.Fprintf(w, "  %-14s %-12s %s\n", "ALGORITHM", "RISK", "DEPENDENCY")
		for _, c := range confirmed {
			riskIcon := riskIcon(c.risk)
			fmt.Fprintf(w, "  %s %-12s %-12s %s\n", riskIcon, c.algorithm, formatRisk(c.risk), c.dependency)
		}
		fmt.Fprintln(w)
	}

	// Print REACHABLE section
	if len(reachable) > 0 {
		fmt.Fprintln(w, "◐ REACHABLE - In call graph from your code:")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		fmt.Fprintf(w, "  %-14s %-12s %s\n", "ALGORITHM", "RISK", "DEPENDENCY")
		for _, c := range reachable {
			riskIcon := riskIcon(c.risk)
			fmt.Fprintf(w, "  %s %-12s %-12s %s\n", riskIcon, c.algorithm, formatRisk(c.risk), c.dependency)
		}
		fmt.Fprintln(w)
	}

	// Print AVAILABLE section (lower priority)
	if len(available) > 0 {
		fmt.Fprintln(w, "○ AVAILABLE - In dependencies but not called:")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		fmt.Fprintf(w, "  %-14s %-12s %s\n", "ALGORITHM", "RISK", "DEPENDENCY")
		for _, c := range available {
			riskIcon := riskIcon(c.risk)
			fmt.Fprintf(w, "  %s %-12s %-12s %s\n", riskIcon, c.algorithm, formatRisk(c.risk), c.dependency)
		}
		fmt.Fprintln(w)
	}
}

// printSimpleBreakdown prints crypto without reachability grouping.
func (f *TableFormatter) printSimpleBreakdown(w io.Writer, allCrypto []cryptoDetail) {
	sortByRisk(allCrypto)

	fmt.Fprintln(w, "CRYPTO ALGORITHMS FOUND:")
	fmt.Fprintln(w, strings.Repeat("─", 90))
	fmt.Fprintf(w, "  %-14s %-12s %s\n", "ALGORITHM", "RISK", "DEPENDENCY")
	for _, c := range allCrypto {
		riskIcon := riskIcon(c.risk)
		fmt.Fprintf(w, "  %s %-12s %-12s %s\n", riskIcon, c.algorithm, formatRisk(c.risk), c.dependency)
	}
	fmt.Fprintln(w)
}

// printRemediation prints remediation guidance for vulnerable algorithms.
func (f *TableFormatter) printRemediation(w io.Writer, allCrypto []cryptoDetail, remediations map[string]string) {
	// Only show remediation for confirmed/reachable vulnerable algorithms
	seen := make(map[string]bool)
	var toShow []cryptoDetail

	for _, c := range allCrypto {
		if seen[c.algorithm] {
			continue
		}
		if c.risk == types.RiskVulnerable || c.risk == types.RiskPartial {
			if _, hasRemediation := remediations[c.algorithm]; hasRemediation {
				toShow = append(toShow, c)
				seen[c.algorithm] = true
			}
		}
	}

	if len(toShow) == 0 {
		return
	}

	// Sort: confirmed first, then vulnerable before partial
	sort.Slice(toShow, func(i, j int) bool {
		// Confirmed first
		if toShow[i].reachability == types.ReachabilityConfirmed && toShow[j].reachability != types.ReachabilityConfirmed {
			return true
		}
		if toShow[i].reachability != types.ReachabilityConfirmed && toShow[j].reachability == types.ReachabilityConfirmed {
			return false
		}
		// Then vulnerable before partial
		return riskPriority(toShow[i].risk) > riskPriority(toShow[j].risk)
	})

	fmt.Fprintln(w, "REMEDIATION GUIDANCE:")
	fmt.Fprintln(w, strings.Repeat("─", 90))
	for _, c := range toShow {
		icon := "!"
		if c.risk == types.RiskVulnerable {
			icon = "!!"
		}
		reachNote := ""
		if c.reachability == types.ReachabilityConfirmed {
			reachNote = " [PRIORITY]"
		}
		fmt.Fprintf(w, "  [%s] %-12s → %s%s\n", icon, c.algorithm, remediations[c.algorithm], reachNote)
	}
	fmt.Fprintln(w)
}

// filterByReachability returns crypto with the given reachability.
func filterByReachability(crypto []cryptoDetail, reach types.Reachability) []cryptoDetail {
	var result []cryptoDetail
	for _, c := range crypto {
		if c.reachability == reach {
			result = append(result, c)
		}
	}
	return result
}

// sortByRisk sorts crypto by risk level (vulnerable first).
func sortByRisk(crypto []cryptoDetail) {
	sort.Slice(crypto, func(i, j int) bool {
		return riskPriority(crypto[i].risk) > riskPriority(crypto[j].risk)
	})
}

// riskIcon returns an icon for the risk level.
func riskIcon(risk types.QuantumRisk) string {
	switch risk {
	case types.RiskVulnerable:
		return "🔴"
	case types.RiskPartial:
		return "🟡"
	case types.RiskSafe:
		return "🟢"
	default:
		return "⚪"
	}
}

// riskPriority returns a numeric priority for sorting risks.
func riskPriority(risk types.QuantumRisk) int {
	switch risk {
	case types.RiskVulnerable:
		return 3
	case types.RiskPartial:
		return 2
	case types.RiskSafe:
		return 1
	default:
		return 0
	}
}

// formatRisk formats a quantum risk level for display.
func formatRisk(risk types.QuantumRisk) string {
	switch risk {
	case types.RiskVulnerable:
		return "VULNERABLE"
	case types.RiskPartial:
		return "PARTIAL"
	case types.RiskSafe:
		return "SAFE"
	default:
		return "UNKNOWN"
	}
}
