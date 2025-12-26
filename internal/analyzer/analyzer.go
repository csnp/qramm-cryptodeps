// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package analyzer provides the core dependency analysis functionality.
package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer/ondemand"
	"github.com/csnp/qramm-cryptodeps/internal/analyzer/reachability"
	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/internal/manifest"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// Analyzer analyzes dependencies for cryptographic usage.
type Analyzer struct {
	db       *database.Database
	options  Options
	ondemand *ondemand.Analyzer
}

// Options configures the analyzer behavior.
type Options struct {
	Offline      bool   // Only use database, no on-demand analysis
	Deep         bool   // Force on-demand analysis for all packages
	Reachability bool   // Perform reachability analysis to determine actual crypto usage
	RiskFilter   string // Filter by risk level (vulnerable, partial, all)
	MinSeverity  string // Minimum severity to report
}

// New creates a new analyzer with the given database and options.
func New(db *database.Database, opts Options) *Analyzer {
	a := &Analyzer{
		db:      db,
		options: opts,
	}

	// Initialize on-demand analyzer if deep mode is enabled
	if opts.Deep && !opts.Offline {
		a.ondemand = ondemand.NewAnalyzer("")
	}

	return a
}

// Analyze analyzes dependencies in a manifest file.
func (a *Analyzer) Analyze(path string) (*types.ScanResult, error) {
	// Parse the manifest
	m, err := manifest.DetectAndParse(path)
	if err != nil {
		return nil, err
	}

	return a.analyzeManifest(m, path)
}

// AnalyzeAll discovers and analyzes all manifests in a directory (including workspaces).
func (a *Analyzer) AnalyzeAll(path string) (*types.MultiProjectResult, error) {
	// Discover and parse all manifests
	manifests, err := manifest.DetectAndParseAll(path)
	if err != nil {
		return nil, err
	}

	var results []*types.ScanResult
	for _, m := range manifests {
		result, err := a.analyzeManifest(m, filepath.Dir(m.Path))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to analyze %s: %v\n", m.Path, err)
			continue
		}
		results = append(results, result)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no manifests could be analyzed")
	}

	return types.AggregateResults(path, results), nil
}

// analyzeManifest analyzes a single parsed manifest.
func (a *Analyzer) analyzeManifest(m *manifest.Manifest, projectPath string) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Project:      projectPath,
		Manifest:     m.Path,
		Ecosystem:    m.Ecosystem,
		ScanDate:     time.Now(),
		Dependencies: make([]types.DependencyResult, 0, len(m.Dependencies)),
		Summary:      types.ScanSummary{},
	}

	// Analyze each dependency
	for _, dep := range m.Dependencies {
		depResult := a.analyzeDependency(dep)
		result.Dependencies = append(result.Dependencies, depResult)

		// Update summary
		result.Summary.TotalDependencies++
		if dep.Direct {
			result.Summary.DirectDependencies++
		}
		if depResult.Analysis != nil && len(depResult.Analysis.Crypto) > 0 {
			result.Summary.WithCrypto++
			// Check quantum risk
			for _, crypto := range depResult.Analysis.Crypto {
				switch crypto.QuantumRisk {
				case types.RiskVulnerable:
					result.Summary.QuantumVulnerable++
				case types.RiskPartial:
					result.Summary.QuantumPartial++
				}
			}
		}
		if !depResult.InDatabase {
			result.Summary.NotInDatabase++
		}
	}

	// Perform reachability analysis if enabled and ecosystem supports it
	if a.options.Reachability && m.Ecosystem == types.EcosystemGo {
		a.performReachabilityAnalysis(result, projectPath)
	}

	// Generate hints based on results
	result.Hints = a.generateHints(result)

	return result, nil
}

// performReachabilityAnalysis analyzes the user's source code to determine
// which crypto functions are actually reachable from their code.
func (a *Analyzer) performReachabilityAnalysis(result *types.ScanResult, projectPath string) {
	// Get the project directory (parent of manifest)
	projectDir := filepath.Dir(result.Manifest)
	if projectDir == "" || projectDir == "." {
		projectDir = projectPath
	}

	// Create reachability analyzer
	reachAnalyzer := reachability.NewAnalyzer(projectDir)

	// Perform analysis
	traces, err := reachAnalyzer.Analyze()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: reachability analysis failed: %v\n", err)
		return
	}

	// Mark that reachability was analyzed
	result.Summary.ReachabilityAnalyzed = true

	// Classify all crypto findings by reachability
	for i := range result.Dependencies {
		dep := &result.Dependencies[i]
		if dep.Analysis == nil || len(dep.Analysis.Crypto) == 0 {
			continue
		}

		// Classify each crypto usage
		dep.Analysis.Crypto = reachability.ClassifyFindings(dep.Analysis.Crypto, traces)

		// Update summary stats
		for _, crypto := range dep.Analysis.Crypto {
			switch crypto.Reachability {
			case types.ReachabilityConfirmed:
				result.Summary.ConfirmedCrypto++
			case types.ReachabilityReachable:
				result.Summary.ReachableCrypto++
			case types.ReachabilityAvailable:
				result.Summary.AvailableCrypto++
			}
		}
	}
}

// generateHints creates actionable suggestions based on scan results.
func (a *Analyzer) generateHints(result *types.ScanResult) []string {
	hints := make([]string, 0)

	// Hint: suggest --deep when many packages not in database
	if result.Summary.NotInDatabase > 0 && !a.options.Deep {
		pct := float64(result.Summary.NotInDatabase) / float64(result.Summary.TotalDependencies) * 100
		if pct >= 50 || (result.Summary.WithCrypto == 0 && result.Summary.NotInDatabase > 5) {
			hints = append(hints, fmt.Sprintf(
				"%d packages (%.0f%%) not in database. Run with --deep for source code analysis.",
				result.Summary.NotInDatabase, pct))
		}
	}

	// Hint: no crypto found but packages exist
	if result.Summary.WithCrypto == 0 && result.Summary.TotalDependencies > 0 {
		if result.Summary.NotInDatabase == result.Summary.TotalDependencies {
			hints = append(hints, "No crypto findings. All packages are unknown - try --deep to analyze source code.")
		}
	}

	return hints
}

// analyzeDependency analyzes a single dependency.
func (a *Analyzer) analyzeDependency(dep types.Dependency) types.DependencyResult {
	result := types.DependencyResult{
		Dependency: dep,
		InDatabase: false,
	}

	// Look up in database
	analysis, found := a.db.Lookup(dep.Ecosystem, dep.Name, dep.Version)
	if found {
		result.Analysis = analysis
		result.InDatabase = true
		return result
	}

	// If offline mode or not deep, just return without analysis
	if a.options.Offline || !a.options.Deep {
		return result
	}

	// On-demand analysis
	if a.ondemand != nil {
		analysis, err := a.ondemand.Analyze(dep)
		if err != nil {
			// Log the error but continue
			fmt.Fprintf(os.Stderr, "Warning: on-demand analysis failed for %s: %v\n", dep.Name, err)
			return result
		}
		result.Analysis = analysis
		result.DeepAnalyzed = true
	}

	return result
}
