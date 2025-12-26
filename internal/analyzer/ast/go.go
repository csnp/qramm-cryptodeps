// Copyright 2024 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package ast provides AST-based analysis for crypto detection.
package ast

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/crypto"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// GoAnalyzer analyzes Go source code for cryptographic usage.
type GoAnalyzer struct {
	fset *token.FileSet
}

// NewGoAnalyzer creates a new Go AST analyzer.
func NewGoAnalyzer() *GoAnalyzer {
	return &GoAnalyzer{
		fset: token.NewFileSet(),
	}
}

// AnalyzeDirectory analyzes all Go files in a directory.
func (a *GoAnalyzer) AnalyzeDirectory(dir string) ([]types.CryptoUsage, error) {
	var allUsages []types.CryptoUsage

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip non-Go files
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Skip test files
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		// Skip vendor directory
		if strings.Contains(path, "/vendor/") {
			return nil
		}

		usages, err := a.AnalyzeFile(path)
		if err != nil {
			// Log but continue on parse errors
			return nil
		}

		allUsages = append(allUsages, usages...)
		return nil
	})

	return allUsages, err
}

// AnalyzeFile analyzes a single Go file for cryptographic usage.
func (a *GoAnalyzer) AnalyzeFile(filename string) ([]types.CryptoUsage, error) {
	src, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	file, err := parser.ParseFile(a.fset, filename, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	visitor := &cryptoVisitor{
		fset:     a.fset,
		filename: filename,
		imports:  make(map[string]string),
		usages:   make([]types.CryptoUsage, 0),
	}

	// First pass: collect imports
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		visitor.imports[name] = path
	}

	// Second pass: find crypto usages
	ast.Walk(visitor, file)

	return visitor.usages, nil
}

// cryptoVisitor walks the AST looking for crypto-related code.
type cryptoVisitor struct {
	fset     *token.FileSet
	filename string
	imports  map[string]string // alias -> import path
	usages   []types.CryptoUsage
}

func (v *cryptoVisitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}

	switch n := node.(type) {
	case *ast.CallExpr:
		v.checkCallExpr(n)
	case *ast.SelectorExpr:
		v.checkSelectorExpr(n)
	}

	return v
}

// checkCallExpr checks function calls for crypto usage.
func (v *cryptoVisitor) checkCallExpr(call *ast.CallExpr) {
	// Check for crypto function calls like rsa.GenerateKey, aes.NewCipher, etc.
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		// Package.Function pattern
		if ident, ok := fun.X.(*ast.Ident); ok {
			pkgName := ident.Name
			funcName := fun.Sel.Name

			// Check if this is a crypto package
			if importPath, ok := v.imports[pkgName]; ok {
				if pattern, isCrypto := crypto.IsCryptoImport(importPath, types.EcosystemGo); isCrypto {
					usage := v.createUsage(call, importPath, funcName, pattern)
					if usage != nil {
						v.usages = append(v.usages, *usage)
					}
				}
			}
		}
	}
}

// checkSelectorExpr checks for crypto type references.
func (v *cryptoVisitor) checkSelectorExpr(sel *ast.SelectorExpr) {
	if ident, ok := sel.X.(*ast.Ident); ok {
		pkgName := ident.Name

		if importPath, ok := v.imports[pkgName]; ok {
			if _, isCrypto := crypto.IsCryptoImport(importPath, types.EcosystemGo); isCrypto {
				// Check for specific crypto types/constants
				typeName := sel.Sel.Name
				if algorithm := v.detectAlgorithmFromName(typeName, importPath); algorithm != "" {
					pos := v.fset.Position(sel.Pos())
					info, _ := crypto.ClassifyAlgorithm(algorithm)

					usage := types.CryptoUsage{
						Algorithm:   info.Name,
						Type:        info.Type,
						QuantumRisk: info.QuantumRisk,
						Severity:    info.Severity,
						Location: types.Location{
							File: v.filename,
							Line: pos.Line,
						},
					}
					v.usages = append(v.usages, usage)
				}
			}
		}
	}
}

// createUsage creates a CryptoUsage from a function call.
func (v *cryptoVisitor) createUsage(call *ast.CallExpr, importPath, funcName string, pattern crypto.ImportPattern) *types.CryptoUsage {
	pos := v.fset.Position(call.Pos())

	// Detect algorithm from function name and import path
	algorithm := v.detectAlgorithmFromFunc(funcName, importPath)
	if algorithm == "" {
		// Use first algorithm from pattern as fallback
		if len(pattern.Algorithms) > 0 {
			algorithm = pattern.Algorithms[0]
		} else {
			return nil
		}
	}

	info, found := crypto.ClassifyAlgorithm(algorithm)
	if !found {
		info = crypto.AlgorithmInfo{
			Name:        algorithm,
			Type:        "unknown",
			QuantumRisk: types.RiskUnknown,
			Severity:    types.SeverityInfo,
		}
	}

	return &types.CryptoUsage{
		Algorithm:   info.Name,
		Type:        info.Type,
		QuantumRisk: info.QuantumRisk,
		Severity:    info.Severity,
		Location: types.Location{
			File: v.filename,
			Line: pos.Line,
		},
		CallPath: []string{funcName + "()"},
	}
}

// detectAlgorithmFromFunc detects the algorithm from a function name.
func (v *cryptoVisitor) detectAlgorithmFromFunc(funcName, importPath string) string {
	funcLower := strings.ToLower(funcName)

	// RSA functions
	if strings.Contains(importPath, "crypto/rsa") {
		return "RSA"
	}

	// ECDSA functions
	if strings.Contains(importPath, "crypto/ecdsa") {
		return "ECDSA"
	}

	// Ed25519 functions
	if strings.Contains(importPath, "crypto/ed25519") || strings.Contains(importPath, "x/crypto/ed25519") {
		return "Ed25519"
	}

	// AES functions
	if strings.Contains(importPath, "crypto/aes") {
		return "AES"
	}

	// DES functions
	if strings.Contains(importPath, "crypto/des") {
		if strings.Contains(funcLower, "triple") || strings.Contains(funcLower, "3des") {
			return "3DES"
		}
		return "DES"
	}

	// Hash functions
	if strings.Contains(importPath, "crypto/sha256") {
		return "SHA-256"
	}
	if strings.Contains(importPath, "crypto/sha512") {
		return "SHA-512"
	}
	if strings.Contains(importPath, "crypto/sha1") {
		return "SHA-1"
	}
	if strings.Contains(importPath, "crypto/md5") {
		return "MD5"
	}

	// RC4
	if strings.Contains(importPath, "crypto/rc4") {
		return "RC4"
	}

	// DSA
	if strings.Contains(importPath, "crypto/dsa") {
		return "DSA"
	}

	// ECDH
	if strings.Contains(importPath, "crypto/ecdh") {
		return "ECDH"
	}

	// Elliptic curves
	if strings.Contains(importPath, "crypto/elliptic") {
		if strings.Contains(funcLower, "p256") {
			return "P-256"
		}
		if strings.Contains(funcLower, "p384") {
			return "P-384"
		}
		if strings.Contains(funcLower, "p521") {
			return "P-521"
		}
		return "ECDSA"
	}

	// x/crypto packages
	if strings.Contains(importPath, "x/crypto/chacha20") {
		return "ChaCha20"
	}
	if strings.Contains(importPath, "x/crypto/curve25519") {
		return "X25519"
	}
	if strings.Contains(importPath, "x/crypto/bcrypt") {
		return "bcrypt"
	}
	if strings.Contains(importPath, "x/crypto/argon2") {
		return "Argon2"
	}
	if strings.Contains(importPath, "x/crypto/scrypt") {
		return "scrypt"
	}
	if strings.Contains(importPath, "x/crypto/sha3") {
		return "SHA3"
	}

	return ""
}

// detectAlgorithmFromName detects algorithm from a type/constant name.
func (v *cryptoVisitor) detectAlgorithmFromName(name, importPath string) string {
	nameLower := strings.ToLower(name)

	// Common type patterns
	typePatterns := map[string]string{
		"publickey":   "",
		"privatekey":  "",
		"generatekey": "",
		"newcipher":   "",
		"new":         "",
		"sum":         "",
		"sign":        "",
		"verify":      "",
		"encrypt":     "",
		"decrypt":     "",
	}

	// Check if this is a crypto operation
	for pattern := range typePatterns {
		if strings.Contains(nameLower, pattern) {
			return v.detectAlgorithmFromFunc(name, importPath)
		}
	}

	return ""
}
