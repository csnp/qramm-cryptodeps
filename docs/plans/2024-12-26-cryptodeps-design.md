# CryptoDeps Design Document

**Date:** 2024-12-26
**Status:** Approved
**Author:** CSNP Team

---

## Overview

CryptoDeps is a dependency crypto analyzer that identifies quantum-vulnerable cryptographic algorithms in software dependencies. It answers the question: *"My app has hundreds of dependencies. Which ones use quantum-vulnerable crypto, and how does that crypto reach my code?"*

### Key Differentiators

1. **Crypto Call Graph** — Shows the full path from your code to crypto usage in dependencies
2. **Community-Curated Database** — Git-based, transparent, forkable knowledge base
3. **Reproducible Analysis** — Every analysis is verifiable and signed
4. **Hybrid Engine** — Fast database lookups + deep on-demand AST analysis

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI Interface                            │
│   cryptodeps analyze ./go.mod                                   │
│   cryptodeps analyze ./package.json --format cbom               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Manifest Parser                             │
│   Detects ecosystem, parses dependencies + versions             │
│   Resolves transitive dependencies (full tree)                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Lookup Engine                               │
│                          │                                      │
│    ┌─────────────────────┴─────────────────────┐                │
│    ▼                                           ▼                │
│  Database                                 On-Demand             │
│  (Git repo)                               Analyzer              │
│    │                                           │                │
│    ├─ Known package?                           ├─ Download src  │
│    │  └─ Return cached analysis                ├─ Parse AST     │
│    │                                           ├─ Trace calls   │
│    └─ Unknown?                                 └─ Generate      │
│       └─ Trigger on-demand ──────────────────────► analysis     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Output Formatter                             │
│   JSON | CBOM (CycloneDX) | SARIF | Table | Markdown           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Database Structure

The crypto knowledge base is a separate Git repository (`qramm-cryptodeps-db`) with one file per package/version:

```
qramm-cryptodeps-db/
├── README.md
├── CONTRIBUTING.md
├── schema/
│   └── package.schema.json      # JSON Schema for validation
├── database/
│   ├── go/
│   │   └── golang.org/
│   │       └── x/
│   │           └── crypto/
│   │               └── v0.17.0.yaml
│   ├── npm/
│   │   ├── jsonwebtoken/
│   │   │   ├── 9.0.0.yaml
│   │   │   └── 8.5.1.yaml
│   │   └── bcrypt/
│   │       └── 5.1.0.yaml
│   ├── pypi/
│   │   └── cryptography/
│   │       └── 41.0.0.yaml
│   └── maven/
│       └── org.bouncycastle/
│           └── bcprov-jdk18on/
│               └── 1.77.yaml
└── index/
    ├── go.json          # Quick lookup index
    ├── npm.json
    ├── pypi.json
    └── maven.json
```

### Package File Format

```yaml
package: jsonwebtoken
version: "9.0.0"
ecosystem: npm
license: MIT

analysis:
  date: 2024-12-26
  method: ast
  tool: cryptodeps/1.0.0
  contributor: github:decimai
  sourceHash: sha256:a1b2c3...

crypto:
  - algorithm: RS256
    type: signature
    quantumRisk: VULNERABLE
    severity: HIGH
    location:
      file: lib/sign.js
      line: 47
    callPath:
      - "sign(payload, key)"
      - "createSign('RSA-SHA256')"
      - "crypto.sign()"

  - algorithm: HS256
    type: signature
    quantumRisk: PARTIAL
    severity: INFO
    location:
      file: lib/sign.js
      line: 52

quantumSummary:
  vulnerable: 1
  partial: 1
  safe: 0
```

---

## On-Demand Analysis Engine

When a package isn't in the database:

### Pipeline

1. **Fetch Source**
   - Go: `go mod download` + locate in module cache
   - npm: Registry tarball download
   - Python: `pip download --no-deps`
   - Maven: Download sources JAR

2. **Parse AST**
   - Go: `go/ast` (stdlib, native)
   - JavaScript: tree-sitter-javascript
   - Python: tree-sitter-python
   - Java: tree-sitter-java

3. **Identify Crypto Entry Points**
   - Go: `crypto/*`, `golang.org/x/crypto/*`
   - JS: `crypto`, `node:crypto`, `crypto-js`, `bcrypt`
   - Python: `cryptography`, `hashlib`, `Crypto`, `ssl`
   - Java: `javax.crypto.*`, `java.security.*`, `org.bouncycastle.*`

4. **Trace Call Graph**
   - Find all functions that call crypto APIs
   - Trace backwards to exported/public functions
   - Build full path from public API to crypto call

5. **Classify**
   - Map algorithms to quantum risk levels
   - Generate structured analysis with evidence

### Performance Target

- Analyze a medium package (1000 files) in <10 seconds
- Downloaded sources cached locally

---

## CLI Interface

```bash
# Basic usage
cryptodeps analyze ./go.mod
cryptodeps analyze ./package.json
cryptodeps analyze .                    # Auto-detect manifest

# Output formats
cryptodeps analyze . --format table     # Human-readable (default)
cryptodeps analyze . --format json      # Machine-readable
cryptodeps analyze . --format cbom      # CycloneDX CBOM
cryptodeps analyze . --format sarif     # GitHub Security
cryptodeps analyze . --format markdown  # Reports

# Filtering
cryptodeps analyze . --risk vulnerable  # Only quantum-vulnerable
cryptodeps analyze . --risk partial     # Include partial risk
cryptodeps analyze . --min-severity high

# Analysis control
cryptodeps analyze . --offline          # Database only, no downloads
cryptodeps analyze . --deep             # Force on-demand for all
cryptodeps analyze . --timeout 30s      # Per-package timeout

# Database management
cryptodeps db update                    # Pull latest database
cryptodeps db stats                     # Show database coverage
cryptodeps db path                      # Show database location

# Contributing
cryptodeps contribute ./analysis.yaml   # Submit to database
cryptodeps analyze . --export-unknown   # Export unknowns for contribution
```

### Example Output

```
$ cryptodeps analyze ./go.mod

Scanning go.mod... found 47 dependencies

DEPENDENCY                          CRYPTO          RISK
────────────────────────────────────────────────────────────────
golang.org/x/crypto v0.17.0         Ed25519         VULNERABLE
                                    ChaCha20        SAFE
github.com/golang-jwt/jwt/v5        RS256, ES256    VULNERABLE
github.com/go-sql-driver/mysql      SHA256          PARTIAL
cloud.google.com/go/kms             [uses KMS]      UNKNOWN

────────────────────────────────────────────────────────────────
SUMMARY: 47 deps | 12 use crypto | 4 vulnerable | 3 partial

⚠ 2 packages not in database (use --deep to analyze)
```

---

## Contribution Workflow

### Flow

1. User runs `cryptodeps analyze . --deep`
2. On-demand analysis runs for unknown packages
3. CLI prompts: "jsonwebtoken@9.0.0 analyzed. Contribute? [Y/n]"
4. User runs `cryptodeps contribute ./jsonwebtoken-9.0.0.yaml`
5. CLI opens PR against qramm-cryptodeps-db
6. CI validates schema and reproduces analysis
7. Maintainer reviews and merges

### Trust Levels

| Level | Badge | Meaning |
|-------|-------|---------|
| `verified` | ✓ | CI reproduced the analysis |
| `reviewed` | ✓✓ | Maintainer manually reviewed |
| `community` | ○ | Contributed, not yet verified |

---

## Project Structure

```
qramm-cryptodeps/
├── cmd/
│   └── cryptodeps/
│       └── main.go              # CLI entry point
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go          # Core analysis orchestration
│   │   ├── ast/
│   │   │   ├── go.go            # Go AST parser
│   │   │   ├── javascript.go    # JS via tree-sitter
│   │   │   ├── python.go        # Python via tree-sitter
│   │   │   └── java.go          # Java via tree-sitter
│   │   └── callgraph/
│   │       └── tracer.go        # Call graph construction
│   ├── database/
│   │   ├── database.go          # Database interface
│   │   ├── lookup.go            # Fast index lookups
│   │   ├── update.go            # Git pull/sync
│   │   └── contribute.go        # PR generation
│   ├── manifest/
│   │   ├── parser.go            # Auto-detect & parse
│   │   ├── gomod.go             # go.mod parser
│   │   ├── npm.go               # package.json parser
│   │   ├── python.go            # requirements.txt parser
│   │   └── maven.go             # pom.xml parser
│   └── resolver/
│       ├── resolver.go          # Dependency resolution
│       └── transitive.go        # Full tree resolution
├── pkg/
│   ├── crypto/
│   │   ├── patterns.go          # Crypto detection patterns
│   │   └── quantum.go           # Quantum risk classification
│   ├── output/
│   │   ├── table.go
│   │   ├── json.go
│   │   ├── cbom.go              # CycloneDX output
│   │   ├── sarif.go
│   │   └── markdown.go
│   └── types/
│       └── types.go             # Shared types
├── .github/
│   └── workflows/
│       └── ci.yml
├── .goreleaser.yaml
├── go.mod
├── go.sum
├── LICENSE
├── README.md
├── CONTRIBUTING.md
└── Makefile
```

---

## Tech Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Language | Go 1.21+ | Consistent with QRAMM toolkit |
| Go AST | `go/ast` (stdlib) | Native, fast, no dependencies |
| JS/Python/Java AST | tree-sitter | Battle-tested, multi-language |
| CLI Framework | cobra | Industry standard for Go CLIs |
| YAML Parsing | `gopkg.in/yaml.v3` | Full YAML 1.2 support |
| Git Operations | go-git | Pure Go, no git binary needed |
| Build | GoReleaser | Proven in CryptoScan |

---

## Implementation Phases

### Phase 1: Foundation (MVP)
- [ ] Project scaffolding (Go module, CI, GoReleaser)
- [ ] Manifest parsers (go.mod, package.json)
- [ ] Database structure + initial seed data
- [ ] Database lookup engine
- [ ] Table + JSON output
- [ ] Basic CLI (`analyze`, `db update`)

### Phase 2: Deep Analysis
- [ ] AST parsing for Go (native)
- [ ] AST parsing for JS (tree-sitter)
- [ ] Call graph tracer
- [ ] On-demand analysis pipeline
- [ ] Source fetching (Go modules, npm registry)

### Phase 3: Ecosystem Expansion
- [ ] Python manifest + AST parser
- [ ] Java/Maven manifest + AST parser
- [ ] CBOM + SARIF output formats
- [ ] Markdown reports

### Phase 4: Community
- [ ] Contribution workflow (`cryptodeps contribute`)
- [ ] PR generation for database
- [ ] Verification CI for contributions
- [ ] Database statistics dashboard

### Phase 5: Polish
- [ ] Performance optimization
- [ ] Offline mode
- [ ] GitHub Action for CI/CD
- [ ] Documentation site

---

## Competitive Moat

| Advantage | Why Money Can't Buy It |
|-----------|------------------------|
| **Community database** | Years of contributions, network effects |
| **Call graph evidence** | Novel feature, builds trust |
| **Reproducible analysis** | Verifiable claims, not guesses |
| **Ecosystem consistency** | QRAMM toolkit integration |
| **Git-based transparency** | Anyone can audit, fork, verify |

---

## References

- [CycloneDX CBOM Specification](https://cyclonedx.org/capabilities/cbom/)
- [IBM CBOMkit](https://github.com/IBM/CBOM)
- [GitHub CodeQL for CBOM](https://github.blog/security/vulnerability-research/addressing-post-quantum-cryptography-with-codeql/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [tree-sitter](https://tree-sitter.github.io/tree-sitter/)
