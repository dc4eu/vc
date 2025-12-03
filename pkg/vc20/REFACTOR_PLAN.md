# Refactoring Plan for pkg/vc20

This document tracks the progress of refactoring the `pkg/vc20` package to improve readability, maintainability, and reduce code duplication.

## Status Overview

| Task | Status | Description |
|------|--------|-------------|
| 1. Consolidate Cryptographic Utilities | ✅ Completed | Create `pkg/vc20/crypto/common` for shared functions like `FindProofNode`. |
| 2. Standardize JSON-LD Options | ✅ Completed | Add factory method for `ld.JsonLdOptions` in `credential` package. |
| 3. Centralize Constants | ✅ Completed | Define constants for Context URLs, Proof Types, etc. |
| 4. Refactor `sd_suite.go` | ✅ Completed | Split monolithic file into `sd_suite.go`, `sd_types.go`, and `sd_helpers.go`. |
| 5. Update Suites | ✅ Completed | Update all crypto suites to use shared utilities and constants. |

## Detailed Tasks

### 1. Consolidate Cryptographic Utilities
- [x] Create directory `pkg/vc20/crypto/common`
- [x] Create `pkg/vc20/crypto/common/utils.go`
- [x] Move `FindProofNode` / `sdFindProofNode` to `common.FindProofNode`
- [x] Move `HasType` / `sdHasType` to `common.HasType`

### 2. Standardize JSON-LD Options & 3. Centralize Constants
- [x] Create `pkg/vc20/credential/common.go` (or similar)
- [x] Add `NewJSONLDOptions()` factory function
- [x] Add constants:
    - `ContextV2 = "https://www.w3.org/ns/credentials/v2"`
    - `ProofTypeDataIntegrity = "DataIntegrityProof"`

### 4. Refactor `sd_suite.go` (ECDSA-SD)
- [x] Create `pkg/vc20/crypto/ecdsa/sd_types.go` for CBOR structures
- [x] Create `pkg/vc20/crypto/ecdsa/sd_helpers.go` for N-Quad parsing and helpers
- [x] Clean up `pkg/vc20/crypto/ecdsa/sd_suite.go` to contain only protocol logic

### 5. Update Suites
- [x] Update `pkg/vc20/crypto/eddsa/suite.go`
- [x] Update `pkg/vc20/crypto/ecdsa/suite.go`
- [x] Update `pkg/vc20/crypto/ecdsa/sd_suite.go`
