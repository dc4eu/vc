# VC20 Module Architecture

This document describes the architectural principles and design of the `vc20` module, which implements W3C Verifiable Credentials Data Integrity 1.0 and specific cryptographic suites.

## Core Principles

1.  **RDF-Centric Data Model**: The module treats Verifiable Credentials primarily as RDF datasets. While the input and output are JSON-LD, internal processing relies on RDF N-Quads and URDNA2015 canonicalization to ensure data integrity and consistent hashing.
2.  **Suite Modularity**: Cryptographic suites are implemented as separate structures that operate on the common `RDFCredential` abstraction.
3.  **Selective Disclosure Support**: The architecture is designed to support advanced features like Selective Disclosure (ECDSA-SD), which requires complex manipulation of the RDF graph (skolemization, grouping, and label mapping).

## Key Components

### 1. `RDFCredential` (`pkg/vc20/credential`)

The `RDFCredential` struct is the central abstraction. It wraps the underlying JSON-LD processor and RDF dataset.

*   **Responsibilities**:
    *   Parsing JSON-LD into an RDF Dataset.
    *   Canonicalizing the dataset using URDNA2015.
    *   Separating the "Proof" graph from the "Credential" graph.
    *   Serializing back to JSON-LD or N-Quads.
*   **Design Choice**: It uses `github.com/piprate/json-gold` for JSON-LD processing.

### 2. Cryptographic Suites (`pkg/vc20/crypto/ecdsa`)

The module implements two main suites:

#### A. `ecdsa-rdfc-2019` (`Suite`)
*   **Standard**: W3C Data Integrity ECDSA Cryptosuite v1.0.
*   **Mechanism**:
    1.  Canonicalize the credential (without proof).
    2.  Canonicalize the proof configuration.
    3.  Hash both and sign the concatenation.
*   **Output**: A `DataIntegrityProof` with a `proofValue` encoded in Multibase (base58-btc).

#### B. `ecdsa-sd-2023` (`SdSuite`)
*   **Standard**: W3C ECDSA Selective Disclosure Cryptosuite v1.0 (Draft).
*   **Mechanism**:
    *   **Base Proof (Sign)**:
        *   **Skolemization**: Replaces blank node identifiers with HMAC-based stable IDs to allow for selective disclosure of graph components.
        *   **Grouping**: Groups N-Quads by their subject/object blank nodes.
        *   **Ephemeral Signing**: Signs each group individually with an ephemeral ECDSA key.
        *   **Base Signing**: Signs the ephemeral public key and metadata with the Issuer's long-term key.
        *   **Output**: A CBOR-encoded `BaseProofValue`.
    *   **Derived Proof (Derive)**:
        *   Selects a subset of quads to reveal.
        *   **Label Mapping**: Generates new random IDs for revealed blank nodes and creates a map to the original HMAC IDs.
        *   **URN Strategy**: Uses `urn:bn:<id>` as temporary identifiers during JSON-LD processing to prevent the processor from renaming blank nodes, ensuring the `LabelMap` remains valid.
        *   **Output**: A CBOR-encoded `DerivedProofValue` containing the subset of signatures and the label map.
    *   **Verification**:
        *   Reconstructs the original N-Quads by applying the `LabelMap` (reversing the ID randomization).
        *   Verifies the ephemeral key signature against the Issuer's key.
        *   Verifies the group signatures against the ephemeral key.

#### C. `eddsa-rdfc-2022` (Implemented in Test Server)
*   **Standard**: W3C Data Integrity EdDSA Cryptosuite v1.0.
*   **Mechanism**: Similar to `ecdsa-rdfc-2019` but uses Ed25519 keys and signatures.
*   **Graph Normalization**: Includes a specific workaround for `json-gold` where embedded Verifiable Credentials in a Verifiable Presentation are moved from the default graph to named graphs to comply with the VC Data Model 2.0 RDF structure (`@container: @graph`).

## Data Flow

1.  **Input**: JSON-LD byte slice.
2.  **Parsing**: `NewRDFCredentialFromJSON` creates an `RDFCredential`.
3.  **Signing**:
    *   The Suite extracts the payload (credential without proof).
    *   Performs canonicalization and hashing.
    *   Generates the signature.
    *   Re-marshals the credential with the new proof attached.
4.  **Verification**:
    *   Extracts the proof object.
    *   Re-calculates the canonical hash of the payload.
    *   Verifies the signature against the public key.

## Specific Implementation Details

*   **URN Freezing**: In `ecdsa-sd-2023`, standard JSON-LD processors rename blank nodes (e.g., `_:b0` -> `_:b1`) during framing and canonicalization. This breaks the link between the derived credential and the original signatures. The module solves this by temporarily converting blank nodes to URNs (`urn:bn:b0`) which are treated as absolute IRIs and preserved by the processor. They are converted back to blank nodes before hashing.
*   **CBOR & Multibase**: The SD suite uses CBOR for complex proof structures and Multibase (base64url) for the final string representation, whereas the standard suite uses raw bytes and base58-btc.

## Dependencies

*   `github.com/piprate/json-gold`: JSON-LD/RDF processing.
*   `github.com/fxamacker/cbor/v2`: CBOR encoding.
*   `github.com/multiformats/go-multibase`: Encoding formats.
