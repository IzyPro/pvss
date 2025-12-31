# Pedersen Verifiable Secret Sharing (PVSS) Library

A production-ready Go implementation of Pedersen Verifiable Secret Sharing with human-friendly BIP-39 style mnemonic encoding.

## Features

✨ **Human-Readable Shares** - Shares encoded as BIP-39 compatible mnemonic phrases  
🔒 **Cryptographically Secure** - Based on elliptic curve cryptography (P-256)  
✅ **Verifiable Shares** - Built-in Pedersen commitment verification  
📦 **Threshold Secret Sharing** - Configurable (k,n) threshold schemes  
🎯 **Production Ready** - Comprehensive error handling and validation  
⚡ **Optimized** - Compressed elliptic curve points and efficient encoding  

## Overview

This library implements Pedersen Verifiable Secret Sharing (VSS), a cryptographic protocol that splits a secret into multiple shares where:

- Any **k shares** can reconstruct the original secret (threshold)
- Fewer than **k shares** reveal no information about the secret
- Each share can be **verified** for authenticity without revealing the secret
- Shares are encoded as **human-readable mnemonic phrases**

## Installation

```bash
go get github.com/IzyPro/pvss
```

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/IzyPro/pvss"
)

func main() {
    // Initialize the PVSS instance
    vss := pvss.NewPedersenVSS()
    
    // Split a secret into 5 shares with a threshold of 3
    secret := "My secret message that needs protection"
    shares, err := vss.SplitSecret(secret, 5, 3)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Generated %d shares:\n", len(shares))
    for i, share := range shares {
        fmt.Printf("Share %d:\n", i+1)
        fmt.Printf("  Key: %s\n", share.Key)
        fmt.Printf("  KeyCheck: %s\n\n", share.KeyCheck)
    }
    
    // Verify a share
    valid, err := vss.VerifyShare(shares[0])
    if err != nil {
        panic(err)
    }
    fmt.Printf("Share 1 is valid: %v\n", valid)
    
    // Reconstruct secret using 3 shares
    reconstructed, err := vss.ReconstructSecret(shares[:3])
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Reconstructed secret: %s\n", reconstructed)
    fmt.Printf("Match: %v\n", reconstructed == secret)
}
```

## API Reference

### Types

#### `Share`
```go
type Share struct {
    Key      string // Mnemonic phrase containing share data
    KeyCheck string // Mnemonic phrase containing verification data
}
```

Each share consists of two mnemonic phrases:
- **Key**: The actual share value encoded as BIP-39 words with checksum
- **KeyCheck**: Metadata for verification (commitments, threshold, etc.)

### Functions

#### `NewPedersenVSS() *PedersenVSS`

Creates a new PVSS instance with P-256 elliptic curve and BIP-39 English word list.

```go
vss := pvss.NewPedersenVSS()
```

#### `SplitSecret(secret string, numShares, threshold int) ([]Share, error)`

Splits a secret into multiple shares.

**Parameters:**
- `secret` - The secret string to split (must not be empty)
- `numShares` - Total number of shares to generate (1-255)
- `threshold` - Minimum number of shares required for reconstruction (1 ≤ threshold ≤ numShares)

**Returns:**
- `[]Share` - Array of generated shares
- `error` - Error if parameters are invalid

**Example:**
```go
shares, err := vss.SplitSecret("my-secret", 5, 3)
```

#### `VerifyShare(share Share) (bool, error)`

Verifies the authenticity of a share using Pedersen commitments.

**Parameters:**
- `share` - The share to verify

**Returns:**
- `bool` - `true` if share is valid, `false` otherwise
- `error` - Error if share data is corrupted or malformed

**Example:**
```go
valid, err := vss.VerifyShare(shares[0])
if err != nil {
    // Handle error
}
if !valid {
    // Share is invalid
}
```

#### `ReconstructSecret(shares []Share) (string, error)`

Reconstructs the original secret from shares.

**Parameters:**
- `shares` - Array of shares (must be at least threshold number)

**Returns:**
- `string` - The reconstructed secret
- `error` - Error if insufficient shares, corrupted data, or verification fails

**Example:**
```go
secret, err := vss.ReconstructSecret(shares[:3])
```

## How It Works

### Secret Splitting

1. **Chunking**: The secret is split into 31-byte chunks to fit within the P-256 field
2. **Polynomial Generation**: For each chunk, a random polynomial of degree (threshold-1) is generated with the chunk as the constant term
3. **Share Evaluation**: Each share is a point on the polynomial evaluated at a unique x-coordinate
4. **Commitment Generation**: Pedersen commitments are created for each polynomial coefficient
5. **Mnemonic Encoding**: Share data and metadata are encoded as BIP-39 mnemonic phrases with checksums

### Share Verification

1. **Checksum Validation**: Verifies mnemonic phrase integrity
2. **Commitment Verification**: Uses Pedersen commitments to verify share authenticity without revealing the secret
3. **Mathematical Validation**: Ensures share values match the expected polynomial evaluation

### Secret Reconstruction

1. **Validation**: Checks threshold, checksums, and share consistency
2. **Lagrange Interpolation**: Reconstructs each chunk's secret using the mathematical properties of polynomials
3. **Chunk Assembly**: Combines reconstructed chunks back into the original secret

## Security Properties

### Cryptographic Security

- **Information-Theoretic Security**: Fewer than threshold shares reveal no information about the secret
- **Verifiable Shares**: Pedersen commitments allow share verification without exposing the secret
- **Elliptic Curve Cryptography**: Uses NIST P-256 curve for commitment generation
- **Secure Random Generation**: Uses Go's `crypto/rand` for all random number generation

### Metadata Security

The `KeyCheck` (metadata) contains **only verification data**:
- Threshold parameter
- Number of chunks
- Pedersen commitments for verification

**Critical**: The metadata does **NOT** contain any information that could be used to reconstruct the secret without the required threshold of shares.

## Error Handling

The library provides comprehensive error handling:

```go
shares, err := vss.SplitSecret("secret", 5, 3)
if err != nil {
    switch {
    case errors.Is(err, pvss.ErrInvalidThreshold):
        // Handle threshold error
    case errors.Is(err, pvss.ErrEmptySecret):
        // Handle empty secret error
    default:
        // Handle other errors
    }
}
```

Common errors:
- `threshold cannot be greater than number of shares`
- `threshold must be at least 1`
- `number of shares cannot exceed 255`
- `secret cannot be empty`
- `insufficient shares: need X, got Y`
- `invalid share phrase checksum`
- `duplicate share ID`

## Performance Considerations

### Share Size

For a typical secret:
- **Share phrase (Key)**: 8-15 BIP-39 words
- **Metadata phrase (KeyCheck)**: 15-30 BIP-39 words
- **Total**: ~25-45 words per complete share

Share size scales with:
- Secret length (more chunks = more words)
- Threshold value (higher threshold = more commitments)

### Computational Complexity

- **Splitting**: O(n × m × t) where n=shares, m=chunks, t=threshold
- **Verification**: O(m × t) where m=chunks, t=threshold
- **Reconstruction**: O(t² × m) where t=threshold, m=chunks

## Best Practices

### Secret Storage

```go
// ❌ Don't store all shares together
storeInSameDatabase(shares) 

// ✅ Distribute shares across different locations
storeShare(shares[0], "location1")
storeShare(shares[1], "location2")
storeShare(shares[2], "location3")
```

### Share Distribution

```go
// Create 7 shares with threshold of 4
shares, _ := vss.SplitSecret(secret, 7, 4)

// Distribute to different parties/locations
// This allows up to 3 shares to be lost/compromised
sendToParty("Alice", shares[0])
sendToParty("Bob", shares[1])
sendToParty("Carol", shares[2])
// ... etc
```

### Verification Before Reconstruction

```go
// Always verify shares before attempting reconstruction
validShares := []pvss.Share{}
for _, share := range shares {
    valid, err := vss.VerifyShare(share)
    if err != nil || !valid {
        continue // Skip invalid shares
    }
    validShares = append(validShares, share)
}

if len(validShares) >= threshold {
    secret, _ := vss.ReconstructSecret(validShares)
}
```

## Use Cases

- **Key Management**: Distribute cryptographic keys across multiple parties
- **Backup Systems**: Create redundant backups where no single backup compromises security
- **Multi-Party Computation**: Enable collaborative secret management
- **Disaster Recovery**: Ensure critical secrets survive loss of some shares
- **Access Control**: Require multiple parties to authorize access to sensitive data

## Limitations

- **Maximum shares**: 255 (limited by 1-byte ID field)
- **Chunk size**: 31 bytes (ensures safe operation within P-256 field)
- **Secret size**: Unlimited (automatically chunked)
- **Word list**: BIP-39 English (2048 words)


## Testing

Run the test suite:

```bash
go test ./...
```

Run with race detector:

```bash
go test -race ./...
```

Run benchmarks:

```bash
go test -bench=. -benchmem
```


## Security

### Reporting Vulnerabilities

If you discover a security vulnerability, please contact me on [X (Twitter)](https://x.com/IzyPro_) or [LinkedIn](https://www.linkedin.com/in/uleluisrael/)  instead of using the issue tracker.


## References

- Pedersen, T. P. (1992). "[Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)"
- Shamir, A. (1979). "[How to Share a Secret](https://dl.acm.org/doi/abs/10.1145/359168.359176)"
- [BIP-39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf)

## Acknowledgments

- Built with Go's `crypto/elliptic` package
- BIP-39 word list for mnemonic encoding
- Inspired by threshold cryptography research

---

**Note**: This library is provided as-is for educational and production use. Always perform appropriate security reviews for your specific use case.