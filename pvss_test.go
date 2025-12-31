package pvss

import (
	"math/big"
	"strings"
	"testing"
)

// TestNewPedersenVSS tests initialization
func TestNewPedersenVSS(t *testing.T) {
	pvss := NewPedersenVSS()

	if pvss == nil {
		t.Fatal("NewPedersenVSS returned nil")
	}

	if pvss.curve == nil {
		t.Error("curve is nil")
	}

	if pvss.order == nil {
		t.Error("order is nil")
	}

	if pvss.mnemonicEncoder == nil {
		t.Error("mnemonicEncoder is nil")
	}
}

// TestChunkSecret tests secret chunking
func TestChunkSecret(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name            string
		secret          string
		expectedChunks  int
		expectedLastLen int
	}{
		{
			name:           "empty secret",
			secret:         "",
			expectedChunks: 0,
		},
		{
			name:            "short secret",
			secret:          "hello",
			expectedChunks:  1,
			expectedLastLen: 5,
		},
		{
			name:            "exactly 31 bytes",
			secret:          strings.Repeat("a", 31),
			expectedChunks:  1,
			expectedLastLen: 31,
		},
		{
			name:            "32 bytes (2 chunks)",
			secret:          strings.Repeat("a", 32),
			expectedChunks:  2,
			expectedLastLen: 1,
		},
		{
			name:            "62 bytes (2 chunks)",
			secret:          strings.Repeat("a", 62),
			expectedChunks:  2,
			expectedLastLen: 31,
		},
		{
			name:            "63 bytes (3 chunks)",
			secret:          strings.Repeat("a", 63),
			expectedChunks:  3,
			expectedLastLen: 1,
		},
		{
			name:           "large secret",
			secret:         strings.Repeat("test", 100),
			expectedChunks: 13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks := pvss.chunkSecret(tt.secret)

			if len(chunks) != tt.expectedChunks {
				t.Errorf("expected %d chunks, got %d", tt.expectedChunks, len(chunks))
			}

			if tt.expectedChunks > 0 {
				// Verify no chunk exceeds 31 bytes
				for i, chunk := range chunks {
					if len(chunk) > 31 {
						t.Errorf("chunk %d exceeds 31 bytes: %d", i, len(chunk))
					}
				}

				// Verify last chunk length
				if tt.expectedLastLen > 0 && len(chunks[len(chunks)-1]) != tt.expectedLastLen {
					t.Errorf("last chunk: expected %d bytes, got %d", tt.expectedLastLen, len(chunks[len(chunks)-1]))
				}

				// Verify chunks reconstruct original
				reconstructed := []byte{}
				for _, chunk := range chunks {
					reconstructed = append(reconstructed, chunk...)
				}
				if string(reconstructed) != tt.secret {
					t.Error("chunks don't reconstruct original secret")
				}
			}
		})
	}
}

// TestChunkToSecret tests chunk to secret conversion
func TestChunkToSecret(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name  string
		chunk []byte
	}{
		{
			name:  "empty chunk",
			chunk: []byte{},
		},
		{
			name:  "single byte",
			chunk: []byte{42},
		},
		{
			name:  "multiple bytes",
			chunk: []byte{1, 2, 3, 4, 5},
		},
		{
			name:  "max safe chunk (31 bytes)",
			chunk: make([]byte, 31),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretInt := pvss.chunkToSecret(tt.chunk)

			if secretInt == nil {
				t.Fatal("chunkToSecret returned nil")
			}

			// Verify it's within order
			if secretInt.Cmp(pvss.order) >= 0 {
				t.Error("secret exceeds curve order")
			}

			// Verify round trip for non-empty chunks
			if len(tt.chunk) > 0 {
				reconstructed := pvss.secretToChunk(secretInt)
				if len(reconstructed) > 0 && tt.chunk[0] != 0 {
					// Compare without leading zeros
					if !bytesEqualIgnoreLeadingZeros(tt.chunk, reconstructed) {
						t.Errorf("round trip failed: original=%v, reconstructed=%v", tt.chunk, reconstructed)
					}
				}
			}
		})
	}
}

// Helper function to compare bytes ignoring leading zeros
func bytesEqualIgnoreLeadingZeros(a, b []byte) bool {
	// Trim leading zeros
	for len(a) > 0 && a[0] == 0 {
		a = a[1:]
	}
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestGenerateRandomPolynomial tests polynomial generation
func TestGenerateRandomPolynomial(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name        string
		secret      *big.Int
		threshold   int
		expectError bool
	}{
		{
			name:        "threshold 1",
			secret:      big.NewInt(42),
			threshold:   1,
			expectError: false,
		},
		{
			name:        "threshold 3",
			secret:      big.NewInt(100),
			threshold:   3,
			expectError: false,
		},
		{
			name:        "threshold 0",
			secret:      big.NewInt(50),
			threshold:   0,
			expectError: true,
		},
		{
			name:        "negative threshold",
			secret:      big.NewInt(50),
			threshold:   -1,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coeffs, err := pvss.generateRandomPolynomial(tt.secret, tt.threshold)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(coeffs) != tt.threshold {
				t.Errorf("expected %d coefficients, got %d", tt.threshold, len(coeffs))
			}

			// Verify first coefficient is the secret
			if coeffs[0].Cmp(tt.secret) != 0 {
				t.Error("first coefficient is not the secret")
			}

			// Verify other coefficients are within order
			for i := 1; i < len(coeffs); i++ {
				if coeffs[i].Cmp(pvss.order) >= 0 {
					t.Errorf("coefficient %d exceeds order", i)
				}
			}
		})
	}
}

// TestEvaluatePolynomial tests polynomial evaluation
func TestEvaluatePolynomial(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name         string
		coefficients []*big.Int
		x            int
		expected     *big.Int
	}{
		{
			name:         "empty polynomial",
			coefficients: []*big.Int{},
			x:            1,
			expected:     big.NewInt(0),
		},
		{
			name:         "constant polynomial",
			coefficients: []*big.Int{big.NewInt(5)},
			x:            10,
			expected:     big.NewInt(5),
		},
		{
			name:         "linear polynomial: 3 + 2x at x=1",
			coefficients: []*big.Int{big.NewInt(3), big.NewInt(2)},
			x:            1,
			expected:     big.NewInt(5),
		},
		{
			name:         "linear polynomial: 3 + 2x at x=2",
			coefficients: []*big.Int{big.NewInt(3), big.NewInt(2)},
			x:            2,
			expected:     big.NewInt(7),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pvss.evaluatePolynomial(tt.coefficients, tt.x)

			// Result should be modulo order
			result.Mod(result, pvss.order)
			tt.expected.Mod(tt.expected, pvss.order)

			if result.Cmp(tt.expected) != 0 {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestGenerateCommitments tests commitment generation
func TestGenerateCommitments(t *testing.T) {
	pvss := NewPedersenVSS()

	coeffs := []*big.Int{
		big.NewInt(42),
		big.NewInt(100),
		big.NewInt(200),
	}

	commitments, err := pvss.generateCommitments(coeffs)

	if err != nil {
		t.Fatalf("generateCommitments failed: %v", err)
	}

	if len(commitments) != len(coeffs) {
		t.Errorf("expected %d commitments, got %d", len(coeffs), len(commitments))
	}

	// Verify all commitments are valid points
	for i, commitment := range commitments {
		if commitment.X == nil || commitment.Y == nil {
			t.Errorf("commitment %d has nil coordinates", i)
		}

		// Verify point is on curve
		if !pvss.curve.IsOnCurve(commitment.X, commitment.Y) {
			t.Errorf("commitment %d is not on curve", i)
		}
	}
}

// TestSerializeDeserializeCommitment tests commitment serialization
func TestSerializeDeserializeCommitment(t *testing.T) {
	pvss := NewPedersenVSS()

	// Generate a test point
	scalar := big.NewInt(42)
	x, y := pvss.curve.ScalarBaseMult(scalar.Bytes())
	point := Point{X: x, Y: y}

	// Serialize
	serialized := pvss.serializeCommitment(point)

	if len(serialized) != 33 {
		t.Errorf("expected 33 bytes, got %d", len(serialized))
	}

	// Verify parity byte
	if serialized[0] != 0x02 && serialized[0] != 0x03 {
		t.Errorf("invalid parity byte: %x", serialized[0])
	}

	// Deserialize
	reconstructed, err := pvss.deserializeCommitment(serialized)
	if err != nil {
		t.Fatalf("deserialization failed: %v", err)
	}

	// Verify reconstruction
	if reconstructed.X.Cmp(point.X) != 0 || reconstructed.Y.Cmp(point.Y) != 0 {
		t.Error("deserialized point doesn't match original")
	}
}

// TestSerializeDeserializeCommitment_Invalid tests error handling
func TestSerializeDeserializeCommitment_Invalid(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: make([]byte, 32),
		},
		{
			name: "too long",
			data: make([]byte, 34),
		},
		{
			name: "invalid parity",
			data: append([]byte{0x01}, make([]byte, 32)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pvss.deserializeCommitment(tt.data)
			if err == nil {
				t.Error("expected error but got nil")
			}
		})
	}
}

// TestSerializeDeserializeShareData tests share data serialization
func TestSerializeDeserializeShareData(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name   string
		id     int
		values []*big.Int
	}{
		{
			name:   "single value",
			id:     1,
			values: []*big.Int{big.NewInt(42)},
		},
		{
			name:   "multiple values",
			id:     5,
			values: []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)},
		},
		{
			name:   "empty values",
			id:     3,
			values: []*big.Int{},
		},
		{
			name:   "large values",
			id:     10,
			values: []*big.Int{new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialized := pvss.serializeShareData(tt.id, tt.values)

			id, values, err := pvss.deserializeShareData(serialized)
			if err != nil {
				t.Fatalf("deserialization failed: %v", err)
			}

			if id != tt.id {
				t.Errorf("expected id %d, got %d", tt.id, id)
			}

			if len(values) != len(tt.values) {
				t.Errorf("expected %d values, got %d", len(tt.values), len(values))
			}

			for i := range values {
				if values[i].Cmp(tt.values[i]) != 0 {
					t.Errorf("value %d mismatch: expected %v, got %v", i, tt.values[i], values[i])
				}
			}
		})
	}
}

// TestSplitSecret_BasicCases tests basic secret splitting
func TestSplitSecret_BasicCases(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name      string
		secret    string
		numShares int
		threshold int
	}{
		{
			name:      "simple 3-of-5",
			secret:    "my secret password",
			numShares: 5,
			threshold: 3,
		},
		{
			name:      "2-of-2",
			secret:    "test",
			numShares: 2,
			threshold: 2,
		},
		{
			name:      "1-of-1",
			secret:    "single",
			numShares: 1,
			threshold: 1,
		},
		{
			name:      "5-of-10",
			secret:    "larger scheme",
			numShares: 10,
			threshold: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, err := pvss.SplitSecret(tt.secret, tt.numShares, tt.threshold)

			if err != nil {
				t.Fatalf("SplitSecret failed: %v", err)
			}

			if len(shares) != tt.numShares {
				t.Errorf("expected %d shares, got %d", tt.numShares, len(shares))
			}

			// Verify all shares have non-empty mnemonics
			for i, share := range shares {
				if share.Key == "" {
					t.Errorf("share %d has empty Key", i)
				}
				if share.KeyCheck == "" {
					t.Errorf("share %d has empty KeyCheck", i)
				}
			}

			// Verify all KeyCheck values are identical
			for i := 1; i < len(shares); i++ {
				if shares[i].KeyCheck != shares[0].KeyCheck {
					t.Error("KeyCheck values are not identical across shares")
				}
			}
		})
	}
}

// TestSplitSecret_ValidationErrors tests input validation
func TestSplitSecret_ValidationErrors(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name      string
		secret    string
		numShares int
		threshold int
	}{
		{
			name:      "threshold > numShares",
			secret:    "test",
			numShares: 3,
			threshold: 5,
		},
		{
			name:      "threshold < 1",
			secret:    "test",
			numShares: 5,
			threshold: 0,
		},
		{
			name:      "numShares < 1",
			secret:    "test",
			numShares: 0,
			threshold: 1,
		},
		{
			name:      "numShares > 255",
			secret:    "test",
			numShares: 256,
			threshold: 128,
		},
		{
			name:      "empty secret",
			secret:    "",
			numShares: 5,
			threshold: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pvss.SplitSecret(tt.secret, tt.numShares, tt.threshold)

			if err == nil {
				t.Error("expected error but got nil")
			}
		})
	}
}

// TestVerifyShare tests share verification
func TestVerifyShare(t *testing.T) {
	pvss := NewPedersenVSS()

	secret := "test secret"
	shares, err := pvss.SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	// Test valid shares
	for i, share := range shares {
		t.Run("valid share "+string(rune(i+'0')), func(t *testing.T) {
			valid, err := pvss.VerifyShare(share)

			if err != nil {
				t.Fatalf("VerifyShare failed: %v", err)
			}

			if !valid {
				t.Error("valid share marked as invalid")
			}
		})
	}

	// Test corrupted share
	t.Run("corrupted share", func(t *testing.T) {
		corrupted := shares[0]
		words := strings.Fields(corrupted.Key)
		if len(words) > 2 {
			words[1] = "invalid"
			corrupted.Key = strings.Join(words, " ")
		}

		_, err := pvss.VerifyShare(corrupted)
		if err == nil {
			t.Error("expected error for corrupted share")
		}
	})
}

// TestReconstructSecret tests secret reconstruction
func TestReconstructSecret(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name      string
		secret    string
		numShares int
		threshold int
		useShares []int // which shares to use for reconstruction
	}{
		{
			name:      "exact threshold (3-of-5)",
			secret:    "my secret",
			numShares: 5,
			threshold: 3,
			useShares: []int{0, 1, 2},
		},
		{
			name:      "more than threshold",
			secret:    "test password",
			numShares: 5,
			threshold: 3,
			useShares: []int{0, 1, 2, 3, 4},
		},
		{
			name:      "different share combination",
			secret:    "another secret",
			numShares: 5,
			threshold: 3,
			useShares: []int{1, 3, 4},
		},
		{
			name:      "2-of-2",
			secret:    "simple",
			numShares: 2,
			threshold: 2,
			useShares: []int{0, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allShares, err := pvss.SplitSecret(tt.secret, tt.numShares, tt.threshold)
			if err != nil {
				t.Fatalf("SplitSecret failed: %v", err)
			}

			// Select shares to use
			sharesToUse := make([]Share, len(tt.useShares))
			for i, idx := range tt.useShares {
				sharesToUse[i] = allShares[idx]
			}

			// Reconstruct
			reconstructed, err := pvss.ReconstructSecret(sharesToUse)
			if err != nil {
				t.Fatalf("ReconstructSecret failed: %v", err)
			}

			if reconstructed != tt.secret {
				t.Errorf("reconstruction failed:\nexpected: %q\ngot: %q", tt.secret, reconstructed)
			}
		})
	}
}

// TestReconstructSecret_InsufficientShares tests error handling
func TestReconstructSecret_InsufficientShares(t *testing.T) {
	pvss := NewPedersenVSS()

	secret := "test secret"
	shares, err := pvss.SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	// Try with fewer shares than threshold
	insufficientShares := shares[:2]

	_, err = pvss.ReconstructSecret(insufficientShares)
	if err == nil {
		t.Error("expected error for insufficient shares")
	}
}

// TestReconstructSecret_EmptyShares tests empty share handling
func TestReconstructSecret_EmptyShares(t *testing.T) {
	pvss := NewPedersenVSS()

	_, err := pvss.ReconstructSecret([]Share{})

	if err == nil {
		t.Error("expected error for empty shares")
	}
}

// TestReconstructSecret_DuplicateShares tests duplicate detection
func TestReconstructSecret_DuplicateShares(t *testing.T) {
	pvss := NewPedersenVSS()

	secret := "test secret"
	shares, err := pvss.SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	// Use duplicate shares
	duplicateShares := []Share{shares[0], shares[1], shares[0]}

	_, err = pvss.ReconstructSecret(duplicateShares)
	if err == nil {
		t.Error("expected error for duplicate shares")
	}
}

// TestLongSecrets tests with various length secrets
func TestLongSecrets(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name   string
		secret string
	}{
		{
			name:   "short secret",
			secret: "abc",
		},
		{
			name:   "31 bytes (1 chunk)",
			secret: strings.Repeat("a", 31),
		},
		{
			name:   "32 bytes (2 chunks)",
			secret: strings.Repeat("b", 32),
		},
		{
			name:   "100 bytes (multiple chunks)",
			secret: strings.Repeat("c", 100),
		},
		{
			name:   "1000 bytes",
			secret: strings.Repeat("large secret data ", 50),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, err := pvss.SplitSecret(tt.secret, 5, 3)
			if err != nil {
				t.Fatalf("SplitSecret failed: %v", err)
			}

			reconstructed, err := pvss.ReconstructSecret(shares[:3])
			if err != nil {
				t.Fatalf("ReconstructSecret failed: %v", err)
			}

			if reconstructed != tt.secret {
				t.Errorf("reconstruction failed for %d byte secret", len(tt.secret))
			}
		})
	}
}

// TestSpecialCharacters tests with special characters
func TestSpecialCharacters(t *testing.T) {
	pvss := NewPedersenVSS()

	secrets := []string{
		"Hello\nWorld",
		"Tab\tSeparated",
		"Unicode: 你好世界",
		"Emoji: 🔐🔑",
		"Special: !@#$%^&*()",
		"Mixed\n\t特殊🌍chars",
	}

	for _, secret := range secrets {
		t.Run(secret, func(t *testing.T) {
			shares, err := pvss.SplitSecret(secret, 5, 3)
			if err != nil {
				t.Fatalf("SplitSecret failed: %v", err)
			}

			reconstructed, err := pvss.ReconstructSecret(shares[:3])
			if err != nil {
				t.Fatalf("ReconstructSecret failed: %v", err)
			}

			if reconstructed != secret {
				t.Errorf("special characters not preserved:\nexpected: %q\ngot: %q", secret, reconstructed)
			}
		})
	}
}

// TestLagrangeInterpolation tests Lagrange interpolation
func TestLagrangeInterpolation(t *testing.T) {
	pvss := NewPedersenVSS()

	// Simple test: secret = 42, threshold = 2 (linear)
	secret := big.NewInt(42)
	coeffs, _ := pvss.generateRandomPolynomial(secret, 2)

	// Evaluate at x=1, x=2, x=3
	y1 := pvss.evaluatePolynomial(coeffs, 1)
	y2 := pvss.evaluatePolynomial(coeffs, 2)
	y3 := pvss.evaluatePolynomial(coeffs, 3)

	// Reconstruct using first two points
	shareValues := []*big.Int{y1, y2}
	shareIDs := []int{1, 2}

	reconstructed, err := pvss.lagrangeInterpolation(shareValues, shareIDs)
	if err != nil {
		t.Fatalf("lagrangeInterpolation failed: %v", err)
	}

	if reconstructed.Cmp(secret) != 0 {
		t.Errorf("expected %v, got %v", secret, reconstructed)
	}

	// Try with different points
	shareValues = []*big.Int{y1, y3}
	shareIDs = []int{1, 3}

	reconstructed, err = pvss.lagrangeInterpolation(shareValues, shareIDs)
	if err != nil {
		t.Fatalf("lagrangeInterpolation failed: %v", err)
	}

	if reconstructed.Cmp(secret) != 0 {
		t.Errorf("expected %v, got %v", secret, reconstructed)
	}
}

// BenchmarkSplitSecret benchmarks secret splitting
func BenchmarkSplitSecret(b *testing.B) {
	pvss := NewPedersenVSS()
	secret := "benchmark secret data"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pvss.SplitSecret(secret, 5, 3)
	}
}

// BenchmarkReconstructSecret benchmarks secret reconstruction
func BenchmarkReconstructSecret(b *testing.B) {
	pvss := NewPedersenVSS()
	secret := "benchmark secret data"
	shares, _ := pvss.SplitSecret(secret, 5, 3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pvss.ReconstructSecret(shares[:3])
	}
}

// BenchmarkVerifyShare benchmarks share verification
func BenchmarkVerifyShare(b *testing.B) {
	pvss := NewPedersenVSS()
	secret := "benchmark secret"
	shares, _ := pvss.SplitSecret(secret, 5, 3)
	share := shares[0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pvss.VerifyShare(share)
	}
}

// TestEndToEndWorkflow tests complete workflow
func TestEndToEndWorkflow(t *testing.T) {
	pvss := NewPedersenVSS()

	secret := "My very important secret password 123!"

	// Step 1: Split
	shares, err := pvss.SplitSecret(secret, 7, 4)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Step 2: Verify all shares
	for i, share := range shares {
		valid, err := pvss.VerifyShare(share)
		if err != nil {
			t.Fatalf("Verification failed for share %d: %v", i, err)
		}
		if !valid {
			t.Errorf("Share %d is invalid", i)
		}
	}

	// Step 3: Reconstruct with minimum threshold
	reconstructed, err := pvss.ReconstructSecret(shares[:4])
	if err != nil {
		t.Fatalf("Reconstruction failed: %v", err)
	}

	if reconstructed != secret {
		t.Errorf("Reconstruction mismatch:\nexpected: %q\ngot: %q", secret, reconstructed)
	}

	// Step 4: Verify different combination works
	reconstructed2, err := pvss.ReconstructSecret(shares[2:6])
	if err != nil {
		t.Fatalf("Second reconstruction failed: %v", err)
	}

	if reconstructed2 != secret {
		t.Errorf("Second reconstruction mismatch")
	}
}

// TestConcurrentOperations tests thread safety
func TestConcurrentOperations(t *testing.T) {
	pvss := NewPedersenVSS()
	secret := "concurrent test secret"

	const numGoroutines = 10
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			shares, err := pvss.SplitSecret(secret, 5, 3)
			if err != nil {
				errors <- err
				return
			}

			reconstructed, err := pvss.ReconstructSecret(shares[:3])
			if err != nil {
				errors <- err
				return
			}

			if reconstructed != secret {
				errors <- err
				return
			}

			errors <- nil
		}(i)
	}

	// Check all goroutines succeeded
	for i := 0; i < numGoroutines; i++ {
		if err := <-errors; err != nil {
			t.Errorf("goroutine error: %v", err)
		}
	}
}

// TestShareIndependence tests that shares are independent
func TestShareIndependence(t *testing.T) {
	pvss := NewPedersenVSS()

	secret := "test secret"
	shares1, _ := pvss.SplitSecret(secret, 5, 3)
	shares2, _ := pvss.SplitSecret(secret, 5, 3)

	// Shares should be different due to random polynomial coefficients
	allDifferent := true
	for i := range shares1 {
		if shares1[i].Key == shares2[i].Key {
			allDifferent = false
			break
		}
	}

	if !allDifferent {
		t.Error("shares from different splits should be different (randomized)")
	}

	// But both should reconstruct to same secret
	reconstructed1, _ := pvss.ReconstructSecret(shares1[:3])
	reconstructed2, _ := pvss.ReconstructSecret(shares2[:3])

	if reconstructed1 != secret || reconstructed2 != secret {
		t.Error("both share sets should reconstruct the same secret")
	}
}

// TestMetadataConsistency tests that metadata is consistent across shares
func TestMetadataConsistency(t *testing.T) {
	pvss := NewPedersenVSS()

	secret := "test"
	shares, err := pvss.SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	// All shares should have identical KeyCheck
	reference := shares[0].KeyCheck
	for i := 1; i < len(shares); i++ {
		if shares[i].KeyCheck != reference {
			t.Errorf("share %d has different KeyCheck", i)
		}
	}
}

// TestDifferentThresholds tests various threshold configurations
func TestDifferentThresholds(t *testing.T) {
	pvss := NewPedersenVSS()
	secret := "threshold test"

	configs := []struct {
		numShares int
		threshold int
	}{
		{2, 1},   // 1-of-2
		{3, 2},   // 2-of-3
		{5, 3},   // 3-of-5
		{7, 4},   // 4-of-7
		{10, 6},  // 6-of-10
		{10, 10}, // 10-of-10 (all required)
	}

	for _, cfg := range configs {
		t.Run("", func(t *testing.T) {
			shares, err := pvss.SplitSecret(secret, cfg.numShares, cfg.threshold)
			if err != nil {
				t.Fatalf("SplitSecret(%d, %d) failed: %v", cfg.numShares, cfg.threshold, err)
			}

			reconstructed, err := pvss.ReconstructSecret(shares[:cfg.threshold])
			if err != nil {
				t.Fatalf("ReconstructSecret failed: %v", err)
			}

			if reconstructed != secret {
				t.Errorf("reconstruction failed for %d-of-%d", cfg.threshold, cfg.numShares)
			}
		})
	}
}

// TestMnemonicFormat tests that mnemonics are valid
func TestMnemonicFormat(t *testing.T) {
	pvss := NewPedersenVSS()

	secret := "test secret"
	shares, err := pvss.SplitSecret(secret, 3, 2)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	wordList := BIP39EnglishWords()
	wordMap := make(map[string]bool)
	for _, word := range wordList {
		wordMap[word] = true
	}

	for i, share := range shares {
		// Check Key
		keyWords := strings.Fields(share.Key)
		for _, word := range keyWords {
			if !wordMap[word] {
				t.Errorf("share %d Key contains invalid word: %s", i, word)
			}
		}

		// Check KeyCheck
		keyCheckWords := strings.Fields(share.KeyCheck)
		for _, word := range keyCheckWords {
			if !wordMap[word] {
				t.Errorf("share %d KeyCheck contains invalid word: %s", i, word)
			}
		}
	}
}

// TestReconstructWithWrongMetadata tests error when metadata doesn't match
func TestReconstructWithWrongMetadata(t *testing.T) {
	pvss := NewPedersenVSS()

	// Create two different secret sharings
	shares1, _ := pvss.SplitSecret("secret1", 5, 3)
	shares2, _ := pvss.SplitSecret("secret2", 5, 3)

	// Mix shares from different sharings
	mixedShares := []Share{
		shares1[0],
		shares1[1],
		shares2[2], // Different KeyCheck
	}

	// This should either fail or produce wrong result
	reconstructed, err := pvss.ReconstructSecret(mixedShares)

	// Either error or wrong reconstruction is acceptable
	if err == nil && reconstructed == "secret1" {
		t.Error("should not successfully reconstruct with mixed shares")
	}
}

// TestSerializeMetadata tests metadata serialization
func TestSerializeMetadata(t *testing.T) {
	pvss := NewPedersenVSS()

	// Create sample commitments
	threshold := 3
	chunkCount := 2
	allCommitments := make([][]Point, chunkCount)

	for i := 0; i < chunkCount; i++ {
		commitments := make([]Point, threshold)
		for j := 0; j < threshold; j++ {
			scalar := big.NewInt(int64(i*10 + j))
			x, y := pvss.curve.ScalarBaseMult(scalar.Bytes())
			commitments[j] = Point{X: x, Y: y}
		}
		allCommitments[i] = commitments
	}

	// Serialize
	serialized := pvss.serializeMetadata(threshold, chunkCount, allCommitments)

	// Deserialize
	recThreshold, recChunkCount, recCommitments, err := pvss.deserializeMetadata(serialized)
	if err != nil {
		t.Fatalf("deserializeMetadata failed: %v", err)
	}

	// Verify
	if recThreshold != threshold {
		t.Errorf("threshold mismatch: expected %d, got %d", threshold, recThreshold)
	}

	if recChunkCount != chunkCount {
		t.Errorf("chunkCount mismatch: expected %d, got %d", chunkCount, recChunkCount)
	}

	if len(recCommitments) != chunkCount {
		t.Errorf("commitments count mismatch")
	}
}

// TestDeserializeMetadata_Invalid tests invalid metadata handling
func TestDeserializeMetadata_Invalid(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: []byte{1},
		},
		{
			name: "invalid threshold",
			data: []byte{0, 1},
		},
		{
			name: "invalid chunk count",
			data: []byte{1, 0},
		},
		{
			name: "size mismatch",
			data: []byte{2, 1, 0, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := pvss.deserializeMetadata(tt.data)
			if err == nil {
				t.Error("expected error for invalid metadata")
			}
		})
	}
}

// TestDeserializeShareData_Invalid tests invalid share data handling
func TestDeserializeShareData_Invalid(t *testing.T) {
	pvss := NewPedersenVSS()

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "too short",
			data: []byte{1},
		},
		{
			name: "insufficient value length data",
			data: []byte{1, 2, 5}, // says 2 chunks, but only provides 1 length byte
		},
		{
			name: "insufficient value data",
			data: []byte{1, 1, 10}, // says value is 10 bytes but no data follows
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := pvss.deserializeShareData(tt.data)
			if err == nil {
				t.Error("expected error for invalid share data")
			}
		})
	}
}

// TestMaximumShares tests with maximum allowed shares
func TestMaximumShares(t *testing.T) {
	pvss := NewPedersenVSS()

	secret := "max shares test"
	shares, err := pvss.SplitSecret(secret, 255, 128)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	if len(shares) != 255 {
		t.Errorf("expected 255 shares, got %d", len(shares))
	}

	// Reconstruct with threshold
	reconstructed, err := pvss.ReconstructSecret(shares[:128])
	if err != nil {
		t.Fatalf("ReconstructSecret failed: %v", err)
	}

	if reconstructed != secret {
		t.Error("reconstruction failed with maximum shares")
	}
}

// TestChunking_EdgeCases tests edge cases in chunking
func TestChunking_EdgeCases(t *testing.T) {
	pvss := NewPedersenVSS()

	// Test secrets at chunk boundaries
	tests := []struct {
		length int
	}{
		{30}, // Just under boundary
		{31}, // Exactly at boundary
		{32}, // Just over boundary
		{61}, // Just under 2 chunks
		{62}, // Exactly 2 chunks
		{63}, // Just over 2 chunks
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			secret := strings.Repeat("x", tt.length)
			shares, err := pvss.SplitSecret(secret, 3, 2)
			if err != nil {
				t.Fatalf("SplitSecret failed for length %d: %v", tt.length, err)
			}

			reconstructed, err := pvss.ReconstructSecret(shares[:2])
			if err != nil {
				t.Fatalf("ReconstructSecret failed: %v", err)
			}

			if reconstructed != secret {
				t.Errorf("reconstruction failed for %d byte secret", tt.length)
			}
		})
	}
}

// TestPointSerialization_AllCurvePoints tests various curve points
func TestPointSerialization_AllCurvePoints(t *testing.T) {
	pvss := NewPedersenVSS()

	// Test several different scalars
	scalars := []*big.Int{
		big.NewInt(1),
		big.NewInt(42),
		big.NewInt(12345),
		new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil),
	}

	for i, scalar := range scalars {
		t.Run("", func(t *testing.T) {
			x, y := pvss.curve.ScalarBaseMult(scalar.Bytes())
			point := Point{X: x, Y: y}

			serialized := pvss.serializeCommitment(point)
			deserialized, err := pvss.deserializeCommitment(serialized)

			if err != nil {
				t.Fatalf("scalar %d: deserialization failed: %v", i, err)
			}

			if deserialized.X.Cmp(point.X) != 0 || deserialized.Y.Cmp(point.Y) != 0 {
				t.Errorf("scalar %d: point mismatch", i)
			}

			// Verify point is on curve
			if !pvss.curve.IsOnCurve(deserialized.X, deserialized.Y) {
				t.Errorf("scalar %d: deserialized point not on curve", i)
			}
		})
	}
}
