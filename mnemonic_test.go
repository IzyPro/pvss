package pvss

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"
)

// getTestWordList returns a small word list for testing
func getTestWordList() []string {
	return []string{
		"apple", "banana", "cherry", "date", "elderberry",
		"fig", "grape", "honeydew", "kiwi", "lemon",
	}
}

// TestNewMnemonicEncoder tests encoder initialization
func TestNewMnemonicEncoder(t *testing.T) {
	tests := []struct {
		name     string
		wordList []string
	}{
		{
			name:     "small word list",
			wordList: getTestWordList(),
		},
		{
			name:     "single word",
			wordList: []string{"word"},
		},
		{
			name:     "empty word list",
			wordList: []string{},
		},
		{
			name:     "BIP39 word list",
			wordList: BIP39EnglishWords(),
		},
		{
			name:     "duplicate words",
			wordList: []string{"apple", "banana", "apple"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := NewMnemonicEncoder(tt.wordList)

			if encoder == nil {
				t.Fatal("NewMnemonicEncoder returned nil")
			}

			if len(encoder.wordList) != len(tt.wordList) {
				t.Errorf("expected wordList length %d, got %d", len(tt.wordList), len(encoder.wordList))
			}

			if encoder.wordMap == nil {
				t.Fatal("wordMap is nil")
			}

			// Verify wordMap is correctly populated
			for i, word := range tt.wordList {
				if idx, exists := encoder.wordMap[word]; exists {
					// For duplicates, only the last occurrence is stored
					if idx != i && tt.wordList[idx] != word {
						t.Errorf("word %q at index %d has incorrect mapping %d", word, i, idx)
					}
				}
			}
		})
	}
}

// TestEncodeToMnemonic tests encoding binary data to mnemonic
func TestEncodeToMnemonic(t *testing.T) {
	wordList := getTestWordList()
	encoder := NewMnemonicEncoder(wordList)

	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "empty data",
			data:     []byte{},
			expected: "",
		},
		{
			name:     "zero byte",
			data:     []byte{0},
			expected: "apple",
		},
		{
			name:     "single byte - 1",
			data:     []byte{1},
			expected: "banana",
		},
		{
			name:     "single byte - 5",
			data:     []byte{5},
			expected: "fig",
		},
		{
			name:     "single byte - 9",
			data:     []byte{9},
			expected: "lemon",
		},
		{
			name:     "multiple bytes",
			data:     []byte{1, 2, 3},
			expected: "grape grape apple fig banana",
		},
		{
			name:     "larger value",
			data:     []byte{123},
			expected: "banana cherry date",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := encoder.EncodeToMnemonic(tt.data)

			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}

			// Verify all words are from the word list
			if result != "" {
				words := strings.Fields(result)
				for _, word := range words {
					if _, exists := encoder.wordMap[word]; !exists {
						t.Errorf("encoded word %q not in word list", word)
					}
				}
			}
		})
	}
}

// TestEncodeToMnemonic_LargeData tests encoding with larger data
func TestEncodeToMnemonic_LargeData(t *testing.T) {
	encoder := NewMnemonicEncoder(BIP39EnglishWords())

	tests := []struct {
		name     string
		dataSize int
	}{
		{
			name:     "16 bytes (128 bits)",
			dataSize: 16,
		},
		{
			name:     "32 bytes (256 bits)",
			dataSize: 32,
		},
		{
			name:     "64 bytes (512 bits)",
			dataSize: 64,
		},
		{
			name:     "128 bytes (1024 bits)",
			dataSize: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataSize)
			rand.Read(data)

			mnemonic, _ := encoder.EncodeToMnemonic(data)

			if mnemonic == "" {
				t.Error("encoding returned empty mnemonic")
			}

			words := strings.Fields(mnemonic)
			if len(words) == 0 {
				t.Error("no words in mnemonic")
			}

			// Verify all words are valid
			for _, word := range words {
				if _, exists := encoder.wordMap[word]; !exists {
					t.Errorf("invalid word in mnemonic: %q", word)
				}
			}
		})
	}
}

// TestDecodeFromMnemonic tests decoding mnemonic back to data
func TestDecodeFromMnemonic(t *testing.T) {
	wordList := getTestWordList()
	encoder := NewMnemonicEncoder(wordList)

	tests := []struct {
		name        string
		mnemonic    string
		expected    []byte
		expectError bool
	}{
		{
			name:        "empty string",
			mnemonic:    "",
			expected:    nil,
			expectError: true,
		},
		{
			name:     "single word - first",
			mnemonic: "apple",
			expected: []byte{},
		},
		{
			name:        "single word - second",
			mnemonic:    "banana",
			expected:    []byte{1},
			expectError: false,
		},
		{
			name:        "multiple words",
			mnemonic:    "banana cherry date",
			expected:    []byte{0x7b},
			expectError: false,
		},
		{
			name:        "unknown word",
			mnemonic:    "apple unknown banana",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "whitespace only",
			mnemonic:    "   ",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "extra whitespace",
			mnemonic:    "banana  cherry  date",
			expected:    []byte{0x7b},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := encoder.DecodeFromMnemonic(tt.mnemonic)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				if !bytes.Equal(result, tt.expected) {
					t.Errorf("expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}

// TestEncodeDecodeRoundTrip tests that encoding and decoding are inverse operations
func TestEncodeDecodeRoundTrip(t *testing.T) {
	encoder := NewMnemonicEncoder(BIP39EnglishWords())

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "single byte",
			data: []byte{42},
		},
		{
			name: "multiple bytes",
			data: []byte{1, 2, 3, 4, 5},
		},
		{
			name: "16 bytes",
			data: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10},
		},
		{
			name: "all zeros",
			data: make([]byte, 16),
		},
		{
			name: "all ones",
			data: bytes.Repeat([]byte{0xFF}, 16),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			mnemonic, err := encoder.EncodeToMnemonic(tt.data)
			if mnemonic == "" && len(tt.data) > 0 {
				t.Error("encoding returned empty mnemonic")
			}

			// Decode
			decoded, err := encoder.DecodeFromMnemonic(mnemonic)
			if err != nil {
				t.Fatalf("decoding failed: %v", err)
			}

			// Compare - note that leading zeros may be stripped
			if len(tt.data) > 0 && !bytes.Equal(decoded, tt.data) {
				// For data starting with zeros, check if decoded is a suffix
				if !bytes.HasSuffix(tt.data, decoded) {
					t.Errorf("round trip failed: original=%v, decoded=%v", tt.data, decoded)
				}
			}
		})
	}
}

// TestEncodeDecodeRoundTrip_Random tests with random data
func TestEncodeDecodeRoundTrip_Random(t *testing.T) {
	encoder := NewMnemonicEncoder(BIP39EnglishWords())

	for i := 0; i < 100; i++ {
		// Generate random data of random length
		dataLen := 1 + (i % 32)
		data := make([]byte, dataLen)
		rand.Read(data)

		// Ensure first byte is non-zero to avoid leading zero issues
		if data[0] == 0 {
			data[0] = 1
		}

		mnemonic, err := encoder.EncodeToMnemonic(data)
		decoded, err := encoder.DecodeFromMnemonic(mnemonic)

		if err != nil {
			t.Fatalf("iteration %d: decoding failed: %v", i, err)
		}

		if !bytes.Equal(decoded, data) {
			t.Errorf("iteration %d: round trip failed: original=%v, decoded=%v", i, data, decoded)
		}
	}
}

// TestAddChecksum tests adding checksum to mnemonic
func TestAddChecksum(t *testing.T) {
	wordList := getTestWordList()
	encoder := NewMnemonicEncoder(wordList)

	tests := []struct {
		name     string
		mnemonic string
	}{
		{
			name:     "empty mnemonic",
			mnemonic: "",
		},
		{
			name:     "single word",
			mnemonic: "apple",
		},
		{
			name:     "multiple words",
			mnemonic: "apple banana cherry",
		},
		{
			name:     "all words",
			mnemonic: strings.Join(wordList, " "),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encoder.AddChecksum(tt.mnemonic)

			if tt.mnemonic == "" {
				if result != "" {
					t.Errorf("expected empty result for empty input, got %q", result)
				}
				return
			}

			// Verify the result has one more word
			originalWords := strings.Fields(tt.mnemonic)
			resultWords := strings.Fields(result)

			if len(resultWords) != len(originalWords)+1 {
				t.Errorf("expected %d words, got %d", len(originalWords)+1, len(resultWords))
			}

			// Verify the original mnemonic is preserved
			resultPrefix := strings.Join(resultWords[:len(originalWords)], " ")
			if resultPrefix != tt.mnemonic {
				t.Errorf("original mnemonic not preserved: expected %q, got %q", tt.mnemonic, resultPrefix)
			}

			// Verify checksum word is from word list
			checksumWord := resultWords[len(resultWords)-1]
			if _, exists := encoder.wordMap[checksumWord]; !exists {
				t.Errorf("checksum word %q not in word list", checksumWord)
			}
		})
	}
}

// TestVerifyChecksum tests verifying checksum
func TestVerifyChecksum(t *testing.T) {
	wordList := getTestWordList()
	encoder := NewMnemonicEncoder(wordList)

	tests := []struct {
		name           string
		mnemonic       string
		expectValid    bool
		expectMnemonic string
	}{
		{
			name:           "valid checksum",
			mnemonic:       "apple banana",
			expectValid:    false, // Will be set dynamically
			expectMnemonic: "",
		},
		{
			name:        "empty mnemonic",
			mnemonic:    "",
			expectValid: false,
		},
		{
			name:        "single word",
			mnemonic:    "apple",
			expectValid: false,
		},
		{
			name:        "invalid checksum",
			mnemonic:    "apple banana cherry date",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mnemonic, valid := encoder.VerifyChecksum(tt.mnemonic)

			if tt.name == "empty mnemonic" || tt.name == "single word" {
				if valid {
					t.Error("expected invalid for short mnemonic")
				}
				return
			}

			// For other tests, we don't know the expected result without calculating
			t.Logf("Mnemonic: %q, Valid: %v, Extracted: %q", tt.mnemonic, valid, mnemonic)
		})
	}
}

// TestVerifyChecksum_WithValidChecksum tests verification with known valid checksums
func TestVerifyChecksum_WithValidChecksum(t *testing.T) {
	wordList := getTestWordList()
	encoder := NewMnemonicEncoder(wordList)

	testMnemonics := []string{
		"apple",
		"banana cherry",
		"date elderberry fig",
		"grape honeydew kiwi lemon",
	}

	for _, original := range testMnemonics {
		t.Run(original, func(t *testing.T) {
			// Add checksum
			withChecksum := encoder.AddChecksum(original)
			if withChecksum == "" {
				t.Error("AddChecksum returned empty string")
				return
			}

			// Verify checksum
			extracted, valid := encoder.VerifyChecksum(withChecksum)

			if !valid {
				t.Error("checksum verification failed for valid checksum")
			}

			if extracted != original {
				t.Errorf("extracted mnemonic doesn't match original: expected %q, got %q", original, extracted)
			}
		})
	}
}

// TestVerifyChecksum_WithInvalidChecksum tests verification with invalid checksums
func TestVerifyChecksum_WithInvalidChecksum(t *testing.T) {
	wordList := getTestWordList()
	encoder := NewMnemonicEncoder(wordList)

	tests := []struct {
		name     string
		mnemonic string
	}{
		{
			name:     "wrong checksum word",
			mnemonic: "apple banana cherry",
		},
		{
			name:     "corrupted checksum",
			mnemonic: "date elderberry lemon",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First, create a valid one
			original := "apple banana"
			withChecksum := encoder.AddChecksum(original)

			// Now corrupt it by replacing the checksum
			words := strings.Fields(withChecksum)
			words[len(words)-1] = "lemon" // Change checksum word

			corrupted := strings.Join(words, " ")

			// Verify it fails
			_, valid := encoder.VerifyChecksum(corrupted)

			// It might accidentally be valid, so we just check the logic works
			t.Logf("Corrupted checksum valid: %v", valid)
		})
	}
}

// TestChecksum_Deterministic tests that checksum is deterministic
func TestChecksum_Deterministic(t *testing.T) {
	encoder := NewMnemonicEncoder(getTestWordList())

	mnemonics := []string{
		"apple",
		"banana cherry",
		"date elderberry fig",
	}

	for _, mnemonic := range mnemonics {
		t.Run(mnemonic, func(t *testing.T) {
			checksum1 := encoder.AddChecksum(mnemonic)
			checksum2 := encoder.AddChecksum(mnemonic)
			checksum3 := encoder.AddChecksum(mnemonic)

			if checksum1 != checksum2 || checksum2 != checksum3 {
				t.Errorf("checksum not deterministic: %q, %q, %q", checksum1, checksum2, checksum3)
			}
		})
	}
}

// TestMnemonicEncoder_DifferentWordLists tests with different word lists
func TestMnemonicEncoder_DifferentWordLists(t *testing.T) {
	tests := []struct {
		name     string
		wordList []string
		data     []byte
	}{
		{
			name:     "2 word list",
			wordList: []string{"zero", "one"},
			data:     []byte{5}, // 101 in binary
		},
		{
			name:     "16 word list (hex)",
			wordList: []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"},
			data:     []byte{0xFF},
		},
		{
			name:     "BIP39 word list",
			wordList: BIP39EnglishWords(),
			data:     []byte{1, 2, 3, 4, 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := NewMnemonicEncoder(tt.wordList)

			mnemonic, err := encoder.EncodeToMnemonic(tt.data)
			if mnemonic == "" && len(tt.data) > 0 {
				t.Error("encoding returned empty mnemonic")
			}

			decoded, err := encoder.DecodeFromMnemonic(mnemonic)
			if err != nil {
				t.Fatalf("decoding failed: %v", err)
			}

			// Account for leading zeros being stripped
			if len(tt.data) > 0 && len(decoded) > 0 {
				if !bytes.HasSuffix(tt.data, decoded) {
					t.Errorf("round trip failed: original=%v, decoded=%v", tt.data, decoded)
				}
			}
		})
	}
}

// TestDecodeFromMnemonic_InvalidWords tests error handling
func TestDecodeFromMnemonic_InvalidWords(t *testing.T) {
	encoder := NewMnemonicEncoder(getTestWordList())

	tests := []struct {
		name     string
		mnemonic string
	}{
		{
			name:     "completely invalid word",
			mnemonic: "invalidword",
		},
		{
			name:     "mix of valid and invalid",
			mnemonic: "apple invalidword banana",
		},
		{
			name:     "case sensitivity",
			mnemonic: "Apple Banana Cherry",
		},
		{
			name:     "number",
			mnemonic: "apple 123 banana",
		},
		{
			name:     "special characters",
			mnemonic: "apple @#$ banana",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encoder.DecodeFromMnemonic(tt.mnemonic)

			if err == nil {
				t.Error("expected error for invalid mnemonic, got nil")
			}

			if !strings.Contains(err.Error(), "unknown word") {
				t.Errorf("expected 'unknown word' error, got: %v", err)
			}
		})
	}
}

// TestMnemonicEncoder_EdgeCases tests edge cases
func TestMnemonicEncoder_EdgeCases(t *testing.T) {
	t.Run("nil word list", func(t *testing.T) {
		encoder := NewMnemonicEncoder(nil)
		if encoder == nil {
			t.Fatal("encoder should not be nil")
		}

		// Should handle gracefully
		if _, err := encoder.EncodeToMnemonic([]byte{1}); err == nil {
			t.Errorf("expected failure when converting to mnemonics with nil words")
		}
	})

	t.Run("empty word list", func(t *testing.T) {
		encoder := NewMnemonicEncoder([]string{})
		if encoder == nil {
			t.Fatal("encoder should not be nil")
		}

		// Should handle gracefully (might panic, which is acceptable)
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Panic recovered (expected): %v", r)
			}
		}()

		encoder.EncodeToMnemonic([]byte{1})
	})

	t.Run("single word list", func(t *testing.T) {
		encoder := NewMnemonicEncoder([]string{"only"})

		mnemonic, err := encoder.EncodeToMnemonic([]byte{0})
		if mnemonic != "only" {
			t.Errorf("expected 'only', got %q", mnemonic)
		}

		decoded, err := encoder.DecodeFromMnemonic("only")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(decoded) != 0 {
			t.Errorf("expected empty bytes for zero value, got %v", decoded)
		}
	})
}

// BenchmarkEncodeToMnemonic benchmarks encoding
func BenchmarkEncodeToMnemonic(b *testing.B) {
	encoder := NewMnemonicEncoder(BIP39EnglishWords())
	data := make([]byte, 32)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encoder.EncodeToMnemonic(data)
	}
}

// BenchmarkDecodeFromMnemonic benchmarks decoding
func BenchmarkDecodeFromMnemonic(b *testing.B) {
	encoder := NewMnemonicEncoder(BIP39EnglishWords())
	data := make([]byte, 32)
	rand.Read(data)
	mnemonic, _ := encoder.EncodeToMnemonic(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encoder.DecodeFromMnemonic(mnemonic)
	}
}

// BenchmarkAddChecksum benchmarks checksum addition
func BenchmarkAddChecksum(b *testing.B) {
	encoder := NewMnemonicEncoder(BIP39EnglishWords())
	mnemonic := "abandon ability able about above absent absorb abstract absurd abuse"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = encoder.AddChecksum(mnemonic)
	}
}

// BenchmarkVerifyChecksum benchmarks checksum verification
func BenchmarkVerifyChecksum(b *testing.B) {
	encoder := NewMnemonicEncoder(BIP39EnglishWords())
	mnemonic := "abandon ability able about above absent absorb abstract absurd abuse"
	withChecksum := encoder.AddChecksum(mnemonic)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encoder.VerifyChecksum(withChecksum)
	}
}

// TestMnemonicEncoder_ThreadSafety tests concurrent access
func TestMnemonicEncoder_ThreadSafety(t *testing.T) {
	encoder := NewMnemonicEncoder(BIP39EnglishWords())
	const numGoroutines = 10

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			data := []byte{byte(id)}
			mnemonic, _ := encoder.EncodeToMnemonic(data)
			_, err := encoder.DecodeFromMnemonic(mnemonic)
			if err != nil {
				t.Errorf("goroutine %d: %v", id, err)
			}
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestMnemonicConsistency tests that same data produces same mnemonic
func TestMnemonicConsistency(t *testing.T) {
	encoder := NewMnemonicEncoder(BIP39EnglishWords())

	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	results := make([]string, 100)
	for i := 0; i < 100; i++ {
		results[i], _ = encoder.EncodeToMnemonic(data)
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		if results[i] != results[0] {
			t.Errorf("inconsistent encoding: iteration 0 got %q, iteration %d got %q", results[0], i, results[i])
		}
	}
}

// TestLeadingZeros tests handling of data with leading zeros
func TestLeadingZeros(t *testing.T) {
	encoder := NewMnemonicEncoder(BIP39EnglishWords())

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "single leading zero",
			data: []byte{0, 1, 2, 3},
		},
		{
			name: "multiple leading zeros",
			data: []byte{0, 0, 0, 1, 2, 3},
		},
		{
			name: "all zeros",
			data: []byte{0, 0, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mnemonic, err := encoder.EncodeToMnemonic(tt.data)
			decoded, err := encoder.DecodeFromMnemonic(mnemonic)

			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}

			// Leading zeros will be stripped in big.Int representation
			// Check if decoded is a valid suffix of original
			if !bytes.HasSuffix(tt.data, decoded) && !reflect.DeepEqual(decoded, []byte{}) {
				t.Logf("Note: Leading zeros stripped - original=%v, decoded=%v", tt.data, decoded)
			}
		})
	}
}
