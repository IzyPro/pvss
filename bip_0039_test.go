package pvss

import (
	"sort"
	"strings"
	"testing"
	"unicode"
)

// TestBIP39EnglishWordsCount tests that the word list has exactly 2048 words
func TestBIP39EnglishWordsCount(t *testing.T) {
	words := BIP39EnglishWords()

	expectedCount := 2048
	actualCount := len(words)

	if actualCount != expectedCount {
		t.Errorf("expected %d words, got %d", expectedCount, actualCount)
	}
}

// TestBIP39EnglishWordsNotEmpty tests that no words are empty strings
func TestBIP39EnglishWordsNotEmpty(t *testing.T) {
	words := BIP39EnglishWords()

	for i, word := range words {
		if word == "" {
			t.Errorf("word at index %d is empty", i)
		}
	}
}

// TestBIP39EnglishWordsUnique tests that all words are unique
func TestBIP39EnglishWordsUnique(t *testing.T) {
	words := BIP39EnglishWords()

	seen := make(map[string]int)
	duplicates := []string{}

	for i, word := range words {
		if prevIndex, exists := seen[word]; exists {
			duplicates = append(duplicates, word)
			t.Errorf("duplicate word '%s' found at indices %d and %d", word, prevIndex, i)
		}
		seen[word] = i
	}

	if len(duplicates) > 0 {
		t.Errorf("found %d duplicate words: %v", len(duplicates), duplicates)
	}
}

// TestBIP39EnglishWordsLowercase tests that all words are lowercase
func TestBIP39EnglishWordsLowercase(t *testing.T) {
	words := BIP39EnglishWords()

	for i, word := range words {
		if word != strings.ToLower(word) {
			t.Errorf("word at index %d ('%s') is not lowercase", i, word)
		}
	}
}

// TestBIP39EnglishWordsNoSpaces tests that words contain no spaces
func TestBIP39EnglishWordsNoSpaces(t *testing.T) {
	words := BIP39EnglishWords()

	for i, word := range words {
		if strings.Contains(word, " ") {
			t.Errorf("word at index %d ('%s') contains spaces", i, word)
		}
	}
}

// TestBIP39EnglishWordsAlphabetic tests that words contain only alphabetic characters
func TestBIP39EnglishWordsAlphabetic(t *testing.T) {
	words := BIP39EnglishWords()

	for i, word := range words {
		for _, char := range word {
			if !unicode.IsLetter(char) {
				t.Errorf("word at index %d ('%s') contains non-alphabetic character '%c'", i, word, char)
				break
			}
		}
	}
}

// TestBIP39EnglishWordsLength tests that words are between 3 and 8 characters
func TestBIP39EnglishWordsLength(t *testing.T) {
	words := BIP39EnglishWords()

	minLength := 3
	maxLength := 8

	for i, word := range words {
		length := len(word)
		if length < minLength || length > maxLength {
			t.Errorf("word at index %d ('%s') has length %d, expected between %d and %d",
				i, word, length, minLength, maxLength)
		}
	}
}

// TestBIP39EnglishWordsAlphabeticalOrder tests that words are in alphabetical order
func TestBIP39EnglishWordsAlphabeticalOrder(t *testing.T) {
	words := BIP39EnglishWords()

	if !sort.StringsAreSorted(words) {
		t.Error("words are not in alphabetical order")

		// Find the first out-of-order word
		for i := 1; i < len(words); i++ {
			if words[i] < words[i-1] {
				t.Errorf("word at index %d ('%s') comes before word at index %d ('%s')",
					i, words[i], i-1, words[i-1])
				break
			}
		}
	}
}

// TestBIP39EnglishWordsSpecificWords tests that specific known BIP39 words exist
func TestBIP39EnglishWordsSpecificWords(t *testing.T) {
	words := BIP39EnglishWords()

	// Create a map for O(1) lookup
	wordMap := make(map[string]bool)
	for _, word := range words {
		wordMap[word] = true
	}

	// Test some known BIP39 words
	knownWords := []string{
		"abandon", // First word
		"zoo",     // Last word
		"satoshi", // Special word in BIP39
		"bitcoin", // Not in BIP39 list
		"crypto",  // Not in BIP39 list
	}

	expectedPresence := []bool{true, true, true, false, false}

	for i, word := range knownWords {
		exists := wordMap[word]
		expected := expectedPresence[i]

		if exists != expected {
			if expected {
				t.Errorf("expected word '%s' to be in the list, but it's not", word)
			} else {
				t.Errorf("expected word '%s' to NOT be in the list, but it is", word)
			}
		}
	}
}

// TestBIP39EnglishWordsFirstAndLast tests the first and last words
func TestBIP39EnglishWordsFirstAndLast(t *testing.T) {
	words := BIP39EnglishWords()

	if len(words) == 0 {
		t.Fatal("word list is empty")
	}

	expectedFirst := "abandon"
	expectedLast := "zoo"

	actualFirst := words[0]
	actualLast := words[len(words)-1]

	if actualFirst != expectedFirst {
		t.Errorf("expected first word to be '%s', got '%s'", expectedFirst, actualFirst)
	}

	if actualLast != expectedLast {
		t.Errorf("expected last word to be '%s', got '%s'", expectedLast, actualLast)
	}
}

// TestBIP39EnglishWordsUniquePrefixes tests that first 4 characters are unique
func TestBIP39EnglishWordsUniquePrefixes(t *testing.T) {
	words := BIP39EnglishWords()

	prefixMap := make(map[string][]string)

	for _, word := range words {
		var prefix string
		if len(word) >= 4 {
			prefix = word[:4]
		} else {
			prefix = word
		}
		prefixMap[prefix] = append(prefixMap[prefix], word)
	}

	// BIP39 specification requires unique 4-character prefixes
	for prefix, wordList := range prefixMap {
		if len(wordList) > 1 {
			t.Errorf("prefix '%s' is not unique, shared by: %v", prefix, wordList)
		}
	}
}

// TestBIP39EnglishWordsNoLeadingTrailingSpaces tests for leading/trailing whitespace
func TestBIP39EnglishWordsNoLeadingTrailingSpaces(t *testing.T) {
	words := BIP39EnglishWords()

	for i, word := range words {
		trimmed := strings.TrimSpace(word)
		if word != trimmed {
			t.Errorf("word at index %d ('%s') has leading or trailing whitespace", i, word)
		}
	}
}

// TestBIP39EnglishWordsImmutability tests that the function returns a new slice each time
func TestBIP39EnglishWordsImmutability(t *testing.T) {
	words1 := BIP39EnglishWords()
	words2 := BIP39EnglishWords()

	// Verify they have the same content
	if len(words1) != len(words2) {
		t.Error("different calls returned different length slices")
	}

	// Modify the first slice
	if len(words1) > 0 {
		originalWord := words1[0]
		words1[0] = "modified"

		// Verify the second slice is unchanged
		if words2[0] != originalWord {
			t.Error("modifying one slice affected another, slices may be sharing underlying array")
		}
	}
}

// TestBIP39EnglishWordsConsistency tests that multiple calls return identical data
func TestBIP39EnglishWordsConsistency(t *testing.T) {
	words1 := BIP39EnglishWords()
	words2 := BIP39EnglishWords()
	words3 := BIP39EnglishWords()

	if len(words1) != len(words2) || len(words2) != len(words3) {
		t.Error("multiple calls returned different lengths")
	}

	for i := 0; i < len(words1); i++ {
		if words1[i] != words2[i] || words2[i] != words3[i] {
			t.Errorf("word mismatch at index %d: '%s' vs '%s' vs '%s'",
				i, words1[i], words2[i], words3[i])
		}
	}
}

// TestBIP39EnglishWordsASCII tests that all characters are ASCII
func TestBIP39EnglishWordsASCII(t *testing.T) {
	words := BIP39EnglishWords()

	for i, word := range words {
		for j, char := range word {
			if char > unicode.MaxASCII {
				t.Errorf("word at index %d ('%s') contains non-ASCII character at position %d: '%c'",
					i, word, j, char)
			}
		}
	}
}

// BenchmarkBIP39EnglishWords benchmarks the function call
func BenchmarkBIP39EnglishWords(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = BIP39EnglishWords()
	}
}

// BenchmarkBIP39EnglishWordsLookup benchmarks word lookup
func BenchmarkBIP39EnglishWordsLookup(b *testing.B) {
	words := BIP39EnglishWords()
	wordMap := make(map[string]int)
	for i, word := range words {
		wordMap[word] = i
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wordMap["abandon"]
	}
}
