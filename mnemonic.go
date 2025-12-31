package pvss

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type MnemonicEncoder struct {
	wordList []string
	wordMap  map[string]int
}

func NewMnemonicEncoder(wordList []string) *MnemonicEncoder {
	wordMap := make(map[string]int)
	for i, word := range wordList {
		wordMap[word] = i
	}

	return &MnemonicEncoder{
		wordList: wordList,
		wordMap:  wordMap,
	}
}

func (me *MnemonicEncoder) EncodeToMnemonic(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("Let’s double-check that input — something seems off.")
	}
	if len(me.wordList) < 1 || len(me.wordMap) < 1 {
		return "", fmt.Errorf("invalid word list or map")
	}

	dataInt := new(big.Int).SetBytes(data)
	base := big.NewInt(int64(len(me.wordList)))

	var words []string
	zero := big.NewInt(0)

	// Convert to base-n representation where n is the number of words
	for dataInt.Cmp(zero) > 0 {
		remainder := new(big.Int)
		dataInt.DivMod(dataInt, base, remainder)
		wordIndex := int(remainder.Int64())
		words = append([]string{me.wordList[wordIndex]}, words...)
	}

	if len(words) == 0 {
		words = []string{me.wordList[0]}
	}

	return strings.Join(words, " "), nil
}

func (me *MnemonicEncoder) DecodeFromMnemonic(mnemonic string) ([]byte, error) {
	if strings.TrimSpace(mnemonic) == "" {
		return nil, fmt.Errorf("empty mnemonic input")
	}

	if len(me.wordList) < 1 || len(me.wordMap) < 1 {
		return nil, fmt.Errorf("invalid list and map")
	}

	words := strings.Fields(mnemonic)
	if len(words) == 0 {
		return nil, errors.New("empty mnemonic")
	}

	dataInt := big.NewInt(0)
	base := big.NewInt(int64(len(me.wordList)))

	for _, word := range words {
		wordIndex, exists := me.wordMap[word]
		if !exists {
			return nil, fmt.Errorf("unknown word: %s", word)
		}

		dataInt.Mul(dataInt, base)
		dataInt.Add(dataInt, big.NewInt(int64(wordIndex)))
	}

	return dataInt.Bytes(), nil
}

func (me *MnemonicEncoder) AddChecksum(mnemonic string) string {
	if mnemonic == "" {
		return ""
	}

	words := strings.Fields(mnemonic)
	checksum := 0

	for _, word := range words {
		if index, exists := me.wordMap[word]; exists {
			checksum += index
		}
	}

	checksumWord := me.wordList[checksum%len(me.wordList)]
	return mnemonic + " " + checksumWord
}

func (me *MnemonicEncoder) VerifyChecksum(mnemonicWithChecksum string) (string, bool) {
	words := strings.Fields(mnemonicWithChecksum)
	if len(words) < 2 {
		return "", false
	}

	mnemonic := strings.Join(words[:len(words)-1], " ")
	checksumWord := words[len(words)-1]

	expectedChecksum := me.AddChecksum(mnemonic)
	expectedWords := strings.Fields(expectedChecksum)
	if len(expectedWords) == 0 {
		return "", false
	}
	expectedChecksumWord := expectedWords[len(expectedWords)-1]

	return mnemonic, checksumWord == expectedChecksumWord
}
