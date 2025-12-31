package pvss

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

type Share struct {
	Key      string // Mnemonic for share data
	KeyCheck string // Mnemonic for verification data only
}

// Point represents a point on an elliptic curve
type Point struct {
	X *big.Int
	Y *big.Int
}

type PedersenVSS struct {
	curve           elliptic.Curve
	order           *big.Int
	mnemonicEncoder *MnemonicEncoder
}

func NewPedersenVSS() *PedersenVSS {
	curve := elliptic.P256()

	return &PedersenVSS{
		curve:           curve,
		order:           curve.Params().N,
		mnemonicEncoder: NewMnemonicEncoder(BIP39EnglishWords()),
	}
}

func (pvss *PedersenVSS) chunkSecret(secret string) [][]byte {
	secretBytes := []byte(secret)
	// Use 31 bytes to ensure we stay well within P-256 field size
	chunkSize := 31

	var chunks [][]byte
	for i := 0; i < len(secretBytes); i += chunkSize {
		end := i + chunkSize
		if end > len(secretBytes) {
			end = len(secretBytes)
		}
		chunk := make([]byte, end-i)
		copy(chunk, secretBytes[i:end])
		chunks = append(chunks, chunk)
	}

	return chunks
}

func (pvss *PedersenVSS) chunkToSecret(chunk []byte) *big.Int {
	if len(chunk) == 0 {
		return big.NewInt(0)
	}

	secretInt := new(big.Int).SetBytes(chunk)

	// Ensure it's within field order (should be safe with 31-byte chunks)
	if secretInt.Cmp(pvss.order) >= 0 {
		secretInt.Mod(secretInt, pvss.order)
	}

	return secretInt
}

func (pvss *PedersenVSS) secretToChunk(secretInt *big.Int) []byte {
	return secretInt.Bytes()
}

func (pvss *PedersenVSS) generateRandomPolynomial(secret *big.Int, threshold int) ([]*big.Int, error) {
	if threshold < 1 {
		return nil, errors.New("threshold must be at least 1")
	}

	coefficients := make([]*big.Int, threshold)
	coefficients[0] = new(big.Int).Set(secret)

	for i := 1; i < threshold; i++ {
		coeff, err := rand.Int(rand.Reader, pvss.order)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random coefficient: %v", err)
		}
		coefficients[i] = coeff
	}

	return coefficients, nil
}

func (pvss *PedersenVSS) evaluatePolynomial(coefficients []*big.Int, x int) *big.Int {
	if len(coefficients) == 0 {
		return big.NewInt(0)
	}

	result := new(big.Int).Set(coefficients[0])
	if len(coefficients) == 1 {
		return result
	}

	xBig := big.NewInt(int64(x))
	xPower := new(big.Int).Set(xBig)

	for i := 1; i < len(coefficients); i++ {
		term := new(big.Int).Mul(coefficients[i], xPower)
		term.Mod(term, pvss.order)

		result.Add(result, term)
		result.Mod(result, pvss.order)

		if i < len(coefficients)-1 {
			xPower.Mul(xPower, xBig)
			xPower.Mod(xPower, pvss.order)
		}
	}

	return result
}

func (pvss *PedersenVSS) generateCommitments(coefficients []*big.Int) ([]Point, error) {
	commitments := make([]Point, len(coefficients))

	for i, coeff := range coefficients {
		x, y := pvss.curve.ScalarBaseMult(coeff.Bytes())
		if x == nil || y == nil {
			return nil, fmt.Errorf("failed to generate commitment %d", i)
		}
		commitments[i] = Point{X: new(big.Int).Set(x), Y: new(big.Int).Set(y)}
	}

	return commitments, nil
}

func (pvss *PedersenVSS) serializeCommitment(point Point) []byte {
	// Use compressed point format: 1 byte for parity + 32 bytes for X coordinate
	result := make([]byte, 33)

	xBytes := point.X.Bytes()
	if len(xBytes) <= 32 {
		copy(result[33-len(xBytes):], xBytes)
	} else {
		copy(result[1:], xBytes[len(xBytes)-32:])
	}

	// Store Y parity in first byte (0x02 for even Y, 0x03 for odd Y)
	if point.Y.Bit(0) == 0 {
		result[0] = 0x02
	} else {
		result[0] = 0x03
	}

	return result
}

func (pvss *PedersenVSS) deserializeCommitment(data []byte) (Point, error) {
	if len(data) != 33 {
		return Point{}, errors.New("invalid commitment data length")
	}

	parity := data[0]
	if parity != 0x02 && parity != 0x03 {
		return Point{}, errors.New("invalid parity byte")
	}

	xBytes := data[1:]
	x := new(big.Int).SetBytes(xBytes)

	// Reconstruct Y coordinate using curve equation: y² = x³ - 3x + b
	params := pvss.curve.Params()

	// Compute x³ - 3x + b
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, params.P)

	threeX := new(big.Int).Mul(big.NewInt(3), x)
	threeX.Mod(threeX, params.P)

	ySquared := new(big.Int).Sub(x3, threeX)
	ySquared.Add(ySquared, params.B)
	ySquared.Mod(ySquared, params.P)

	y := new(big.Int).ModSqrt(ySquared, params.P)
	if y == nil {
		return Point{}, errors.New("point not on curve")
	}

	// Choose correct Y based on parity
	if (y.Bit(0) == 0) != (parity == 0x02) {
		y.Sub(params.P, y)
	}

	return Point{X: x, Y: y}, nil
}

func (pvss *PedersenVSS) serializeShareData(id int, values []*big.Int) []byte {
	if len(values) == 0 {
		return []byte{byte(id), 0}
	}

	// Header: 1 byte for ID, 1 byte for chunk count
	result := []byte{byte(id), byte(len(values))}

	// Serialize each value with its actual length
	for _, value := range values {
		valueBytes := value.Bytes()
		result = append(result, byte(len(valueBytes)))
		result = append(result, valueBytes...)
	}

	return result
}

func (pvss *PedersenVSS) deserializeShareData(data []byte) (int, []*big.Int, error) {
	if len(data) < 2 {
		return 0, nil, errors.New("insufficient share data")
	}

	id := int(data[0])
	chunkCount := int(data[1])

	if chunkCount == 0 {
		return id, nil, nil
	}

	values := make([]*big.Int, chunkCount)
	offset := 2

	for i := 0; i < chunkCount; i++ {
		if offset >= len(data) {
			return 0, nil, errors.New("insufficient value length data")
		}

		valueLen := int(data[offset])
		offset++

		if offset+valueLen > len(data) {
			return 0, nil, errors.New("insufficient value data")
		}

		if valueLen == 0 {
			values[i] = big.NewInt(0)
		} else {
			values[i] = new(big.Int).SetBytes(data[offset : offset+valueLen])
		}
		offset += valueLen
	}

	return id, values, nil
}

func (pvss *PedersenVSS) serializeMetadata(threshold, chunkCount int, allCommitments [][]Point) []byte {
	// Header: 1 byte threshold + 1 byte chunk count
	result := []byte{byte(threshold), byte(chunkCount)}

	for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
		commitments := allCommitments[chunkIdx]
		for _, commitment := range commitments {
			result = append(result, pvss.serializeCommitment(commitment)...)
		}
	}

	return result
}

func (pvss *PedersenVSS) deserializeMetadata(data []byte) (int, int, [][]Point, error) {
	if len(data) < 2 {
		return 0, 0, nil, errors.New("insufficient metadata")
	}

	threshold := int(data[0])
	chunkCount := int(data[1])

	if threshold < 1 || chunkCount < 1 {
		return 0, 0, nil, errors.New("invalid threshold or chunk count")
	}

	expectedCommitments := threshold * chunkCount
	expectedSize := 2 + (expectedCommitments * 33)
	if len(data) != expectedSize {
		return 0, 0, nil, fmt.Errorf("metadata size mismatch: expected %d, got %d", expectedSize, len(data))
	}

	allCommitments := make([][]Point, chunkCount)
	offset := 2

	for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
		commitments := make([]Point, threshold)
		for i := 0; i < threshold; i++ {
			commitment, err := pvss.deserializeCommitment(data[offset : offset+33])
			if err != nil {
				return 0, 0, nil, fmt.Errorf("failed to deserialize commitment: %v", err)
			}
			commitments[i] = commitment
			offset += 33
		}
		allCommitments[chunkIdx] = commitments
	}

	return threshold, chunkCount, allCommitments, nil
}

func (pvss *PedersenVSS) SplitSecret(secret string, numShares, threshold int) ([]Share, error) {
	if threshold > numShares {
		return nil, errors.New("threshold cannot be greater than number of shares")
	}
	if threshold < 1 {
		return nil, errors.New("threshold must be at least 1")
	}
	if numShares < 1 {
		return nil, errors.New("number of shares must be at least 1")
	}
	if numShares > 255 {
		return nil, errors.New("number of shares cannot exceed 255")
	}
	if secret == "" {
		return nil, errors.New("secret cannot be empty")
	}

	chunks := pvss.chunkSecret(secret)
	chunkCount := len(chunks)

	shareValues := make([][]*big.Int, numShares)
	allCommitments := make([][]Point, chunkCount)

	for i := 0; i < numShares; i++ {
		shareValues[i] = make([]*big.Int, chunkCount)
	}

	for chunkIdx, chunk := range chunks {
		secretInt := pvss.chunkToSecret(chunk)

		coefficients, err := pvss.generateRandomPolynomial(secretInt, threshold)
		if err != nil {
			return nil, fmt.Errorf("failed to generate polynomial for chunk %d: %v", chunkIdx, err)
		}

		commitments, err := pvss.generateCommitments(coefficients)
		if err != nil {
			return nil, fmt.Errorf("failed to generate commitments for chunk %d: %v", chunkIdx, err)
		}
		allCommitments[chunkIdx] = commitments

		for i := 0; i < numShares; i++ {
			shareID := i + 1
			shareValue := pvss.evaluatePolynomial(coefficients, shareID)
			shareValues[i][chunkIdx] = shareValue
		}
	}

	shares := make([]Share, numShares)

	metadataBytes := pvss.serializeMetadata(threshold, chunkCount, allCommitments)
	metedataMnemonics, err := pvss.mnemonicEncoder.EncodeToMnemonic(metadataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to perform mnemonic conversion")
	}
	metadataPhrase := pvss.mnemonicEncoder.AddChecksum(metedataMnemonics)

	for i := 0; i < numShares; i++ {
		shareDataBytes := pvss.serializeShareData(i+1, shareValues[i])
		sharedataMnemonics, err := pvss.mnemonicEncoder.EncodeToMnemonic(shareDataBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to perform mnemonic conversion")
		}
		sharePhrase := pvss.mnemonicEncoder.AddChecksum(sharedataMnemonics)

		shares[i] = Share{
			Key:      sharePhrase,
			KeyCheck: metadataPhrase,
		}
	}

	return shares, nil
}

func (pvss *PedersenVSS) VerifyShare(share Share) (bool, error) {
	sharePhrase, shareValid := pvss.mnemonicEncoder.VerifyChecksum(share.Key)
	if !shareValid {
		return false, errors.New("invalid share phrase checksum")
	}

	shareDataBytes, err := pvss.mnemonicEncoder.DecodeFromMnemonic(sharePhrase)
	if err != nil {
		return false, fmt.Errorf("failed to decode share phrase: %v", err)
	}

	shareID, shareValues, err := pvss.deserializeShareData(shareDataBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse share data: %v", err)
	}

	metadataPhrase, metaValid := pvss.mnemonicEncoder.VerifyChecksum(share.KeyCheck)
	if !metaValid {
		return false, errors.New("invalid metadata phrase checksum")
	}

	metadataBytes, err := pvss.mnemonicEncoder.DecodeFromMnemonic(metadataPhrase)
	if err != nil {
		return false, fmt.Errorf("failed to decode metadata phrase: %v", err)
	}

	_, chunkCount, allCommitments, err := pvss.deserializeMetadata(metadataBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse metadata: %v", err)
	}

	// Validate consistency
	if len(shareValues) != chunkCount {
		return false, fmt.Errorf("share has %d chunks, metadata expects %d", len(shareValues), chunkCount)
	}

	// Verify each chunk share using commitments
	for chunkIdx, shareValue := range shareValues {
		commitments := allCommitments[chunkIdx]

		// Compute expected commitment using Horner's method
		expectedX := big.NewInt(0)
		expectedY := big.NewInt(0)
		xBig := big.NewInt(int64(shareID))
		xPower := big.NewInt(1)

		for i, commitment := range commitments {
			// Multiply commitment by x^i
			tempX, tempY := pvss.curve.ScalarMult(commitment.X, commitment.Y, xPower.Bytes())

			// Add to running sum
			expectedX, expectedY = pvss.curve.Add(expectedX, expectedY, tempX, tempY)

			// Update x power for next iteration
			if i < len(commitments)-1 {
				xPower.Mul(xPower, xBig)
				xPower.Mod(xPower, pvss.order)
			}
		}

		// Compute actual commitment g^shareValue
		actualX, actualY := pvss.curve.ScalarBaseMult(shareValue.Bytes())

		// Verify commitments match
		if expectedX.Cmp(actualX) != 0 || expectedY.Cmp(actualY) != 0 {
			return false, nil // Invalid share (not an error, just invalid)
		}
	}

	return true, nil
}

func (pvss *PedersenVSS) lagrangeInterpolation(shareValues []*big.Int, shareIDs []int) (*big.Int, error) {
	if len(shareValues) != len(shareIDs) {
		return nil, errors.New("mismatched share values and IDs")
	}

	if len(shareValues) == 0 {
		return nil, errors.New("no share values provided")
	}

	secret := big.NewInt(0)

	for i, shareValue := range shareValues {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		for j, otherID := range shareIDs {
			if i != j {
				temp := big.NewInt(int64(-otherID))
				temp.Mod(temp, pvss.order)
				numerator.Mul(numerator, temp)
				numerator.Mod(numerator, pvss.order)

				temp = big.NewInt(int64(shareIDs[i] - otherID))
				temp.Mod(temp, pvss.order)
				denominator.Mul(denominator, temp)
				denominator.Mod(denominator, pvss.order)
			}
		}

		denomInverse := new(big.Int).ModInverse(denominator, pvss.order)
		if denomInverse == nil {
			return nil, fmt.Errorf("failed to compute modular inverse for share %d", shareIDs[i])
		}

		lagrangeCoeff := new(big.Int).Mul(numerator, denomInverse)
		lagrangeCoeff.Mod(lagrangeCoeff, pvss.order)

		term := new(big.Int).Mul(shareValue, lagrangeCoeff)
		term.Mod(term, pvss.order)

		secret.Add(secret, term)
		secret.Mod(secret, pvss.order)
	}

	return secret, nil
}

func (pvss *PedersenVSS) ReconstructSecret(shares []Share) (string, error) {
	if len(shares) == 0 {
		return "", errors.New("no shares provided")
	}

	metadataPhrase, metaValid := pvss.mnemonicEncoder.VerifyChecksum(shares[0].KeyCheck)
	if !metaValid {
		return "", errors.New("invalid metadata phrase checksum")
	}

	metadataBytes, err := pvss.mnemonicEncoder.DecodeFromMnemonic(metadataPhrase)
	if err != nil {
		return "", fmt.Errorf("failed to decode metadata phrase: %v", err)
	}

	threshold, chunkCount, _, err := pvss.deserializeMetadata(metadataBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse metadata: %v", err)
	}

	if len(shares) < threshold {
		return "", fmt.Errorf("insufficient shares: need %d, got %d", threshold, len(shares))
	}

	shareDataList := make([]struct {
		id     int
		values []*big.Int
	}, len(shares))

	shareIDs := make([]int, len(shares))

	for i, share := range shares {
		sharePhrase, shareValid := pvss.mnemonicEncoder.VerifyChecksum(share.Key)
		if !shareValid {
			return "", fmt.Errorf("invalid share phrase checksum for share %d", i)
		}

		shareDataBytes, err := pvss.mnemonicEncoder.DecodeFromMnemonic(sharePhrase)
		if err != nil {
			return "", fmt.Errorf("failed to decode share phrase %d: %v", i, err)
		}

		id, values, err := pvss.deserializeShareData(shareDataBytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse share data %d: %v", i, err)
		}

		if len(values) != chunkCount {
			return "", fmt.Errorf("share %d has %d chunks, expected %d", i, len(values), chunkCount)
		}

		shareDataList[i] = struct {
			id     int
			values []*big.Int
		}{id: id, values: values}
		shareIDs[i] = id
	}

	idMap := make(map[int]bool)
	for _, id := range shareIDs {
		if idMap[id] {
			return "", fmt.Errorf("duplicate share ID: %d", id)
		}
		idMap[id] = true
	}

	reconstructedChunks := make([][]byte, chunkCount)

	for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
		chunkShares := make([]*big.Int, len(shares))
		for i, shareData := range shareDataList {
			chunkShares[i] = shareData.values[chunkIdx]
		}

		reconstructedSecret, err := pvss.lagrangeInterpolation(chunkShares, shareIDs)
		if err != nil {
			return "", fmt.Errorf("failed to reconstruct chunk %d: %v", chunkIdx, err)
		}

		chunk := pvss.secretToChunk(reconstructedSecret)
		reconstructedChunks[chunkIdx] = chunk
	}

	result := make([]byte, 0)
	for _, chunk := range reconstructedChunks {
		result = append(result, chunk...)
	}

	return string(result), nil
}
