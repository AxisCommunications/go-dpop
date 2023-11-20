package dpop

import (
	"crypto"
	"encoding/hex"
)

// Internal function used to ensure hash is available and set the default
// to SHA256
func ValidateHashFunction(args ...crypto.Hash) (*crypto.Hash, error) {
	var hashFn crypto.Hash
	if len(args) > 1 {
		return nil, ErrTooManyArgs
	} else if len(args) < 1 {
		hashFn = crypto.SHA256
	} else {
		hashFn = args[0]
	}
	if !hashFn.Available() {
		return nil, ErrHashFnNotAvailable
	}
	return &hashFn, nil
}

func HashUtil(inString string, args ...crypto.Hash) (string, error) {
	hashFn, err := ValidateHashFunction(args...)
	if err != nil {
		return "", err
	}
	hashFnInst := hashFn.HashFunc().New()
	// helped me here https://forum.golangbridge.org/t/help-with-sha256-code-solved/8210/4
	firstBytes, err := hex.DecodeString(inString)
	if err != nil {
		return "", ErrInputMalformed
	}
	hashFnInst.Write(firstBytes)

	resultingHash := hashFnInst.Sum(nil)
	return hex.EncodeToString(resultingHash), nil
}

func HashEquals(inString string, encryptedString string, args ...crypto.Hash) (bool, error) {
	hashedInString, err :=  HashUtil(inString, args...)
	if err != nil {
		return false, err
	}
	return (encryptedString == hashedInString), nil
}